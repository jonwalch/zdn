//! Bounded, cookie-authenticated JSON-RPC for local node services or SSM tunnels.
//! Numeric loopback endpoints, no redirects, and no environment proxy prevent
//! a diagnostic or seed submission from forwarding credentials elsewhere.

use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, Context, ContextCompat, Result};
use serde_json::{json, Value};
use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const MAX_BODY: usize = 8 * 1024 * 1024;
const METHODS: &[&str] = &[
    "getchainrules",
    "inspectchainblock",
    "getblockhash",
    "getbestblockheightandhash",
    "getblockchaininfo",
    "getblocktemplate",
    "getblockheader",
    "getblock",
    "z_gettreestate",
    "generate",
    "submitblock",
];

struct RequestBytes(Vec<u8>);

impl Write for RequestBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BODY.saturating_sub(self.0.len()) {
            return Err(io::Error::other("request exceeds 8 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Transport(String),
    Unauthorized,
    Remote { code: i64, message: String },
    Protocol(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => f.write_str("node RPC transport failed"),
            Self::Unauthorized => f.write_str("node RPC authentication failed (HTTP 401)"),
            Self::Remote { code, .. } => write!(f, "node RPC returned error {code}"),
            Self::Protocol(message) => write!(f, "node RPC protocol error: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

pub trait NodeRpc: Send + Sync {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError>;
}

/// Monotonic time boundary shared by orchestration and deterministic tests.
pub trait Clock {
    fn elapsed(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock(Instant);

impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Does not implement Debug: neither the cookie nor its Authorization encoding
/// belongs in logs or saved reports. Construction performs no network request.
pub struct HttpNodeRpc {
    agent: ureq::Agent,
    url: String,
    authorization: String,
    next_id: AtomicU64,
}

impl HttpNodeRpc {
    /// `endpoint` is a numeric loopback IP:port, not a URL. The cookie must be
    /// a private regular file. A node restart requires a new client/cookie read.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.rpc.http.new")
    )]
    pub fn new(endpoint: &str, cookie: &Path) -> Result<Self> {
        ensure!(endpoint.len() <= 64, "RPC endpoint exceeds 64 bytes");
        let endpoint: SocketAddr = endpoint
            .parse()
            .context("RPC endpoint must be a numeric loopback IP and port")?;
        let endpoint = match endpoint {
            SocketAddr::V6(v6) => {
                ensure!(
                    v6.scope_id() == 0 && v6.flowinfo() == 0,
                    "RPC endpoint must not include an IPv6 scope or flow info"
                );
                match v6.ip().to_ipv4_mapped() {
                    Some(ip) => SocketAddr::new(IpAddr::V4(ip), endpoint.port()),
                    None => endpoint,
                }
            }
            endpoint => endpoint,
        };
        ensure!(
            endpoint.ip().is_loopback() && endpoint.port() != 0,
            "RPC endpoint must use loopback and a nonzero port"
        );
        let mut open = OpenOptions::new();
        open.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
        }
        let file = open.open(cookie).context("open private node RPC cookie")?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "RPC cookie must be a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "RPC cookie must not be accessible by group or others"
            );
        }
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024, "RPC cookie exceeds 1024 bytes");
        let text = std::str::from_utf8(&bytes).context("RPC cookie must be ASCII")?;
        let text = text.trim_end_matches(['\r', '\n']);
        let (username, password) = text.split_once(':').context("invalid RPC cookie format")?;
        ensure!(
            !username.is_empty()
                && !password.is_empty()
                && !password.contains(':')
                && text.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid RPC cookie format"
        );
        Ok(Self {
            agent: ureq::AgentBuilder::new()
                .try_proxy_from_env(false)
                .redirects(0)
                .build(),
            url: format!("http://{endpoint}/"),
            authorization: format!("Basic {}", STANDARD.encode(text)),
            next_id: AtomicU64::new(1),
        })
    }
}

impl NodeRpc for HttpNodeRpc {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "chain.rpc.http.call")
    )]
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        if !METHODS.contains(&method)
            || !params.is_array()
            || (method == "generate" && params != json!([1]))
        {
            return Err(RpcError::Protocol(
                "unsupported method or parameters".into(),
            ));
        }
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(RpcError::Protocol(
                "request timeout must be within 60 seconds".into(),
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = RequestBytes(Vec::new());
        serde_json::to_writer(
            &mut request,
            &json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params
            }),
        )
        .map_err(|_| RpcError::Protocol("cannot encode request within 8 MiB".into()))?;
        let response = self
            .agent
            .post(&self.url)
            .timeout(timeout)
            .set("Content-Type", "application/json")
            .set("Authorization", &self.authorization)
            .send_bytes(&request.0);
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(500, response)) => response,
            Err(ureq::Error::Status(401, _)) => return Err(RpcError::Unauthorized),
            Err(ureq::Error::Status(code, _)) => {
                return Err(RpcError::Protocol(format!("HTTP status {code}")));
            }
            Err(ureq::Error::Transport(_)) => {
                return Err(RpcError::Transport("request failed or timed out".into()));
            }
        };
        if response.status() != 200 && response.status() != 500 {
            return Err(RpcError::Protocol("unexpected HTTP status".into()));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RpcError::Transport("response failed or timed out".into()))?;
        if bytes.len() > MAX_BODY {
            return Err(RpcError::Protocol("response exceeds 8 MiB".into()));
        }
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| RpcError::Protocol("invalid JSON response".into()))?;
        if value.get("jsonrpc") != Some(&Value::String("2.0".into()))
            || value.get("id").and_then(Value::as_u64) != Some(id)
        {
            return Err(RpcError::Protocol("response version or ID mismatch".into()));
        }
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            if value.get("result").is_some_and(|result| !result.is_null()) {
                return Err(RpcError::Protocol("ambiguous result and error".into()));
            }
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or_else(|| RpcError::Protocol("invalid error code".into()))?;
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|text| text.len() <= 4096)
                .ok_or_else(|| RpcError::Protocol("invalid error message".into()))?;
            return Err(RpcError::Remote {
                code,
                message: message.into(),
            });
        }
        value
            .as_object_mut()
            .and_then(|object| object.remove("result"))
            .ok_or_else(|| RpcError::Protocol("missing result".into()))
    }
}
