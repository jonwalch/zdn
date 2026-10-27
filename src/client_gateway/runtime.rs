//! Native gateway runtime, adapted from retired `runner.py` lines 19–395.
//! Callers must authenticate configuration, supply a pre-opened trusted directory
//! anchor, trusted owner IDs and expected identity/service digest, and arrange
//! root-only invocation themselves. This module registers no command or signal
//! handler. Paths are relative to the anchor, never interpreted against cwd.
//!
//! Deliberate tightening: strict CRLF HTTP, no folded headers, unambiguous
//! upstream framing (no trailers/interim responses), a 128KiB header budget,
//! and integers outside serde_json's i64/u64 range rejected. Credential checks
//! also cover decoded JSON strings, not only their wire representation.
//! Exchanges retain the Python 10-second upstream / cumulative 15-second client
//! limits. Cancellation is polled during established socket I/O (including
//! response writes), not just accepted reads. As with Python, connection setup
//! may wait for its remaining upstream timeout and trusted local regular-file
//! reads are not preemptible.
//!
//! Source map: private_read/identities mirror Python private_read/verify_identity;
//! Seed/decode mirror no_duplicates/finite_float/bounded_integer/decode_json;
//! Wire/serve replace Gateway's admission, timers and socket cleanup;
//! handle/reply/forward mirror Handler, including health and submission outcomes.

use super::{ALLOWED_METHODS, ENDPOINT, OBSERVATION_API_VERSION, SUBMISSION_API_VERSION};
use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, eyre, Result};
use nix::{
    fcntl::{openat, OFlag},
    sys::stat::Mode,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const MAX: usize = 8 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);

/// All fields are trusted caller inputs, not participant request parameters.
/// The caller opens and authenticates the anchor without following symlinks;
/// the anchor itself is not re-resolved or permission-checked here. Production
/// callers supply `/` as anchor, owner IDs 0/10001, the two installed identity
/// paths and the node's `rpc/.cookie` path, all relative to `/`. Tests can
/// instead supply a private temporary directory and their own owner IDs.
/// `identity` and `service_sha256` must come from the authenticated installation,
/// never from files or observations being checked by this runtime.
#[derive(Debug)]
pub struct Config {
    pub anchor: File,
    pub identity_paths: [PathBuf; 2],
    pub cookie_path: PathBuf,
    pub root_uid: u32,
    pub node_uid: u32,
    pub identity: Value,
    pub service_sha256: String,
    pub upstream: SocketAddr,
}

fn private_read(config: &Config, path: &Path, cookie: bool) -> Result<Vec<u8>> {
    let parts: Vec<_> = path.components().collect();
    ensure!(
        !parts.is_empty() && parts.iter().all(|p| matches!(p, Component::Normal(_))),
        "invalid private path"
    );
    let mut directory = config.anchor.try_clone()?;
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    for (index, part) in parts[..parts.len() - 1].iter().enumerate() {
        directory = File::from(openat(
            &directory,
            Path::new(part.as_os_str()),
            flags | OFlag::O_DIRECTORY,
            Mode::empty(),
        )?);
        let info = directory.metadata()?;
        let rpc = cookie && index == parts.len() - 2;
        ensure!(
            info.uid()
                == if rpc {
                    config.node_uid
                } else {
                    config.root_uid
                }
                && info.mode() & if rpc { 0o077 } else { 0o022 } == 0,
            "untrusted directory"
        );
    }
    let file = File::from(openat(
        &directory,
        Path::new(parts.last().unwrap().as_os_str()),
        flags | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?);
    let info = file.metadata()?;
    let limit = if cookie { 1024 } else { 8192 };
    ensure!(
        info.is_file()
            && info.uid()
                == if cookie {
                    config.node_uid
                } else {
                    config.root_uid
                }
            && info.mode() & 0o077 == 0
            && info.nlink() == 1
            && info.len() <= limit,
        "untrusted file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit as usize, "private file too large");
    Ok(bytes)
}

// A seed shares a global value budget across the entire tree. Keys are not
// values, matching Python; duplicate comparison occurs after escape decoding.
struct Seed<'a>(&'a mut usize);
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        *self.0 += 1;
        if *self.0 > 200_000 {
            return Err(de::Error::custom("value limit"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = a.next_element_seed(Seed(self.0))? {
            values.push(v);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            values.insert(key, a.next_value_seed(Seed(self.0))?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.decode")
)]
fn decode(raw: &[u8]) -> Result<Value> {
    ensure!(raw.len() <= MAX, "JSON size limit");
    let mut normalized = None;
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if quoted {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b'[' || c == b'{' {
            depth += 1;
            ensure!(depth <= 64, "depth limit");
        } else if c == b']' || c == b'}' {
            depth = depth.saturating_sub(1);
        } else if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i + 1 < raw.len()
                && matches!(raw[i + 1], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                i += 1;
            }
            let token = &raw[start..=i];
            if !token.iter().any(|c| matches!(c, b'.' | b'e' | b'E')) {
                ensure!(token.len() <= 21, "integer limit");
                // serde_json otherwise silently coerces overflowing integers to f64.
                let text = std::str::from_utf8(token)?;
                ensure!(
                    text.parse::<i64>().is_ok() || text.parse::<u64>().is_ok(),
                    "integer range"
                );
                // Python treats the integer token -0 as int(0), whereas
                // serde_json otherwise turns it into a floating-point -0.0.
                if token == b"-0" {
                    normalized.get_or_insert_with(|| raw.to_vec())[start] = b' ';
                }
            }
        }
        i += 1;
    }
    let mut d = serde_json::Deserializer::from_slice(normalized.as_deref().unwrap_or(raw));
    let value = Seed(&mut 0).deserialize(&mut d)?;
    d.end()?;
    Ok(value)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.identities")
)]
fn identities(c: &Config) -> Result<()> {
    for path in &c.identity_paths {
        ensure!(
            decode(&private_read(c, path, false)?)? == c.identity,
            "identity mismatch"
        );
    }
    Ok(())
}

struct Wire<'a> {
    socket: TcpStream,
    stop: &'a AtomicBool,
    deadline: Instant,
}
impl Wire<'_> {
    fn check(&self) -> Result<()> {
        ensure!(
            !self.stop.load(Ordering::Acquire) && Instant::now() < self.deadline,
            "exchange stopped"
        );
        Ok(())
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        loop {
            self.check()?;
            match self.socket.read(bytes) {
                Ok(n) => return Ok(n),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(POLL)
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn exact(&mut self, size: usize) -> Result<Vec<u8>> {
        ensure!(size <= MAX, "body limit");
        let mut bytes = vec![0; size];
        let mut pos = 0;
        while pos < size {
            let n = self.read(&mut bytes[pos..])?;
            ensure!(n > 0, "truncated body");
            pos += n;
        }
        Ok(bytes)
    }
    fn line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        loop {
            let byte = self.exact(1)?[0];
            line.push(byte);
            ensure!(line.len() <= 65536, "line limit");
            if byte == b'\n' {
                ensure!(line.ends_with(b"\r\n"), "invalid line");
                line.truncate(line.len() - 2);
                return Ok(String::from_utf8(line)?);
            }
        }
    }
    fn headers(&mut self) -> Result<Vec<(String, String)>> {
        let mut headers = Vec::new();
        let mut size = 0;
        loop {
            let line = self.line()?;
            size += line.len() + 2;
            ensure!(size <= 128 * 1024, "header budget");
            if line.is_empty() {
                return Ok(headers);
            }
            ensure!(headers.len() < 99, "header count");
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| eyre!("invalid header"))?;
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    && value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b)),
                "invalid header"
            );
            headers.push((
                name.to_ascii_lowercase(),
                value.trim_matches([' ', '\t']).into(),
            ));
        }
    }
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check()?;
            match self.socket.write(bytes) {
                Ok(0) => return Err(eyre!("closed socket")),
                Ok(n) => bytes = &bytes[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(POLL)
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
impl Drop for Wire<'_> {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
fn values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}
fn length(text: &str) -> Result<usize> {
    ensure!(
        !text.is_empty() && text.len() <= 8 && text.bytes().all(|b| b.is_ascii_digit()),
        "invalid length"
    );
    Ok(text.parse()?)
}
fn identifier(v: &Value) -> bool {
    v.is_null() || v.as_i64().is_some() || v.as_str().is_some_and(|s| s.chars().count() <= 128)
}
fn same_id(a: &Value, b: &Value) -> bool {
    // Numbers used as IDs must be integer tokens, not numerically equal floats.
    identifier(a) && identifier(b) && a == b
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.forward")
)]
fn forward(c: &Config, client: &Wire<'_>, request: &Value, dispatched: &mut bool) -> Result<Value> {
    client.check()?;
    identities(c)?;
    let raw_cookie = private_read(c, &c.cookie_path, true)?;
    let cookie = raw_cookie
        .strip_suffix(b"\r\n")
        .or_else(|| raw_cookie.strip_suffix(b"\n"))
        .unwrap_or(&raw_cookie);
    ensure!(
        cookie.len() == 55
            && cookie.starts_with(b"__cookie__:")
            && cookie[54] == b'='
            && cookie[11..54]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b)),
        "invalid cookie"
    );
    let authorization = format!("Basic {}", STANDARD.encode(cookie));
    let deadline = client
        .deadline
        .min(Instant::now() + Duration::from_secs(10));
    #[cfg(feature = "profiling")]
    let connect_span = tracing::info_span!("client_gateway.runtime.upstream_connect").entered();
    let socket = TcpStream::connect_timeout(
        &c.upstream,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    #[cfg(feature = "profiling")]
    drop(connect_span);
    socket.set_nonblocking(true)?;
    let mut upstream = Wire {
        socket,
        stop: client.stop,
        deadline,
    };
    let body = serde_json::to_vec(request)?;
    let header = format!("POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAuthorization: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", c.upstream, authorization, body.len());
    #[cfg(feature = "profiling")]
    let write_span = tracing::info_span!("client_gateway.runtime.upstream_write").entered();
    upstream.check()?;
    *dispatched = true;
    upstream.write(header.as_bytes())?;
    upstream.write(&body)?;
    #[cfg(feature = "profiling")]
    drop(write_span);
    #[cfg(feature = "profiling")]
    let headers_span = tracing::info_span!("client_gateway.runtime.upstream_headers").entered();
    let status = upstream.line()?;
    let parts: Vec<_> = status.splitn(3, ' ').collect();
    ensure!(
        parts.len() >= 2 && matches!(parts[0], "HTTP/1.0" | "HTTP/1.1"),
        "upstream status"
    );
    let status: u16 = parts[1].parse()?;
    ensure!([200, 400, 500].contains(&status), "upstream status");
    let headers = upstream.headers()?;
    #[cfg(feature = "profiling")]
    drop(headers_span);
    ensure!(
        values(&headers, "content-encoding").is_empty() && values(&headers, "location").is_empty(),
        "upstream encoding"
    );
    let lengths = values(&headers, "content-length");
    let encodings = values(&headers, "transfer-encoding");
    ensure!(
        lengths.len() <= 1 && encodings.len() <= 1 && (lengths.is_empty() || encodings.is_empty()),
        "ambiguous framing"
    );
    #[cfg(feature = "profiling")]
    let body_span = tracing::info_span!("client_gateway.runtime.upstream_body").entered();
    let mut raw = Vec::new();
    if let Some(encoding) = encodings.first() {
        ensure!(
            encoding.eq_ignore_ascii_case("chunked"),
            "unsupported encoding"
        );
        let mut chunks = 0;
        loop {
            chunks += 1;
            ensure!(chunks <= 200_000, "chunk budget");
            let line = upstream.line()?;
            let size_text = line.split(';').next().unwrap();
            ensure!(
                !size_text.is_empty()
                    && size_text.len() <= 16
                    && size_text.bytes().all(|b| b.is_ascii_hexdigit()),
                "chunk size"
            );
            let size = usize::from_str_radix(size_text, 16)?;
            ensure!(size <= MAX - raw.len(), "response limit");
            if size == 0 {
                ensure!(upstream.headers()?.is_empty(), "unsupported trailers");
                break;
            }
            raw.extend(upstream.exact(size)?);
            ensure!(upstream.exact(2)? == b"\r\n", "chunk delimiter");
        }
    } else if let Some(text) = lengths.first() {
        raw = upstream.exact(length(text)?)?;
    } else {
        let mut buf = [0; 8192];
        loop {
            let n = upstream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ensure!(raw.len() + n <= MAX, "response limit");
            raw.extend_from_slice(&buf[..n]);
        }
    }
    #[cfg(feature = "profiling")]
    drop(body_span);
    ensure!(
        !raw.windows(cookie.len()).any(|w| w == cookie)
            && !raw
                .windows(authorization.len())
                .any(|w| w == authorization.as_bytes()),
        "credential in reply"
    );
    let mut answer = decode(&raw)?;
    // JSON escaping must not turn a rejected wire credential into a successful
    // decoded result. This also checks object keys, not just leaf values.
    let decoded_wire = serde_json::to_vec(&answer)?;
    ensure!(
        !decoded_wire.windows(cookie.len()).any(|w| w == cookie)
            && !decoded_wire
                .windows(authorization.len())
                .any(|w| w == authorization.as_bytes()),
        "credential in decoded reply"
    );
    let object = answer
        .as_object_mut()
        .ok_or_else(|| eyre!("invalid reply"))?;
    ensure!(
        object
            .keys()
            .all(|k| ["jsonrpc", "id", "result", "error"].contains(&k.as_str()))
            && object.get("id").is_some_and(|v| same_id(v, &request["id"]))
            && object.get("jsonrpc").is_none_or(|v| v == "2.0"),
        "invalid reply"
    );
    let submission = request["method"] == "sendrawtransaction";
    if let Some(error) = object.get("error").filter(|v| !v.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .filter(|v| i32::try_from(*v).is_ok());
        ensure!(
            error.is_object() && code.is_some() && object.get("result").is_none_or(Value::is_null),
            "invalid error"
        );
        let mut error = json!({"code":code.unwrap(),"message":"node rejected the request"});
        if submission {
            error["data"] = outcome("node-rejected");
        }
        Ok(json!({"jsonrpc":"2.0","id":request["id"],"error":error}))
    } else {
        ensure!(
            status == 200 && object.contains_key("result"),
            "missing result"
        );
        if submission {
            ensure!(
                object["result"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
                "invalid txid"
            );
        }
        object.remove("error");
        object.insert("jsonrpc".into(), Value::String("2.0".into()));
        Ok(answer)
    }
}
fn outcome(name: &str) -> Value {
    json!({"apiVersion":SUBMISSION_API_VERSION,"outcome":name})
}
fn failure(id: Value, code: i32, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code":code,"message":message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc":"2.0","id":id,"error":error})
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.reply")
)]
fn reply(client: &mut Wire<'_>, status: u16, value: Value) -> Result<()> {
    let body = serde_json::to_vec(&value)?;
    ensure!(body.len() <= MAX, "response limit");
    client.write(format!("HTTP/1.1 {status} RPC\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",body.len()).as_bytes())?;
    client.write(&body)
}
struct RequestHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.request")
)]
fn handle(client: &mut Wire<'_>, c: &Config) -> Result<()> {
    let parsed = (|| -> Result<RequestHead> {
        #[cfg(feature = "profiling")]
        let _span = tracing::info_span!("client_gateway.runtime.request_headers").entered();
        let line = client.line()?;
        let parts: Vec<_> = line.split(' ').collect();
        ensure!(
            parts.len() == 3 && matches!(parts[2], "HTTP/1.0" | "HTTP/1.1"),
            "invalid request line"
        );
        Ok(RequestHead {
            method: parts[0].into(),
            path: parts[1].into(),
            headers: client.headers()?,
        })
    })();
    let RequestHead {
        method,
        path,
        headers,
    } = match parsed {
        Ok(v) => v,
        Err(_) => {
            return reply(
                client,
                400,
                failure(Value::Null, -32600, "invalid RPC transport", None),
            )
        }
    };
    if !values(&headers, "expect").is_empty() {
        return reply(
            client,
            417,
            failure(Value::Null, -32600, "unsupported RPC transport", None),
        );
    }
    if method == "GET" && path == "/health" {
        let answer = forward(
            c,
            client,
            &json!({"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":"zdn-health"}),
            &mut false,
        );
        if answer
            .as_ref()
            .ok()
            .and_then(|v| v["result"]["blocks"].as_u64())
            .is_some()
        {
            return reply(
                client,
                200,
                json!({"apiVersion":OBSERVATION_API_VERSION,"deploymentId":c.identity["deploymentId"],"nodeId":c.identity["nodeId"],"consensusFingerprint":c.identity["consensusFingerprint"],"serviceSha256":c.service_sha256,"endpoint":ENDPOINT,"status":"ready"}),
            );
        }
        return reply(
            client,
            503,
            failure(Value::Null, -32000, "node RPC is unavailable", None),
        );
    }
    if method != "POST" {
        return reply(
            client,
            404,
            failure(Value::Null, -32600, "unsupported RPC path", None),
        );
    }
    let request = (|| -> Result<Value> {
        let lengths = values(&headers, "content-length");
        let hosts = values(&headers, "host");
        let types = values(&headers, "content-type");
        ensure!(
            path == "/"
                && lengths.len() == 1
                && hosts.len() == 1
                && types.len() == 1
                && ["transfer-encoding", "content-encoding", "origin"]
                    .iter()
                    .all(|h| values(&headers, h).is_empty()),
            "invalid transport"
        );
        let (host, port) = hosts[0]
            .split_once(':')
            .map_or((hosts[0], None), |(h, p)| (h, Some(p)));
        ensure!(
            ["localhost", "127.0.0.1"].contains(&host)
                && port.is_none_or(|p| !p.is_empty()
                    && p.len() <= 5
                    && p.bytes().all(|b| b.is_ascii_digit())),
            "invalid host"
        );
        ensure!(
            ["application/json", "application/json; charset=utf-8"]
                .contains(&types[0].to_ascii_lowercase().as_str()),
            "invalid type"
        );
        let size = length(lengths[0])?;
        ensure!(size > 0, "empty body");
        if size > MAX {
            return Err(eyre!("oversized"));
        }
        let mut v = {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("client_gateway.runtime.request_body").entered();
            decode(&client.exact(size)?)?
        };
        let object = v.as_object_mut().ok_or_else(|| eyre!("invalid request"))?;
        ensure!(
            object
                .keys()
                .all(|k| ["jsonrpc", "method", "params", "id"].contains(&k.as_str()))
                && object.get("id").is_some_and(identifier)
                && object
                    .get("jsonrpc")
                    .is_none_or(|v| v == "1.0" || v == "2.0")
                && object.get("method").is_some_and(Value::is_string)
                && object
                    .get("params")
                    .is_none_or(|v| v.is_array() || v.is_object()),
            "invalid request"
        );
        object.insert("jsonrpc".into(), Value::String("2.0".into()));
        object
            .entry("params")
            .or_insert_with(|| Value::Array(Vec::new()));
        Ok(v)
    })();
    let request = match request {
        Ok(v) => v,
        Err(e) => {
            let oversized = e.to_string() == "oversized";
            return reply(
                client,
                if oversized { 413 } else { 400 },
                failure(
                    Value::Null,
                    -32600,
                    if oversized {
                        "RPC request exceeds its size limit"
                    } else {
                        "invalid RPC request"
                    },
                    None,
                ),
            );
        }
    };
    if !ALLOWED_METHODS.contains(&request["method"].as_str().unwrap()) {
        return reply(
            client,
            403,
            failure(
                Value::Null,
                -32601,
                "method is not available to participants",
                None,
            ),
        );
    }
    let mut dispatched = false;
    match forward(c, client, &request, &mut dispatched) {
        Ok(answer) => reply(client, 200, answer),
        Err(_) => reply(
            client,
            502,
            failure(
                request["id"].clone(),
                -32000,
                "node RPC is unavailable",
                (request["method"] == "sendrawtransaction").then(|| {
                    outcome(if dispatched {
                        "outcome-unknown"
                    } else {
                        "not-dispatched"
                    })
                }),
            ),
        ),
    }
}

/// Fetch only this native service's length-framed health response. The same
/// bounded wire/JSON parsers, cancellation and cumulative deadline apply; no
/// proxies, redirects, credentials or automatic retries enter this local gate.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.health")
)]
pub fn health(endpoint: SocketAddr, deadline: Instant, stop: &AtomicBool) -> Result<Value> {
    (|| {
        ensure!(
            endpoint.ip() == std::net::Ipv4Addr::LOCALHOST && endpoint.port() != 0,
            "invalid gateway endpoint"
        );
        let deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        ensure!(
            !stop.load(Ordering::Acquire) && Instant::now() < deadline,
            "health exchange stopped"
        );
        let socket = TcpStream::connect_timeout(
            &endpoint,
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        )?;
        socket.set_nonblocking(true)?;
        let mut wire = Wire {
            socket,
            stop,
            deadline,
        };
        wire.write(
            format!("GET /health HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        let status = wire.line()?;
        let parts: Vec<_> = status.splitn(3, ' ').collect();
        ensure!(
            parts.len() >= 2 && parts[0] == "HTTP/1.1" && parts[1] == "200",
            "gateway health unavailable"
        );
        let headers = wire.headers()?;
        ensure!(
            values(&headers, "transfer-encoding").is_empty()
                && values(&headers, "content-encoding").is_empty()
                && values(&headers, "location").is_empty(),
            "invalid gateway health framing"
        );
        let lengths = values(&headers, "content-length");
        ensure!(lengths.len() == 1, "invalid gateway health length");
        let size = length(lengths[0])?;
        ensure!(size <= 8192, "gateway health exceeds bound");
        let bytes = wire.exact(size)?;
        wire.check()?;
        decode(&bytes)
    })()
    .map_err(|_: eyre::Report| eyre!("native gateway health unavailable"))
}

/// Serve at most four simultaneous clients until cancellation. The listener
/// must be IPv4 127.0.0.1; port zero fixtures are allowed. Startup verifies both
/// identities, and every forward reopens both identities and the rotating cookie.
/// Errors returned here are intentionally generic: never log internal exchanges.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "client_gateway.runtime.serve")
)]
pub fn serve(listener: TcpListener, config: Config, stop: &AtomicBool) -> Result<()> {
    let run = || -> Result<()> {
        ensure!(
            listener.local_addr()?.ip() == std::net::Ipv4Addr::LOCALHOST
                && config.upstream.ip().is_loopback()
                && config.upstream.port() != 0
                && config.upstream != listener.local_addr()?,
            "invalid endpoints"
        );
        ensure!(config.anchor.metadata()?.is_dir(), "invalid anchor");
        identities(&config)?;
        listener.set_nonblocking(true)?;
        thread::scope(|scope| -> Result<()> {
            let mut workers: Vec<thread::ScopedJoinHandle<'_, ()>> = Vec::new();
            while !stop.load(Ordering::Acquire) {
                let mut i = 0;
                while i < workers.len() {
                    if workers[i].is_finished() {
                        let _ = workers.swap_remove(i).join();
                    } else {
                        i += 1;
                    }
                }
                match listener.accept() {
                    Ok((socket, peer)) => {
                        if workers.len() >= 4 || !peer.ip().is_loopback() {
                            let _ = socket.shutdown(Shutdown::Both);
                            continue;
                        }
                        socket.set_nonblocking(true)?;
                        let c = &config;
                        let deadline = Instant::now() + Duration::from_secs(15);
                        #[cfg(feature = "profiling")]
                        let dispatch = tracing::dispatcher::get_default(Clone::clone);
                        #[cfg(feature = "profiling")]
                        let service_span = tracing::Span::current();
                        workers.push(scope.spawn(move || {
                            #[cfg(feature = "profiling")]
                            let _dispatch = tracing::dispatcher::set_default(&dispatch);
                            #[cfg(feature = "profiling")]
                            let _service_span = service_span.enter();
                            let mut client = Wire {
                                socket,
                                stop,
                                deadline,
                            };
                            let _ = handle(&mut client, c);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })
    };
    run().map_err(|_| eyre!("private RPC service failed"))
}
