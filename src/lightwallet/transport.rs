//! Numeric loopback HTTP/2 gRPC transport for private, tunnelled services.
use super::wire;
use eyre::{ensure, Context, Result};
use prost::{bytes::Buf, Message};
use std::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, TryLockError},
    time::{Duration, Instant},
};
use tonic::{
    client::Grpc,
    codec::{Codec, DecodeBuf, Decoder},
    transport::{Channel, Endpoint},
    Code, Request,
};
use tonic_prost::ProstCodec;

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_STREAM: usize = 8 * 1024 * 1024;
pub const MAX_RANGE: u32 = 64;
const PREFIX: &str = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightwalletError {
    Transport,
    Status(Code),
    Protocol(&'static str),
}
impl fmt::Display for LightwalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport => f.write_str("light-wallet transport unavailable or timed out"),
            Self::Status(Code::Unimplemented) => {
                f.write_str("light-wallet service does not support a required RPC")
            }
            Self::Status(code) => write!(f, "light-wallet RPC returned {code:?}"),
            Self::Protocol(message) => write!(f, "light-wallet protocol error: {message}"),
        }
    }
}
impl std::error::Error for LightwalletError {}
impl From<tonic::Status> for LightwalletError {
    fn from(status: tonic::Status) -> Self {
        Self::Status(status.code())
    }
}

/// Implementations must bound the entire request, including stream completion,
/// by `timeout`. No transaction submission method is exposed.
pub trait LightwalletRpc {
    fn info(&self, timeout: Duration) -> Result<wire::LightdInfo, LightwalletError>;
    fn latest_block(&self, timeout: Duration) -> Result<wire::BlockId, LightwalletError>;
    fn block_range(
        &self,
        start: u32,
        end: u32,
        timeout: Duration,
    ) -> Result<Vec<wire::CompactBlock>, LightwalletError>;
    fn tree_state(
        &self,
        height: u32,
        timeout: Duration,
    ) -> Result<wire::TreeState, LightwalletError>;
}

/// Plaintext is restricted to numeric loopback. SSM supplies the private remote
/// connection. There is no DNS lookup, environment proxy, redirect or TLS bypass.
pub struct GrpcLightwalletRpc {
    endpoint: Endpoint,
    session: Mutex<Option<Session>>,
}
struct Session {
    runtime: tokio::runtime::Runtime,
    channel: Option<Channel>,
}
impl Drop for GrpcLightwalletRpc {
    fn drop(&mut self) {
        if let Some(Session { runtime, channel }) = self
            .session
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            drop(channel);
            // The adapter can be dropped inside another runtime even though its
            // synchronous RPC methods must be called outside one.
            runtime.shutdown_background();
        }
    }
}
impl GrpcLightwalletRpc {
    /// Performs no network access. This synchronous adapter must be called
    /// outside an asynchronous runtime, like the existing node RPC adapter.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.transport.grpc.new")
    )]
    pub fn new(endpoint: &str) -> Result<Self> {
        ensure!(endpoint.len() <= 64, "gRPC endpoint exceeds 64 bytes");
        let mut address: SocketAddr = endpoint
            .parse()
            .context("gRPC endpoint must be a numeric loopback IP and port")?;
        if let SocketAddr::V6(v6) = address {
            ensure!(
                v6.scope_id() == 0 && v6.flowinfo() == 0,
                "gRPC endpoint must not include scope or flow info"
            );
            if let Some(ip) = v6.ip().to_ipv4_mapped() {
                address = SocketAddr::new(IpAddr::V4(ip), address.port());
            }
        }
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "gRPC endpoint must use loopback and a nonzero port"
        );
        Ok(Self {
            endpoint: Endpoint::from_shared(format!("http://{address}"))?,
            session: Mutex::new(None),
        })
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.transport.grpc.run")
    )]
    fn run<T, F, Fut>(&self, timeout: Duration, action: F) -> Result<T, LightwalletError>
    where
        F: FnOnce(Grpc<Channel>) -> Fut,
        Fut: Future<Output = Result<T, LightwalletError>>,
    {
        let start = Instant::now();
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(LightwalletError::Protocol(
                "request timeout must be within 60 seconds",
            ));
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(LightwalletError::Protocol(
                "synchronous transport called inside an async runtime",
            ));
        }
        // One current-thread runtime drives the channel for this adapter's
        // lifetime. Concurrent callers share it, including lock wait in their
        // original whole-request deadline rather than blocking indefinitely.
        let mut session = loop {
            match self.session.try_lock() {
                Ok(session) => break session,
                Err(TryLockError::Poisoned(_)) => return Err(LightwalletError::Transport),
                Err(TryLockError::WouldBlock) => {
                    let remaining = timeout
                        .checked_sub(start.elapsed())
                        .filter(|v| !v.is_zero())
                        .ok_or(LightwalletError::Transport)?;
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        };
        if session.is_none() {
            *session = Some(Session {
                runtime: tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| LightwalletError::Transport)?,
                channel: None,
            });
        }
        let Session { runtime, channel } = session.as_mut().expect("initialized session");
        let remaining = timeout
            .checked_sub(start.elapsed())
            .filter(|v| !v.is_zero())
            .ok_or(LightwalletError::Transport)?;
        let result = runtime.block_on(async {
            tokio::time::timeout(remaining, async {
                if channel.is_none() {
                    *channel = Some(
                        self.endpoint
                            .clone()
                            .connect()
                            .await
                            .map_err(|_| LightwalletError::Transport)?,
                    );
                }
                let client = Grpc::new(channel.as_ref().expect("connected channel").clone())
                    .max_decoding_message_size(MAX_MESSAGE)
                    .max_encoding_message_size(4096);
                action(client).await
            })
            .await
            .map_err(|_| LightwalletError::Transport)?
        });
        // Never replay a failed request. The next caller gets a fresh channel
        // after timeouts, incomplete streams, protocol errors or RPC failures.
        if result.is_err() {
            *channel = None;
        }
        result
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.transport.grpc.unary")
    )]
    fn unary<Req, Resp>(
        &self,
        method: &'static str,
        body: Req,
        timeout: Duration,
    ) -> Result<Resp, LightwalletError>
    where
        Req: Message + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        self.run(timeout, |mut client| async move {
            client
                .ready()
                .await
                .map_err(|_| LightwalletError::Transport)?;
            let mut request = Request::new(body);
            request.set_timeout(timeout);
            let path = format!("{PREFIX}{method}")
                .parse()
                .expect("constant gRPC path");
            let response = client
                .unary(request, path, ProstCodec::<Req, Resp>::default())
                .await?;
            Ok(response.into_inner())
        })
    }
}
impl LightwalletRpc for GrpcLightwalletRpc {
    fn info(&self, timeout: Duration) -> Result<wire::LightdInfo, LightwalletError> {
        self.unary("GetLightdInfo", wire::Empty {}, timeout)
    }
    fn latest_block(&self, timeout: Duration) -> Result<wire::BlockId, LightwalletError> {
        self.unary("GetLatestBlock", wire::ChainSpec {}, timeout)
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.transport.grpc.tree_state")
    )]
    fn tree_state(
        &self,
        height: u32,
        timeout: Duration,
    ) -> Result<wire::TreeState, LightwalletError> {
        if height == 0 {
            return Err(LightwalletError::Protocol(
                "tree-state diagnostic requires a positive height",
            ));
        }
        self.unary(
            "GetTreeState",
            wire::BlockId {
                height: height.into(),
                hash: vec![],
            },
            timeout,
        )
    }
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "lightwallet.transport.grpc.block_range")
    )]
    fn block_range(
        &self,
        start: u32,
        end: u32,
        timeout: Duration,
    ) -> Result<Vec<wire::CompactBlock>, LightwalletError> {
        if end < start || end - start >= MAX_RANGE {
            return Err(LightwalletError::Protocol(
                "block range must contain 1 to 64 ascending heights",
            ));
        }
        self.run(timeout, |mut client| async move {
            client
                .ready()
                .await
                .map_err(|_| LightwalletError::Transport)?;
            let mut request = Request::new(wire::BlockRange {
                start: Some(wire::BlockId {
                    height: start.into(),
                    hash: vec![],
                }),
                end: Some(wire::BlockId {
                    height: end.into(),
                    hash: vec![],
                }),
                pool_types: vec![],
            });
            request.set_timeout(timeout);
            let path = format!("{PREFIX}GetBlockRange")
                .parse()
                .expect("constant gRPC path");
            let mut stream = client
                .server_streaming(request, path, RangeCodec)
                .await?
                .into_inner();
            let mut blocks = Vec::new();
            while let Some(block) = stream.message().await? {
                if blocks.len() >= (end - start + 1) as usize {
                    return Err(LightwalletError::Protocol(
                        "compact stream exceeds requested count or 8 MiB",
                    ));
                }
                blocks.push(block);
            }
            if blocks.len() != (end - start + 1) as usize {
                return Err(LightwalletError::Protocol(
                    "compact stream ended before requested range completed",
                ));
            }
            Ok(blocks)
        })
    }
}

/// Count received protobuf bytes before prost discards unknown fields. Counting
/// the decoded message's re-encoding would let unknown fields bypass the budget.
struct RangeCodec;
type RangeProst = ProstCodec<wire::BlockRange, wire::CompactBlock>;
impl Codec for RangeCodec {
    type Encode = wire::BlockRange;
    type Decode = wire::CompactBlock;
    type Encoder = <RangeProst as Codec>::Encoder;
    type Decoder = RangeDecoder;
    fn encoder(&mut self) -> Self::Encoder {
        RangeProst::default().encoder()
    }
    fn decoder(&mut self) -> Self::Decoder {
        RangeDecoder {
            inner: RangeProst::default().decoder(),
            received: 0,
        }
    }
}
struct RangeDecoder {
    inner: <RangeProst as Codec>::Decoder,
    received: usize,
}
impl Decoder for RangeDecoder {
    type Item = wire::CompactBlock;
    type Error = tonic::Status;
    fn decode(&mut self, buffer: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        let length = buffer.remaining();
        if length > MAX_STREAM.saturating_sub(self.received) {
            return Err(tonic::Status::resource_exhausted(
                "compact stream exceeds 8 MiB",
            ));
        }
        self.received += length;
        self.inner.decode(buffer)
    }
}
