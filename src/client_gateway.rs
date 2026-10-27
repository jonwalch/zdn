//! Private loopback RPC for SSM participants, without exporting node credentials.
//!
//! This gateway is deliberately smaller than the node RPC surface. It permits
//! reviewed queries and transaction submission, never chain control or mining.
//! Rendering is offline; the owned host installer must publish/start the files.

use eyre::{ensure, ContextCompat, Result};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::host::HostInstallSpec;

mod install;
pub mod native;
#[cfg(unix)]
pub mod runtime;
pub use install::{
    ClientGatewayObservation, RenderedClientGatewayInstall, OBSERVATION_API_VERSION,
};

pub const API_VERSION: &str = "zdn-client-rpc/v1alpha1";
/// Submission outcomes are independent of connection cleanup and confirmation.
pub const SUBMISSION_API_VERSION: &str = "zdn-submission/v1alpha1";
pub const ENDPOINT: &str = "127.0.0.1:18234";
pub const UNIT_NAME: &str = "zdn-client-rpc.service";

/// Exact names from the pinned Zakura RPC implementation. Adding any method is
/// an access decision; node discovery and wildcard prefixes are not consulted.
pub const ALLOWED_METHODS: &[&str] = &[
    "getinfo",
    "getdeprecationinfo",
    "getblockchaininfo",
    "getaddressbalance",
    "sendrawtransaction",
    "getblock",
    "getblockheader",
    "getbestblockhash",
    "getbestblockheightandhash",
    "getchaintips",
    "getmempoolinfo",
    "getrawmempool",
    "z_gettreestate",
    "z_getsubtreesbyindex",
    "getrawtransaction",
    "getaddresstxids",
    "getaddressutxos",
    "getblockcount",
    "getblockhash",
    "getnetworkinfo",
    "getpeerinfo",
    "validateaddress",
    "z_validateaddress",
    "getdifficulty",
    "z_listunifiedreceivers",
    "gettxout",
];

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn upstream(host: &HostInstallSpec) -> Result<SocketAddr> {
    host.validate()?;
    let config: toml::Value = toml::from_str(&host.config_toml)?;
    let upstream: SocketAddr = config
        .get("rpc")
        .and_then(|rpc| rpc.get("listen_addr"))
        .and_then(toml::Value::as_str)
        .context("host configuration has no RPC endpoint")?
        .parse()?;
    ensure!(
        upstream.ip().is_loopback() && ![0, 18234, 9067, 9068].contains(&upstream.port()),
        "node RPC must use a distinct loopback port"
    );
    Ok(upstream)
}
