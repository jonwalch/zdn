//! Read-only startup gate for a node that may still be opening retained state
//! and replacing the previous process's RPC cookie.

use super::{
    manifest::ConsensusManifest,
    readiness::{PreparedRules, RulesEvidence},
    rpc::{Clock, HttpNodeRpc, RpcError},
};
use eyre::{bail, ensure, ContextCompat, Result};
use std::{io, path::Path, time::Duration};

/// Retry only missing cookies, transport failures, and HTTP 401. Every attempt
/// opens the cookie again; unsafe files, malformed responses, remote RPC errors,
/// and mismatched effective rules fail immediately. No mutation RPC is used.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.startup.wait_for_rpc")
)]
pub fn wait_for_rpc(
    manifest: &ConsensusManifest,
    endpoint: &str,
    cookie: &Path,
    clock: &impl Clock,
    request_timeout: Duration,
    deadline: Duration,
) -> Result<RulesEvidence> {
    wait_prepared(
        PreparedRules::new(manifest)?,
        endpoint,
        cookie,
        clock,
        request_timeout,
        deadline,
        crate::rpc_limits::BodyClass::Default,
    )
    .map(|(_, evidence)| evidence)
}

#[cfg(target_os = "linux")]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "chain.startup.wait_external")
)]
pub(crate) fn wait_external(
    compiled: &crate::public_chain_adapter::contract::Compiled,
    endpoint: &str,
    cookie: &Path,
    clock: &impl Clock,
    request_timeout: Duration,
    deadline: Duration,
) -> Result<HttpNodeRpc> {
    wait_prepared(
        PreparedRules::external(compiled),
        endpoint,
        cookie,
        clock,
        request_timeout,
        deadline,
        crate::rpc_limits::BodyClass::LargeHexV1,
    )
    .map(|(client, _)| client)
}

fn wait_prepared(
    rules: PreparedRules,
    endpoint: &str,
    cookie: &Path,
    clock: &impl Clock,
    request_timeout: Duration,
    deadline: Duration,
    body_class: crate::rpc_limits::BodyClass,
) -> Result<(HttpNodeRpc, RulesEvidence)> {
    ensure!(
        !deadline.is_zero() && deadline <= Duration::from_secs(3600),
        "RPC startup deadline must be positive and at most 3600 seconds"
    );
    ensure!(
        !request_timeout.is_zero()
            && request_timeout <= Duration::from_secs(60)
            && request_timeout <= deadline,
        "RPC startup request timeout must be positive, at most 60 seconds, and within the deadline"
    );
    let start = clock.elapsed();
    let remaining = || {
        deadline
            .checked_sub(clock.elapsed().saturating_sub(start))
            .filter(|duration| !duration.is_zero())
            .context("node RPC startup deadline exceeded")
    };
    // The independent attempt bound also limits a stalled or faulty clock.
    for _ in 0..4096 {
        let timeout = || Ok(request_timeout.min(remaining()?));
        match HttpNodeRpc::with_body_class(endpoint, cookie, body_class) {
            Ok(client) => match rules.verify(&client, timeout) {
                Ok(evidence) => {
                    remaining()?;
                    return Ok((client, evidence));
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<RpcError>(),
                        Some(RpcError::Transport(_) | RpcError::Unauthorized)
                    ) => {}
                Err(error) => return Err(error),
            },
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        clock.sleep(Duration::from_secs(1).min(remaining()?));
    }
    bail!("node RPC startup attempt limit reached")
}
