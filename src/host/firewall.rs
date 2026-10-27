//! Node-UID IMDS isolation from `runner.py::metadata_firewall` (lines 522–532).
//! Host networking bypasses IMDS hop-limit isolation. Installation may insert
//! missing rules; observations must never repair them. Callers authenticate
//! absolute tool paths and retain the shared action executor/deadline. Native
//! host operations use this API. Partial installation is not rolled
//! back: removing a successfully installed protection would weaken isolation.

use std::{path::Path, sync::atomic::AtomicBool, time::Duration};

use eyre::{ensure, Result};

use super::command::{Executor, HostCommand};

/// Require both protections, optionally inserting and rechecking missing ones.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "host.firewall.ensure_rules")
)]
pub fn ensure_rules(
    iptables: &Path,
    ip6tables: &Path,
    install: bool,
    executor: &mut Executor,
    cancelled: &AtomicBool,
) -> Result<()> {
    ensure!(
        iptables.is_absolute() && ip6tables.is_absolute(),
        "metadata firewall tools must be absolute"
    );
    let uid = crate::image::RUNTIME_UID.to_string();
    for (program, address) in [
        (iptables, "169.254.169.254/32"),
        (ip6tables, "fd00:ec2::254/128"),
    ] {
        #[cfg(feature = "profiling")]
        let _span = if address == "169.254.169.254/32" {
            tracing::info_span!("host.firewall.ipv4")
        } else {
            tracing::info_span!("host.firewall.ipv6")
        }
        .entered();
        let rule = [
            "OUTPUT",
            "-m",
            "owner",
            "--uid-owner",
            &uid,
            "-d",
            address,
            "-j",
            "REJECT",
        ];
        let check: Vec<_> = ["--wait", "5", "--check"]
            .into_iter()
            .chain(rule)
            .map(Into::into)
            .collect();
        let mut command = |args: &[_], allowed: &[i32]| {
            executor.execute(
                HostCommand {
                    program,
                    args,
                    stdin: None,
                    timeout: Duration::from_secs(60),
                    allowed,
                },
                cancelled,
            )
        };
        let missing = {
            #[cfg(feature = "profiling")]
            let _span = tracing::info_span!("host.firewall.check").entered();
            command(&check, &[0, 1])?.exit_code == 1
        };
        if missing {
            ensure!(install, "node metadata firewall rule is missing");
            let insert: Vec<_> = ["--wait", "5", "--insert", "OUTPUT", "1"]
                .into_iter()
                .chain(rule[1..].iter().copied())
                .map(Into::into)
                .collect();
            {
                #[cfg(feature = "profiling")]
                let _span = tracing::info_span!("host.firewall.repair").entered();
                command(&insert, &[0])?;
            }
            {
                #[cfg(feature = "profiling")]
                let _span = tracing::info_span!("host.firewall.recheck").entered();
                command(&check, &[0])?;
            }
        }
    }
    Ok(())
}
