//! Explicit, private timing output; never changes the command's stdout protocol.
use eyre::{Context, Result};
use std::{path::Path, sync::Mutex};
use tracing_subscriber::{filter::filter_fn, fmt::format::FmtSpan, prelude::*};

pub fn init() -> Result<()> {
    let Some(path) = std::env::var_os("ZDN_TRACE_FILE") else {
        return Ok(());
    };
    // Called at the start of main, before spawning any threads or children.
    // Supervisors and credential-process children must not reopen this file.
    std::env::remove_var("ZDN_TRACE_FILE");
    let file = crate::cli_output::create_event_file(Path::new(&path))
        .context("create new private trace file")?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(Mutex::new(file))
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(filter_fn(|metadata| {
                    // Only our argument-free spans, not dependency or event fields.
                    metadata.is_span()
                        && (metadata.target() == "zdn" || metadata.target().starts_with("zdn::"))
                })),
        )
        .try_init()
        .context("install profiling trace subscriber")?;
    Ok(())
}
