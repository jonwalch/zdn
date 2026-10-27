//! Read-only light-wallet diagnostics and offline service preparation.

use clap::Subcommand;
use eyre::Result;
use std::{path::PathBuf, time::Duration};
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        rpc::{HttpNodeRpc, SystemClock},
    },
    lightwallet::{check_readiness, GrpcLightwalletRpc, ReadinessOptions},
};

#[derive(Subcommand)]
pub enum LightwalletCommand {
    /// Check exact saved OCI bytes and optional Docker metadata. Does not qualify payments.
    VerifyImage {
        /// Saved lightwalletd image provenance record JSON with expected digests.
        #[arg(long)]
        record: PathBuf,
        /// Exact raw OCI lightwalletd image manifest bytes; not a consensus manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Exact raw OCI configuration bytes matching the image manifest.
        #[arg(long)]
        config: PathBuf,
        /// Optional saved trusted host Docker inspection JSON; ZDN does not run Docker.
        #[arg(long)]
        docker_inspect: Option<PathBuf>,
    },
    /// Compare an existing lightwalletd endpoint with authenticated node history and trees.
    /// This read-only observation does not qualify wallets, payments, or a release.
    Readiness {
        /// Reviewed consensus manifest JSON defining expected node and lightwalletd chain identity.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        rpc: crate::NodeRpcArgs,
        /// Numeric loopback IP:port, reached locally or through an existing private tunnel.
        #[arg(long, default_value = "127.0.0.1:9067")]
        grpc_endpoint: String,
        /// Maximum permitted distance behind the observed node tip.
        #[arg(long, default_value_t = 0)]
        max_lag_blocks: u32,
    },
    /// Render the native service recipe; installs and starts nothing.
    RenderService {
        /// Validated saved Zakura host installation specification.
        #[arg(long)]
        host_spec: PathBuf,
        /// Pinned service, dedicated cache volume, and observed host budget.
        #[arg(long)]
        service_spec: PathBuf,
        /// Also save the JSON recipe to a new file; existing files are never replaced.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "lightwallet_cli.run")
)]
pub fn run(command: LightwalletCommand) -> Result<()> {
    match command {
        LightwalletCommand::VerifyImage {
            record,
            manifest,
            config,
            docker_inspect,
        } => {
            use zdn::{devnet::read_bounded, lightwallet_image as image};
            let record = image::ImageRecord::from_json(&read_bounded(
                &record,
                image::MAX_RECORD_BYTES as u64,
            )?)?;
            let manifest = read_bounded(&manifest, image::MAX_MANIFEST_BYTES as u64)?;
            let config = read_bounded(&config, image::MAX_CONFIG_BYTES as u64)?;
            let inspect = docker_inspect
                .as_ref()
                .map(|p| read_bounded(p, image::MAX_INSPECT_BYTES as u64))
                .transpose()?;
            crate::print_json(&image::validate_artifacts(
                &record,
                &manifest,
                &config,
                inspect.as_deref(),
            )?)
        }
        LightwalletCommand::Readiness {
            manifest,
            rpc,
            grpc_endpoint,
            max_lag_blocks,
        } => {
            let wallet = GrpcLightwalletRpc::new(&grpc_endpoint)?;
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let node = HttpNodeRpc::new(&rpc.rpc_endpoint, &rpc.cookie_file)?;
            let report = check_readiness(
                &manifest,
                &node,
                &wallet,
                &SystemClock::default(),
                &ReadinessOptions {
                    request_timeout: Duration::from_secs(rpc.request_timeout_secs),
                    deadline: Duration::from_secs(rpc.deadline_secs),
                    max_lag_blocks,
                    ..Default::default()
                },
            )?;
            crate::print_json(&report)
        }
        LightwalletCommand::RenderService {
            host_spec,
            service_spec,
            output,
        } => {
            let host = zdn::foundation::read_json(&host_spec)?;
            let service = zdn::foundation::read_json(&service_spec)?;
            let rendered = zdn::lightwallet_service::render_service(&host, &service)?;
            if let Some(path) = output {
                crate::write_new_file(&path, &serde_json::to_vec_pretty(&rendered)?)?;
            }
            crate::print_json(&rendered)
        }
    }
}
