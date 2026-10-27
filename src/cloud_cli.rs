//! Command wiring for AWS foundation setup and the disposable host.

mod discovery;
mod removal;

use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use zdn::{
    access::{self, AccessRequest, DeploymentAccess, RoleManagement},
    access_bootstrap,
    aws::{self, AwsCli, LocalProfile, NetworkReservation, S3Metadata, TeamDefinition},
    foundation::{self, Deployment, DeploymentFile},
    foundation_live::{self, LiveBackend},
    immutable_inputs::{ImmutableInputError, ImmutableInputReport},
    infra::FoundationSpec,
};

pub(super) const UP_HELP: &str = "Fresh launch modes:\n  Source: --manifest CHAIN.json --bundle CHAIN.tar --host-helper LINUX_ZDN --reward-address TESTNET_ADDRESS, plus first-launch --ami-id AMI --availability-zone ZONE. node.source.path/build come from --config. Omit all node image flags: ZDN captures source and submits a billed build.\n  Pinned image: supply the same four chain/helper/reward inputs plus --image-record RECORD --image-manifest OCI_MANIFEST --image-config OCI_CONFIG.\n  Package: use --package PACKAGE --package-sha256 TRUSTED_HASH with a pinned-image config and --reward-address; do not combine with a source build. Package inputs are verified, not trusted merely by hashing.\n  Optional lightwalletd: services.lightwallet must be enabled and all three --lightwallet-image-* inputs supplied (or present in the package). CLI wallet payments do not require lightwalletd.\n\nExecution example (creates billed AWS resources after reviewed setup):\n  zdn devnet up --manifest chain.json --bundle chain.tar --host-helper ./zdn-linux --reward-address TESTNET_ADDRESS --ami-id AMI --availability-zone ZONE --yes\n\nRecovery only, using unchanged immutable saved inputs:\n  zdn devnet up --saved NETWORK --yes --reconcile\nSaved mode rejects config/AMI/zone/package/chain/image/helper/reward overrides; --profile is allowed only with --saved (default devnet). Keep the original private state directory and receipts. --reconcile observes uncertain work; it is not permission to duplicate a build/command or bypass a lease. An expired lease needs its exact observed ETag and a quiescent previous controller. Destroyed retained disks are not a resumable deployment. See docs/private-devnet.md and docs/builds.md.";

const DESTROY_HELP: &str = "Examples (destructive; review the exact saved target first):\n  zdn devnet destroy NETWORK --yes\n  zdn devnet destroy NETWORK --delete-data --yes\n\nDefault teardown retains chain/cache disks and deployment artifacts: these still cost money. --delete-data removes the recorded owned disks and every version/delete marker under this deployment's artifact prefix, not shared backend/IAM/registry/reservation/operation history. After an uncertain result inspect status and receipts; retry with --reconcile and the SAME deletion consent. Never delete journals or add lease recovery to bypass a refusal. No rollback or one-command restore is promised. See docs/private-devnet.md#tear-down and docs/removal.md.";

#[derive(Subcommand)]
pub enum SetupCommand {
    /// Review or remove an administrator-owned participant grant, preserving its audit receipts.
    RemoveParticipant(removal::ParticipantRemovalArgs),
    /// Review or remove an originally created team after network/data/grant cleanup.
    RemoveTeam(removal::TeamRemovalArgs),
    /// Grant a separate participant role access to one devnet's private client services.
    Participant(Box<connect_cli::ParticipantArgs>),
    /// Create an organization-owned S3/KMS backend; requires AWS setup permissions.
    Bootstrap {
        #[command(flatten)]
        store: StoreArgs,
        #[command(flatten)]
        scope: ScopeArgs,
        /// Authenticated administrator AWS CLI profile; creates S3/KMS and optional managed IAM resources.
        #[arg(long)]
        aws_profile: String,
        #[command(flatten)]
        access: Box<AccessArgs>,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Local ZDN profile alias to save; not an AWS CLI profile or team ID.
        #[arg(long, default_value = "devnet")]
        profile: String,
        /// New globally unique organization-owned S3 bucket name for shared state/artifacts.
        #[arg(long)]
        bucket: String,
        /// Pulumi state key prefix within the team bucket; keep stable for recovery.
        #[arg(long, default_value = "pulumi/zdn")]
        prefix: String,
        /// Exact ownership-tagged KMS ARN from an interrupted bootstrap.
        #[arg(long)]
        recovered_key: Option<String>,
        /// Export the team definition; an identical existing export is preserved.
        #[arg(long)]
        export: Option<PathBuf>,
        /// Explicit consent to create billed shared backend and optional IAM resources.
        #[arg(long)]
        yes: bool,
    },
    /// Render administrator IAM policies without contacting AWS or changing files.
    RolePlan {
        /// Reviewed team definition JSON exported by setup bootstrap.
        #[arg(long)]
        from: PathBuf,
        /// Administrator source AWS CLI profile used in the proposed role setup.
        #[arg(long)]
        aws_profile: String,
        /// Exact IAM user/role ARN to trust; repeat for multiple reviewed principals.
        #[arg(long = "trust-principal", required = true)]
        trusted_principals: Vec<String>,
    },
    /// Verify an existing team's backend and bind your own AWS profile locally.
    Import {
        #[command(flatten)]
        store: StoreArgs,
        /// Reviewed team definition JSON; importing does not grant deletion ownership.
        #[arg(long)]
        from: PathBuf,
        /// Your authenticated AWS CLI profile; credentials are not imported from the team file.
        #[arg(long)]
        aws_profile: String,
        /// Local ZDN alias to bind to this team; reuse it for deployment and cleanup.
        #[arg(long, default_value = "devnet")]
        profile: String,
    },
}

#[derive(Args)]
pub struct AccessArgs {
    /// Override the deployment-role source profile (defaults to --aws-profile with --trust-principal).
    #[arg(long)]
    developer_aws_profile: Option<String>,
    /// Enable role setup trusting this exact IAM user or role ARN. Repeatable.
    #[arg(long = "trust-principal")]
    trusted_principals: Vec<String>,
    /// Organization-owned role; requires --trust-principal and --runtime-boundary-arn. Policies are not modified.
    #[arg(long, requires_all = ["trusted_principals", "runtime_boundary_arn"])]
    existing_role_arn: Option<String>,
    /// Existing IAM permissions-boundary policy ARN; requires --existing-role-arn.
    #[arg(long, requires = "existing_role_arn")]
    runtime_boundary_arn: Option<String>,
    /// Refresh the administrator stack before retrying an uncertain apply.
    #[arg(long, requires = "trusted_principals")]
    reconcile: bool,
}

impl AccessArgs {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "cloud_cli.access.validate")
    )]
    fn validate(&self, administrator: &aws::AwsSelection) -> Result<()> {
        if let Some(developer) = &self.developer_aws_profile {
            let mut selection = administrator.clone();
            selection.profile = developer.clone();
            selection.validate()?;
            ensure!(
                !self.trusted_principals.is_empty() && self.trusted_principals.len() <= 20,
                "role setup requires 1-20 --trust-principal values"
            );
            let mut seen = std::collections::BTreeSet::new();
            for principal in &self.trusted_principals {
                ensure!(seen.insert(principal), "duplicate trusted principal");
                access::iam_resource(
                    principal,
                    &administrator.account_id,
                    if principal.contains(":user/") {
                        "user"
                    } else {
                        "role"
                    },
                )?;
            }
            if let Some(role) = &self.existing_role_arn {
                access::iam_resource(role, &administrator.account_id, "role")?;
                ensure!(
                    !self.trusted_principals.contains(role),
                    "deployment role cannot trust itself"
                );
                access::iam_resource(
                    self.runtime_boundary_arn
                        .as_deref()
                        .context("existing role requires --runtime-boundary-arn")?,
                    &administrator.account_id,
                    "policy",
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Args, Clone)]
pub struct LaunchArgs {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(flatten)]
    store: StoreArgs,
    /// Pinned Amazon Linux 2023 x86-64 AMI; required for the first render or launch.
    #[arg(long)]
    ami_id: Option<String>,
    /// Availability zone in the selected region; required with --ami-id for a fresh request.
    #[arg(long)]
    availability_zone: Option<String>,
}

#[derive(Args)]
pub struct FoundationLaunchArgs {
    #[command(flatten)]
    launch: LaunchArgs,
    /// Linux helper implementing native readiness; required for a fresh request.
    #[arg(long)]
    host_helper: Option<PathBuf>,
}

#[derive(Args)]
pub struct ExistingArgs {
    /// Full network ID, unique prefix, or unambiguous saved label.
    selector: String,
    #[command(flatten)]
    store: StoreArgs,
    /// Local ZDN profile alias, not an AWS profile; must match the deployment's saved team.
    #[arg(long, default_value = "devnet")]
    profile: String,
}

#[derive(Subcommand)]
pub enum FoundationCommand {
    /// Save a local foundation request and print its YAML. Makes no AWS calls.
    Render(FoundationLaunchArgs),
    /// Create/update one private health-test host. Does not launch Zakura.
    Up {
        #[command(flatten)]
        launch: FoundationLaunchArgs,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Inspect live state before retrying an operation with an uncertain outcome.
        #[arg(long)]
        reconcile: bool,
        /// Recover only the expired lease with this exact ETag, shown by status.
        #[arg(long, requires = "reconcile")]
        recover_lease_etag: Option<String>,
        /// Explicit consent to provision billed AWS foundation resources; this does not deploy a node.
        #[arg(long)]
        yes: bool,
    },
    /// Read AWS inventory and the current lease without changing resources.
    Status(ExistingArgs),
    /// Remove the host and network. Keep the chain disk unless --delete-data is set.
    Destroy {
        #[command(flatten)]
        existing: ExistingArgs,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Irreversibly remove owned retained chain data; omission retains billed disks. Shared team backend is preserved.
        #[arg(long)]
        delete_data: bool,
        /// Reobserve interrupted teardown; retain the original deletion consent and saved receipts.
        #[arg(long)]
        reconcile: bool,
        /// Exact expired lease ETag from status; requires --reconcile and a quiescent previous controller.
        #[arg(long, requires = "reconcile")]
        recover_lease_etag: Option<String>,
        /// Explicit destructive consent for this saved foundation, not permission to remove shared team resources.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args)]
pub struct NodeLaunchArgs {
    #[command(flatten)]
    launch: LaunchArgs,
    /// Saved network ID/prefix/label (up only); rejects all explicit launch-input overrides. Not a restore for destroyed disks.
    #[arg(long, conflicts_with_all = ["config", "ami_id", "availability_zone", "package", "package_sha256", "manifest", "bundle", "image_record", "image_manifest", "image_config", "lightwallet_image_record", "lightwallet_image_manifest", "lightwallet_image_config", "host_helper", "reward_address"])]
    saved: Option<String>,
    /// Compatibility flag: fresh deployments always use the pinned native host helper.
    #[arg(long, conflicts_with = "saved")]
    native_runtime: bool,
    /// Saved-mode local ZDN profile (default devnet); requires --saved. Fresh mode uses config.profile.
    #[arg(long, requires = "saved")]
    profile: Option<String>,
    /// Digest-pinned deployment package manifest; resolves before local staging.
    #[arg(long, requires = "package_sha256")]
    package: Option<PathBuf>,
    /// Independently reviewed package manifest SHA256; required together with --package.
    #[arg(long, requires = "package")]
    package_sha256: Option<String>,
    /// Reviewed consensus manifest JSON; fresh non-package launch also requires bundle/helper/reward inputs.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Saved chain bundle matching --manifest; not a wallet backup.
    #[arg(long)]
    bundle: Option<PathBuf>,
    /// Node image provenance record JSON; supply all three image flags for a pinned-image launch, none for source.
    #[arg(long)]
    image_record: Option<PathBuf>,
    /// Exact raw OCI node image manifest bytes matching the record/digest; not a consensus manifest.
    #[arg(long)]
    image_manifest: Option<PathBuf>,
    /// Exact raw OCI node image configuration bytes matching the image manifest.
    #[arg(long)]
    image_config: Option<PathBuf>,
    /// Lightwalletd provenance record; requires all three lightwallet image files and enabled config service.
    #[arg(long)]
    lightwallet_image_record: Option<PathBuf>,
    /// Exact raw OCI lightwalletd manifest bytes; supply together with record/config.
    #[arg(long)]
    lightwallet_image_manifest: Option<PathBuf>,
    /// Exact raw OCI lightwalletd config bytes; supply together with record/manifest.
    #[arg(long)]
    lightwallet_image_config: Option<PathBuf>,
    /// Prebuilt Linux x86-64 zdn executable. Never the local macOS binary.
    #[arg(long)]
    host_helper: Option<PathBuf>,
    /// Testnet P2PKH/P2SH block reward address whose key you control; create the signing-enabled funding wallet BEFORE launch.
    #[arg(long)]
    reward_address: Option<String>,
}

#[derive(Subcommand)]
pub enum DevnetCommand {
    /// Export or explicitly attach a validated offline controller handoff.
    Handoff {
        #[command(subcommand)]
        command: HandoffCommand,
    },
    /// List saved deployments in the selected local profile's scope.
    List {
        #[command(flatten)]
        store: StoreArgs,
        /// Local ZDN profile scope to inspect; list does not contact AWS or establish health.
        #[arg(long, default_value = "devnet")]
        profile: String,
    },
    /// Replace only explicitly selected nodes' pinned images, retaining their chain disks.
    #[command(
        after_help = "New image update (service interruption; review storage/mixed-version compatibility first):\n  zdn devnet update NETWORK --node node-2 --image-record image.json --image-manifest image-manifest.json --image-config image-config.json --acknowledge-storage-compatibility --yes\nSource alternative: --source-config candidate.yaml --build-helper LINUX_EXPORTER instead of the three image flags. Requires explicit --node targets; no implicit all-node update.\nResume exact saved work:\n  zdn devnet update NETWORK --resume UPDATE_UUID --reconcile --acknowledge-storage-compatibility --yes\nResume omits all new source/image/target choices. It preserves saved bytes/journals; no automatic rollback or receipt-deletion retry. Keep partial confirmations, inspect unknown SSM outcomes and use fresh observations. Does not run Pulumi or update the installed host helper. See docs/updates.md."
    )]
    Update(UpdateArgs),
    /// Snapshot immutable inputs and print the private-node infrastructure. Makes no AWS calls.
    Render(NodeLaunchArgs),
    /// Install private Zakura nodes, scheduled blocks, and optional pinned lightwalletd.
    #[command(after_help = UP_HELP)]
    Up {
        #[command(flatten)]
        launch: NodeLaunchArgs,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Reobserve interrupted/uncertain saved work before retrying; not needed for a fresh launch.
        #[arg(long)]
        reconcile: bool,
        /// Exact expired lease ETag shown by status; requires --reconcile and a quiescent previous controller.
        #[arg(long, requires = "reconcile")]
        recover_lease_etag: Option<String>,
        /// Explicit consent to billed AWS build/deployment effects; --noninteractive does not imply it.
        #[arg(long)]
        yes: bool,
    },
    /// Inspect saved node deployment outputs and current AWS inventory.
    Status(ExistingArgs),
    /// Observe fresh node and enabled service readiness without changing the deployment.
    Health {
        #[command(flatten)]
        existing: ExistingArgs,
        /// Poll bounded fresh readiness checks; never starts, repairs or reconciles services.
        #[arg(long)]
        wait: bool,
        /// Overall observation deadline in seconds (1..=7200); ready:false is a failure, not qualification.
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u32).range(1..=7200))]
        timeout_seconds: u32,
    },
    /// Remove the node hosts/network; retain chain disks and artifacts unless --delete-data is set.
    #[command(after_help = DESTROY_HELP)]
    Destroy {
        #[command(flatten)]
        existing: ExistingArgs,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Irreversibly delete this deployment's owned chain/cache disks and versioned artifacts; shared backend is preserved.
        #[arg(long)]
        delete_data: bool,
        /// Reobserve an interrupted/uncertain teardown; retain the original --delete-data choice on retry.
        #[arg(long)]
        reconcile: bool,
        /// Exact expired lease ETag from status; requires --reconcile, not permission to override a live owner.
        #[arg(long, requires = "reconcile")]
        recover_lease_etag: Option<String>,
        /// Explicit destructive consent for the selected saved deployment; not implied by noninteractive mode.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum HandoffCommand {
    /// Write a new private, digest-pinned tar; makes no cloud calls.
    Export {
        #[command(flatten)]
        existing: ExistingArgs,
        /// New private tar path; preserves immutable inputs/journals, not credentials or wallet keys. Quiesce the source controller before transfer.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a handoff and bind it to this explicit config/worktree context.
    Import {
        #[command(flatten)]
        binding: BindingArgs,
        /// Receiving controller's saved local ZDN profile; must match the handoff's exact team.
        #[arg(long, default_value = "devnet")]
        profile: String,
        /// Private handoff tar from the source controller; never an arbitrary archive to execute.
        #[arg(long)]
        from: PathBuf,
        /// Independently conveyed handoff SHA256; integrity is not permission to resume unknown external effects.
        #[arg(long)]
        sha256: String,
        /// Independently expected full network UUID. Import never launches or reserves cloud resources.
        #[arg(long)]
        network_id: uuid::Uuid,
    },
}

#[derive(Args)]
pub struct UpdateArgs {
    #[command(flatten)]
    existing: ExistingArgs,
    #[command(flatten)]
    managed: ManagedArgs,
    /// Exact saved node ID; repeat to select nodes. At least one required for new updates; conflicts with --resume. No implicit all-node target.
    #[arg(long = "node", conflicts_with = "resume")]
    nodes: Vec<String>,
    /// Candidate provenance record; requires image manifest/config and conflicts with source-config/resume.
    #[arg(long, requires_all = ["image_manifest", "image_config"], conflicts_with_all = ["source_config", "resume"])]
    image_record: Option<PathBuf>,
    /// Exact OCI manifest bytes for --image-record (not a consensus manifest).
    #[arg(long, requires = "image_record")]
    image_manifest: Option<PathBuf>,
    /// Exact OCI configuration bytes for --image-record.
    #[arg(long, requires = "image_record")]
    image_config: Option<PathBuf>,
    /// Separate config changing only source/build inputs; requires --build-helper and conflicts with resume/image mode.
    #[arg(long, requires = "build_helper", conflicts_with = "resume")]
    source_config: Option<PathBuf>,
    /// Pinned Linux exporter for a new source build; does not replace the installed host helper.
    #[arg(long, requires = "source_config")]
    build_helper: Option<PathBuf>,
    /// Exact saved update UUID; requires --reconcile. Reuses saved bytes, never recaptures source; conflicts with new input/target selection.
    #[arg(long, requires = "reconcile")]
    resume: Option<uuid::Uuid>,
    /// Reobserve saved uncertain update/SSM work; never blindly redispatch an unknown command.
    #[arg(long)]
    reconcile: bool,
    /// Exact expired lease ETag shown by status; requires --resume and --reconcile plus a stopped previous controller.
    #[arg(long, requires_all = ["reconcile", "resume"])]
    recover_lease_etag: Option<String>,
    /// Required attestation: independently reviewed forward storage AND mixed-version compatibility. No automatic rollback.
    #[arg(long)]
    acknowledge_storage_compatibility: bool,
    /// Required consent to replace selected node images and stop/restart services, retaining their disks.
    #[arg(long)]
    yes: bool,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.devnet_update")
)]
pub fn devnet_update(
    args: UpdateArgs,
    output: &mut cli_output::OperationOutput,
) -> Result<serde_json::Value> {
    use zdn::foundation::update_controller as controller;
    ensure!(
        args.yes && args.acknowledge_storage_compatibility,
        "update requires --acknowledge-storage-compatibility --yes"
    );
    ensure!(
        args.resume.is_some() || (args.image_record.is_some() != args.source_config.is_some()),
        "select an image triple or --source-config, or resume a saved update"
    );
    ensure!(
        args.resume.is_some() || !args.nodes.is_empty(),
        "select at least one explicit --node"
    );
    // Validate and freeze caller inputs before saving a pending update. A bad
    // image must not strand the deployment behind an unresumable intent.
    let source_config = args
        .source_config
        .as_deref()
        .map(Config::load)
        .transpose()?;
    let pinned = if let Some(path) = &args.image_record {
        let record = zdn::devnet::read_bounded(path, zdn::image::MAX_RECORD_BYTES as u64)?;
        let manifest = zdn::devnet::read_bounded(
            args.image_manifest.as_ref().unwrap(),
            zdn::image::MAX_MANIFEST_BYTES as u64,
        )?;
        let config = zdn::devnet::read_bounded(
            args.image_config.as_ref().unwrap(),
            zdn::image::MAX_CONFIG_BYTES as u64,
        )?;
        let image = zdn::image::ImageRecord::from_json(&record)?;
        let verified = zdn::image::validate_manifest_bytes(&image, &manifest)?;
        zdn::image::validate_config_bytes(&image, &verified, &config)?;
        Some([
            ("image.json", record),
            ("image-manifest.json", manifest),
            ("image-config.json", config),
        ])
    } else {
        None
    };
    let (store, binding, file, mut deployment) = existing(args.existing)?;
    deployment.require_native_execution()?;
    output.network_id = Some(binding.network_id);
    if let Some(set) = deployment
        .cluster
        .as_ref()
        .and_then(|c| c.artifact_set.as_ref())
    {
        set.require_compatible()?;
    }
    let mut captured_source = None;
    let id = if let Some(id) = args.resume {
        controller::resume(&deployment, id, args.reconcile)?;
        id
    } else {
        if let Some(operation) = deployment.last_operation {
            ensure!(store.operation(operation)?.phases.iter().all(|p| matches!(p.status, zdn::state::PhaseStatus::Succeeded { .. })), "previous deployment operation is not settled; reconcile it before starting an update");
        }
        if let Some(config) = &source_config {
            let original = Config::load(&binding.context.config_path)?;
            ensure!(
                original.fingerprint()?
                    == deployment
                        .cluster
                        .as_ref()
                        .context("node deployment required")?
                        .config_sha256,
                "original bound config changed; restore it before selecting a source update"
            );
            controller::validate_source_config(&original, config)?;
            ensure!(
                config.node.source.path.is_some() && config.node.build.is_some(),
                "source update requires a local source and build settings"
            );
            // Finish fallible local capture/recipe validation before creating
            // an intent. Failed preparation has made no cloud changes.
            let pending = tempfile::tempdir_in(file.directory())?;
            let receipt = source::capture(&CaptureOptions {
                source: config
                    .source_root(args.source_config.as_ref().unwrap())?
                    .unwrap(),
                output: pending.path().join("snapshot"),
                revision: config.node.source.revision.clone(),
                include: vec![],
            })?;
            let contract =
                zdn::build::BuildContract::new(&receipt, config.node.build.as_ref().unwrap())?;
            contract.verify_archive(&pending.path().join("snapshot/source.tar"))?;
            zdn::build_job::prepare_native(
                &pending.path().join("build"),
                &deployment.team,
                &contract,
                args.build_helper.as_ref().unwrap(),
            )?;
            captured_source = Some((pending, contract));
        }
        if let Some(inputs) = &pinned {
            let mut request = deployment
                .cluster
                .clone()
                .context("node deployment required")?;
            request.image = zdn::image::ImageRecord::from_json(&inputs[0].1)?;
            request.ecr_repository(&deployment.team)?;
        }
        controller::prepare(&mut deployment, &args.nodes, true)?
    };
    foundation::private_directory(&file.directory().join("updates"))?;
    let directory = file.directory().join("updates").join(id.to_string());
    foundation::private_directory(&directory)?;
    let artifacts = directory.join("artifacts");
    foundation::private_directory(&artifacts)?;
    // New requests capture once. Resume never opens a working checkout or caller input.
    if args.resume.is_none() {
        if let Some((pending, contract)) = captured_source {
            let config = source_config.as_ref().unwrap();
            fs::rename(
                pending.path().join("snapshot"),
                directory.join("source-snapshot"),
            )?;
            foundation::write_private(
                &directory.join("source-config.json"),
                &serde_json::to_vec_pretty(config)?,
            )?;
            foundation::write_private(
                &directory.join("build-contract.json"),
                &serde_json::to_vec_pretty(&contract)?,
            )?;
            fs::rename(pending.path().join("build"), directory.join("build"))?;
            let intent = deployment
                .runtime
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap();
            intent.build_contract_sha256 = Some(contract.fingerprint()?);
            intent.build_exporter_protocol = Some(zdn::build_export::PROTOCOL.into());
        } else {
            for (name, bytes) in pinned.as_ref().unwrap() {
                foundation::write_private(&artifacts.join(name), bytes)?;
            }
            deployment
                .runtime
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap()
                .revision = Some(zdn::update::ImageRevision::read(id, None, &directory)?);
        }
        // Commit directory entries before the single intent publication. A
        // preparation interruption leaves only an unused UUID directory, not
        // a pending deployment whose recovery inputs are incomplete.
        fs::File::open(&directory)?.sync_all()?;
        fs::File::open(directory.parent().unwrap())?.sync_all()?;
        file.save(&deployment)?;
    }
    output.observe_update(id)?;
    if !output.format.machine() {
        eprintln!("Image update {id}; resume with devnet update {} --resume {id} --reconcile --acknowledge-storage-compatibility --yes", binding.network_id);
    }
    let build_contract: Option<zdn::build::BuildContract> =
        if directory.join("build-contract.json").try_exists()? {
            Some(foundation::read_json(
                &directory.join("build-contract.json"),
            )?)
        } else {
            None
        };
    let intent = deployment
        .runtime
        .as_ref()
        .unwrap()
        .update
        .as_ref()
        .unwrap();
    let build_contract = if let Some(revision) = &intent.revision {
        let embedded = revision.build.clone();
        ensure!(
            build_contract
                .as_ref()
                .is_none_or(|saved| Some(saved) == embedded.as_ref()),
            "saved update build contract changed or is missing"
        );
        embedded
    } else {
        build_contract
    };
    ensure!(
        build_contract
            .as_ref()
            .map(zdn::build::BuildContract::fingerprint)
            .transpose()?
            == intent.build_contract_sha256,
        "saved update build contract changed or is missing"
    );
    if intent.build_exporter_protocol.is_some() && intent.revision.is_none() {
        let observed = zdn::build_job::validate_preparation(
            &directory.join("build"),
            &deployment.team,
            build_contract
                .as_ref()
                .context("native update build contract missing")?,
        )?;
        ensure!(
            observed.exporter_helper.is_some(),
            "native update exporter selection missing"
        );
    }
    let mut operation = store.begin_operation(
        &binding,
        "devnet-update",
        zdn::state::OperationInput {
            config_sha256: zdn::devnet::sha256(&serde_json::to_vec(
                &deployment.runtime.as_ref().unwrap().update,
            )?),
            source_manifest_sha256: build_contract
                .as_ref()
                .map(zdn::build::BuildContract::fingerprint)
                .transpose()?,
            archive_sha256: build_contract.as_ref().map(|c| c.source_sha256.clone()),
        },
        &["update"],
    )?;
    deployment.last_operation = Some(operation.operation_id);
    file.save(&deployment)?;
    output.observe(&operation, None)?;
    let output = std::cell::RefCell::new(output);
    let mut backend = LiveBackend::new(
        &deployment,
        file.directory(),
        &data_path(args.managed.managed_dir, "tools")?,
        cancellation()?,
        args.recover_lease_etag,
    )?;
    backend.observe_commands(|command| output.borrow_mut().observe_command(command));
    operation = store.record_phase(
        operation.operation_id,
        operation.revision,
        "update",
        zdn::state::PhaseStatus::Running {
            external_ref: Some(id.to_string()),
        },
    )?;
    let result = (|| -> Result<()> {
        output.borrow_mut().observe(&operation, Some("update"))?;
        backend.acquire_update(&deployment, operation.operation_id)?;
        backend.preflight_update(&deployment, args.resume.is_none())?;
        if deployment
            .runtime
            .as_ref()
            .and_then(|r| r.update.as_ref())
            .and_then(|u| u.revision.as_ref())
            .is_none()
        {
            let build = if let Some(contract) = build_contract {
                let archive = directory.join("source-snapshot/source.tar");
                contract.verify_archive(&archive)?;
                backend.build_update(
                    &contract,
                    &archive,
                    &directory.join("build"),
                    &mut |build| output.borrow_mut().observe_build(build),
                )?;
                for name in ["image.json", "image-manifest.json", "image-config.json"] {
                    let bytes = zdn::devnet::read_bounded(
                        &directory.join("build").join(name),
                        zdn::image::MAX_CONFIG_BYTES as u64,
                    )?;
                    if artifacts.join(name).exists() {
                        ensure!(
                            zdn::devnet::read_bounded(
                                &artifacts.join(name),
                                zdn::image::MAX_CONFIG_BYTES as u64
                            )? == bytes,
                            "saved build artifact changed"
                        );
                    } else {
                        foundation::write_private(&artifacts.join(name), &bytes)?;
                    }
                }
                Some(contract)
            } else {
                None
            };
            controller::set_revision(
                &file,
                &mut deployment,
                zdn::update::ImageRevision::read(id, build, &directory)?,
            )?;
        }
        controller::run_with_progress(&file, &mut deployment, &mut backend, &mut |intent, node| {
            output.borrow_mut().observe_update_progress(intent, node)
        })
    })();
    let released = backend.release_update();
    let status = if result.is_ok() && released.is_ok() {
        zdn::state::PhaseStatus::Succeeded {
            result: json!({"updateId":id,"freshClusterAndServicesChecked":true}),
        }
    } else {
        zdn::state::PhaseStatus::Unknown {
            message: "image update did not finish; resume the saved UUID with --reconcile".into(),
            external_ref: Some(id.to_string()),
        }
    };
    operation = store.record_phase_outcome(&operation, "update", status)?;
    output.borrow_mut().observe(&operation, Some("update"))?;
    result?;
    released?;
    Ok(
        json!({"networkId":binding.network_id,"savedRuntime":deployment.runtime,"liveReadinessChecked":true}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.node_launch")
)]
fn node_launch(
    mut args: NodeLaunchArgs,
    cancel: Option<&Arc<AtomicBool>>,
    mut output: Option<&mut cli_output::OperationOutput>,
) -> Result<(StateStore, zdn::state::Binding, DeploymentFile, Deployment)> {
    let config = Config::load(&args.launch.config.config)?;
    let source_build = config.node.source.path.is_some();
    zdn::devnet::require_supported_services(&config)?;
    let resolved_package = if let Some(path) = &args.package {
        ensure!(!source_build, "a package contains a completed image; use a pinned-image configuration, not a working source checkout");
        ensure!(
            args.reward_address.is_some(),
            "a package deployment requires --reward-address"
        );
        let overrides = [
            ("manifest.json", &args.manifest),
            ("chain.tar", &args.bundle),
            ("image.json", &args.image_record),
            ("image-manifest.json", &args.image_manifest),
            ("image-config.json", &args.image_config),
            ("zdn", &args.host_helper),
            ("lightwallet-image.json", &args.lightwallet_image_record),
            (
                "lightwallet-image-manifest.json",
                &args.lightwallet_image_manifest,
            ),
            (
                "lightwallet-image-config.json",
                &args.lightwallet_image_config,
            ),
        ]
        .into_iter()
        .filter_map(|(name, path)| path.as_ref().map(|p| (name.into(), p.clone())))
        .collect();
        let resolved =
            zdn::package::resolve(path, args.package_sha256.as_deref().unwrap(), &overrides)?;
        ensure!(
            config.node.source.image.as_deref()
                == Some(resolved.artifact_set.node_image.image.as_str()),
            "package image differs from the pinned configuration"
        );
        ensure!(
            config.services.lightwallet == resolved.artifact_set.lightwallet_image.is_some(),
            "package lightwallet selection differs from configuration"
        );
        let root = resolved.directory();
        zdn::devnet::validate_chain_inputs(
            &config,
            &zdn::devnet::read_bounded(&root.join("manifest.json"), 2 * 1024 * 1024)?,
            &root.join("chain.tar"),
        )?;
        args.manifest = Some(root.join("manifest.json"));
        args.bundle = Some(root.join("chain.tar"));
        args.image_record = Some(root.join("image.json"));
        args.image_manifest = Some(root.join("image-manifest.json"));
        args.image_config = Some(root.join("image-config.json"));
        args.host_helper = Some(root.join("zdn"));
        if config.services.lightwallet {
            args.lightwallet_image_record = Some(root.join("lightwallet-image.json"));
            args.lightwallet_image_manifest = Some(root.join("lightwallet-image-manifest.json"));
            args.lightwallet_image_config = Some(root.join("lightwallet-image-config.json"));
        }
        Some(resolved)
    } else {
        None
    };
    let lightwallet_supplied = [
        args.lightwallet_image_record.is_some(),
        args.lightwallet_image_manifest.is_some(),
        args.lightwallet_image_config.is_some(),
    ];
    ensure!(!lightwallet_supplied.iter().any(|v| *v) || lightwallet_supplied.iter().all(|v| *v), "supply --lightwallet-image-record, --lightwallet-image-manifest and --lightwallet-image-config together");
    ensure!(
        config.services.lightwallet || !lightwallet_supplied.iter().any(|v| *v),
        "lightwallet image inputs require services.lightwallet: true"
    );
    ensure!(
        config.access.visibility == zdn::config::Visibility::Private,
        "private-node deployment cannot enable public access"
    );
    let supplied = [
        args.manifest.is_some(),
        args.bundle.is_some(),
        args.host_helper.is_some(),
        args.reward_address.is_some(),
    ];
    let image_supplied = [
        args.image_record.is_some(),
        args.image_manifest.is_some(),
        args.image_config.is_some(),
    ];
    let new_inputs = supplied
        .iter()
        .chain(image_supplied.iter())
        .chain(lightwallet_supplied.iter())
        .any(|v| *v);
    if new_inputs {
        ensure!(
            supplied.iter().all(|v| *v),
            "supply --manifest, --bundle, --host-helper and --reward-address together"
        );
        ensure!(if source_build { image_supplied.iter().all(|v| !*v) } else { image_supplied.iter().all(|v| *v) }, "source builds must omit image inputs; image deployments require --image-record, --image-manifest and --image-config");
        ensure!(config.services.lightwallet == lightwallet_supplied.iter().all(|v| *v), "services.lightwallet requires all three lightwallet image inputs; disable it for a node-only deployment");
    }
    let (store, binding, file, mut deployment) = launch(args.launch.clone(), LaunchMode::Node)?;
    if let Some(path) = &args.manifest {
        let manifest: ConsensusManifest = zdn::foundation::read_json(path)?;
        connect_cli::check_registered_manifest(&store, binding.network_id, &manifest)?;
    } else if let Some(cluster) = &deployment.cluster {
        connect_cli::check_registered_manifest(&store, binding.network_id, &cluster.manifest)?;
    }
    // Reject conversion before source capture, build submission, or restaging.
    zdn::devnet::select_native_runtime(
        deployment
            .cluster
            .as_ref()
            .map(|s| s.native_runtime_protocol.as_deref()),
        args.native_runtime,
    )?;
    ensure!(
        deployment.foundation_runtime.is_none(),
        "native foundation cannot become a node deployment"
    );
    if let Some(output) = output.as_deref_mut() {
        output.network_id = Some(binding.network_id);
    }
    ensure!(
        !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
        "an image update is unresolved; resume devnet update before up"
    );
    ensure!(
        !new_inputs
            || !deployment
                .runtime
                .as_ref()
                .is_some_and(|r| !r.nodes.is_empty()),
        "up with runtime revisions must reuse saved inputs; use devnet update for image changes"
    );
    ensure!(
        deployment.cluster.is_some()
            || (!deployment.stack_initialized
                && deployment.last_operation.is_none()
                && deployment.outputs.is_none()),
        "an existing foundation host cannot be converted to a node cluster; use a new binding"
    );
    let mut build_contract = None;
    let mut preparation = None;
    if source_build && new_inputs {
        ensure!(deployment.team.deployment.is_some(), "source builds require administrator-managed build resources and deployment access; repeat setup bootstrap");
        source_preflight(&config, &args, &deployment.spec)?;
        let prepared = file
            .directory()
            .join(zdn::build::preparation::RECORD)
            .try_exists()?
            || file.directory().join("source-preparation").try_exists()?;
        let snapshot = file.directory().join("source-snapshot");
        let receipt: SnapshotReceipt = if snapshot.try_exists()? {
            ensure!(
                fs::symlink_metadata(&snapshot)?.is_dir(),
                "saved source snapshot must be a real directory"
            );
            serde_json::from_slice(&read_small(&snapshot.join("receipt.json"))?)
                .context("invalid saved source snapshot receipt")?
        } else {
            ensure!(
                !prepared && !file.directory().join("build").try_exists()?,
                "build receipt exists without its saved source snapshot; refusing recapture"
            );
            source::capture(&CaptureOptions {
                source: config
                    .source_root(&args.launch.config.config)?
                    .context("missing source directory")?,
                output: snapshot.clone(),
                revision: config.node.source.revision.clone(),
                include: vec![],
            })?
        };
        let inputs = operation_inputs(&config, &args.launch.config.config, Some(&snapshot), false)?;
        let inputs_path = file.directory().join("source-build-inputs.json");
        if inputs_path.try_exists()? {
            let saved: zdn::state::OperationInput =
                serde_json::from_slice(&read_small(&inputs_path)?)?;
            saved.validate()?;
            if saved != inputs {
                return Err(ImmutableInputError::new(
                    "source build inputs changed; resume requires the saved configuration and archive",
                    ImmutableInputReport::operation_inputs(&saved, &inputs)?,
                ).into());
            }
        } else {
            ensure!(
                !prepared && !file.directory().join("build").try_exists()?,
                "source build input receipt missing; inspect the existing build before retrying"
            );
            foundation::write_private(&inputs_path, &serde_json::to_vec_pretty(&inputs)?)?;
        }
        let contract = zdn::build::BuildContract::new(
            &receipt,
            config
                .node
                .build
                .as_ref()
                .context("missing build settings")?,
        )?;
        contract.verify_archive(&snapshot.join("source.tar"))?;
        if deployment.cluster.is_none() {
            ensure!(
                store.handoff_operations(&binding)?.is_empty(),
                "initial source preparation has operation history"
            );
            let sources = [
                ("manifest.json", &args.manifest),
                ("chain.tar", &args.bundle),
                ("zdn", &args.host_helper),
                ("lightwallet-image.json", &args.lightwallet_image_record),
                (
                    "lightwallet-image-manifest.json",
                    &args.lightwallet_image_manifest,
                ),
                (
                    "lightwallet-image-config.json",
                    &args.lightwallet_image_config,
                ),
            ]
            .into_iter()
            .filter_map(|(name, path)| {
                path.as_ref()
                    .map(|p| (format!("source-preparation/{name}"), p.clone()))
            })
            .collect();
            preparation = Some(zdn::build::preparation::Preparation::save(
                &config,
                &deployment,
                &contract,
                args.reward_address.as_deref().unwrap(),
                args.native_runtime,
                &sources,
                file.directory(),
            )?);
        }
        let (api, _) = zdn::credentials::client(
            &deployment.team,
            aws::AwsSelection {
                profile: deployment.spec.aws_profile.clone(),
                account_id: deployment.team.aws.account_id.clone(),
                region: deployment.team.aws.region.clone(),
            },
            &file.directory().join("credentials"),
        )?;
        aws::verify_identity(&api, api.selection())?;
        let cancel = cancel.context("source builds require an explicitly authorized up")?;
        let directory = file.directory().join("build");
        zdn::build_job::run_with_progress(
            &api,
            &deployment.team,
            &contract,
            &snapshot.join("source.tar"),
            &directory,
            &foundation_live::SystemRuntime::default(),
            || {
                ensure!(!cancel.load(Ordering::SeqCst), "build cancelled");
                Ok(())
            },
            &mut |build| match output.as_deref_mut() {
                Some(output) => output.observe_build(build),
                None => Ok(()),
            },
        )?;
        args.image_record = Some(directory.join("image.json"));
        args.image_manifest = Some(directory.join("image-manifest.json"));
        args.image_config = Some(directory.join("image-config.json"));
        build_contract = Some(contract);
    }
    let mut request = if let Some(preparation) = preparation {
        preparation.stage(file.directory(), &deployment)?
    } else if new_inputs {
        let lightwallet_paths = args
            .lightwallet_image_record
            .as_deref()
            .map(|image_record| zdn::devnet::LightwalletInputPaths {
                image_record,
                image_manifest: args.lightwallet_image_manifest.as_deref().unwrap(),
                image_config: args.lightwallet_image_config.as_deref().unwrap(),
            });
        let mut request = zdn::devnet::stage_with_lightwallet(
            &config,
            &deployment.spec,
            &deployment.team,
            &zdn::devnet::InputPaths {
                build_contract: build_contract.as_ref(),
                manifest: args.manifest.as_deref().unwrap(),
                bundle: args.bundle.as_deref().unwrap(),
                image_record: args.image_record.as_deref().unwrap(),
                image_manifest: args.image_manifest.as_deref().unwrap(),
                image_config: args.image_config.as_deref().unwrap(),
                helper: args.host_helper.as_deref().unwrap(),
            },
            lightwallet_paths.as_ref(),
            args.reward_address.as_deref().unwrap(),
            file.directory(),
        )?;
        if let Some(service) = &mut request.lightwallet {
            service.capacity_protocol = match &deployment.cluster {
                Some(saved) => saved
                    .lightwallet
                    .as_ref()
                    .and_then(|s| s.capacity_protocol.clone()),
                None => Some(zdn::host::CAPACITY_PROTOCOL.into()),
            };
        }
        request.installer_fetch_protocol = match &deployment.cluster {
            Some(saved) => saved.installer_fetch_protocol.clone(),
            None => Some(zdn::host::installer_bootstrap::PROTOCOL.into()),
        };
        request
    } else {
        deployment.cluster.clone().context("first node deployment requires saved chain/image inputs and a Linux host helper; inspect devnet render --help")?
    };
    request.native_runtime_protocol =
        zdn::devnet::select_native_runtime(
            deployment
                .cluster
                .as_ref()
                .map(|s| s.native_runtime_protocol.as_deref())
                .or((!new_inputs || source_build)
                    .then_some(request.native_runtime_protocol.as_deref())),
            args.native_runtime,
        )?;
    request.validate(&deployment.spec, &deployment.team)?;
    if let Some(resolved) = resolved_package {
        request.build = resolved.artifact_set.build.clone();
        request.artifact_set = Some(resolved.artifact_set);
        request.validate(&deployment.spec, &deployment.team)?;
    }
    if config.services.lightwallet != request.lightwallet.is_some() {
        return Err(ImmutableInputError::new(
            "saved deployment does not match services.lightwallet; existing node-only deployments cannot be converted during recovery",
            ImmutableInputReport::lightwallet_selection(),
        ).into());
    }
    if request.config_sha256 != config.fingerprint()? {
        return Err(ImmutableInputError::new(
            "devnet configuration differs from the immutable saved node request; binary/config updates are not implemented yet",
            ImmutableInputReport::config_fingerprint(),
        ).into());
    }
    if let Some(saved) = &deployment.cluster {
        if serde_json::to_value(saved)? != serde_json::to_value(&request)? {
            return Err(ImmutableInputError::new(
                "cannot change existing cluster inputs; preserve the saved deployment for recovery",
                ImmutableInputReport::cluster_request(saved, &request)?,
            )
            .into());
        }
    }
    request.verify_local(file.directory())?;
    deployment.cluster = Some(request);
    deployment.validate()?;
    // Rendering verifies topology and prerequisites before saving a launchable request.
    deployment.render()?;
    file.save(&deployment)?;
    Ok((store, binding, file, deployment))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.source_preflight")
)]
fn source_preflight(config: &Config, args: &NodeLaunchArgs, spec: &FoundationSpec) -> Result<()> {
    let manifest = zdn::devnet::validate_chain_inputs(
        config,
        &zdn::devnet::read_bounded(
            args.manifest
                .as_ref()
                .context("source up requires --manifest")?,
            2 * 1024 * 1024,
        )?,
        args.bundle
            .as_deref()
            .context("source up requires --bundle")?,
    )?;
    zdn::devnet::validate_helper(&zdn::devnet::read_bounded(
        args.host_helper
            .as_ref()
            .context("source up requires --host-helper")?,
        zdn::devnet::MAX_HELPER_BYTES,
    )?)?;
    let mut options = zdn::chain::runtime_config::RuntimeOptions::new(spec.network_id, "node-1");
    options.role = zdn::chain::runtime_config::NodeRole::Producer;
    options.reward_address = Some(
        args.reward_address
            .clone()
            .context("source up requires --reward-address")?,
    );
    zdn::chain::runtime_config::render_runtime_config(&manifest, &options)?;
    if config.services.lightwallet {
        let record = zdn::lightwallet_image::ImageRecord::from_json(&zdn::devnet::read_bounded(
            args.lightwallet_image_record
                .as_ref()
                .context("lightwallet record missing")?,
            zdn::image::MAX_RECORD_BYTES as u64,
        )?)?;
        zdn::lightwallet_image::validate_artifacts(
            &record,
            &zdn::devnet::read_bounded(
                args.lightwallet_image_manifest
                    .as_ref()
                    .context("lightwallet manifest missing")?,
                zdn::image::MAX_MANIFEST_BYTES as u64,
            )?,
            &zdn::devnet::read_bounded(
                args.lightwallet_image_config
                    .as_ref()
                    .context("lightwallet config missing")?,
                zdn::image::MAX_CONFIG_BYTES as u64,
            )?,
            None,
        )?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.devnet")
)]
pub fn devnet(command: DevnetCommand) -> Result<()> {
    match command {
        DevnetCommand::Handoff { command } => match command {
            HandoffCommand::Export { existing, output } => {
                let (store, binding, profile) = existing_selection(existing)?;
                let deployment = DeploymentFile::read_snapshot(store.root(), binding.network_id)?;
                ensure!(
                    deployment.team == profile.team
                        && deployment.spec.aws_profile == profile.aws_profile,
                    "saved deployment differs from selected local profile"
                );
                let sha256 = zdn::handoff::export::export(&store, &binding, &output)?;
                print_json(
                    &json!({"apiVersion": zdn::handoff::API_VERSION, "networkId": binding.network_id,
                    "output": output, "sha256": sha256, "cloudAccessChecked": false}),
                )
            }
            HandoffCommand::Import {
                binding,
                profile,
                from,
                sha256,
                network_id,
            } => {
                let (_, context) = binding_context(&binding)?;
                let store = open_store(binding.store)?;
                let profile = load_profile(&store, &profile)?;
                let attached = zdn::handoff::import::import(
                    &store, &context, network_id, &profile, &from, &sha256,
                )?;
                print_json(
                    &json!({"apiVersion": zdn::handoff::API_VERSION, "networkId": attached.network_id,
                    "binding": attached, "cloudAccessChecked": false, "deploymentStarted": false}),
                )
            }
        },
        DevnetCommand::Update(args) => {
            let mut output =
                cli_output::OperationOutput::new(cli_output::Format::Human, "devnet update");
            print_json(&devnet_update(args, &mut output)?)
        }
        DevnetCommand::Render(args) => {
            ensure!(
                args.saved.is_none(),
                "--saved is supported only by devnet up"
            );
            let config = Config::load(&args.launch.config.config)?;
            if let Some(source_root) = config.source_root(&args.launch.config.config)? {
                ensure!(args.package.is_none(), "a package contains a completed image; source render cannot resolve a deployment package");
                zdn::devnet::require_supported_services(&config)?;
                ensure!(
                    [&args.image_record, &args.image_manifest, &args.image_config]
                        .iter()
                        .all(|v| v.is_none()),
                    "source render must omit prebuilt image inputs"
                );
                let temporary = tempfile::tempdir()?;
                let receipt = source::capture(&CaptureOptions {
                    source: source_root,
                    output: temporary.path().join("snapshot"),
                    revision: config.node.source.revision.clone(),
                    include: vec![],
                })?;
                let contract = zdn::build::BuildContract::new(
                    &receipt,
                    config
                        .node
                        .build
                        .as_ref()
                        .context("missing build settings")?,
                )?;
                contract.verify_archive(&temporary.path().join("snapshot/source.tar"))?;
                return print_json(
                    &json!({"buildContract":contract,"contractSha256":contract.fingerprint()?,"cloudActionStarted":false,"launchReady":false,"qualification":"pending","next":"zdn up --yes with chain inputs, Linux helper and reward address; source is captured again at up","costItems":["native CodeBuild job","private S3 source/results storage","ECR image storage","private EC2 nodes after image verification"]}),
                );
            }
            let (_, _, file, deployment) = node_launch(args, None, None)?;
            let cluster = deployment.cluster.as_ref().unwrap();
            let mut cost_items = vec![
                "one EC2 host and root/chain EBS disks per node",
                "one NAT gateway and public IPv4",
                "S3 artifacts/state and KMS",
            ];
            if cluster.lightwallet.is_some() {
                cost_items.push("one dedicated retained lightwalletd cache EBS disk");
            }
            print_json(
                &json!({"networkId":deployment.spec.network_id,"receiptDirectory":file.directory(),"nodeCount":cluster.node_count,"image":cluster.image,"lightwallet":cluster.lightwallet,"artifactSetSha256":cluster.artifact_set.as_ref().map(zdn::artifact_set::ArtifactSet::fingerprint).transpose()?,"consensusFingerprint":cluster.manifest.fingerprint()?,"pulumiYaml":deployment.render()?.to_yaml()?,"blockIntervalSeconds":cluster.block_interval_seconds,"producerNode":cluster.block_interval_seconds.map(|_| "node-1"),"nodeRuntimeQualified":false,"scheduledProducer":false,"launchReady":false,"costItems":cost_items}),
            )
        }
        up @ DevnetCommand::Up { .. } => {
            let mut output =
                cli_output::OperationOutput::new(cli_output::Format::Human, "devnet up");
            print_json(&devnet_up(up, &mut output)?)
        }
        command @ (DevnetCommand::List { .. }
        | DevnetCommand::Status(_)
        | DevnetCommand::Health { .. }) => {
            let health = matches!(command, DevnetCommand::Health { .. });
            let report = devnet_discovery(command)?;
            print_json(&report)?;
            if health {
                ensure!(
                    report["ready"] == true,
                    "live readiness not established; see health report"
                );
            }
            Ok(())
        }
        destroy @ DevnetCommand::Destroy { .. } => {
            let mut output =
                cli_output::OperationOutput::new(cli_output::Format::Human, "devnet destroy");
            print_json(&devnet_destroy(destroy, &mut output)?)
        }
    }
}

/// Read-only reports shared by human and machine output; never capture stdout.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.devnet_discovery")
)]
pub fn devnet_discovery(command: DevnetCommand) -> Result<serde_json::Value> {
    match command {
        DevnetCommand::List { store, profile } => discovery::list(store, profile),
        DevnetCommand::Status(args) => {
            let (store, binding, profile) = existing_selection(args)?;
            let deployment = select_existing_profile(
                DeploymentFile::read_snapshot(store.root(), binding.network_id)?,
                profile,
            )?;
            ensure!(
                deployment.cluster.is_some(),
                "saved deployment is a health-test foundation; use foundation status"
            );
            status_report(&store, &binding, &deployment)
        }
        DevnetCommand::Health {
            existing,
            wait,
            timeout_seconds,
        } => {
            let (store, binding, profile) = existing_selection(existing)?;
            let deployment = DeploymentFile::read_snapshot(store.root(), binding.network_id)?;
            ensure!(
                deployment.team == profile.team,
                "saved deployment team differs from the selected profile"
            );
            let directory = store
                .root()
                .join("foundation")
                .join(binding.network_id.to_string());
            let options = zdn::health::Options {
                wait,
                timeout_secs: timeout_seconds,
            };
            if let Some(id) = deployment.last_operation {
                let operation = store.operation(id)?;
                ensure!(
                    operation.network_id == binding.network_id
                        && operation.scope == binding.context.scope
                        && operation.phases.iter().all(|phase| matches!(
                            phase.status,
                            zdn::state::PhaseStatus::Succeeded { .. }
                        )),
                    "health refuses an incomplete or foreign operation"
                );
            }
            zdn::health::validate(&deployment, &directory, options)?;
            // Selected credentials must not rewrite the immutable saved volume proofs.
            let (api, _) = zdn::credentials::client(
                &deployment.team,
                profile.selection(),
                &store.root().join("credentials"),
            )?;
            api.verify_identity()?;
            let cancel = cancellation()?;
            let report = zdn::health::check(
                &api,
                &deployment,
                &directory,
                options,
                &foundation_live::SystemRuntime::default(),
                &cancel,
            )?;
            Ok(serde_json::to_value(report)?)
        }
        _ => unreachable!(),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.devnet_up")
)]
pub fn devnet_up(
    command: DevnetCommand,
    output: &mut cli_output::OperationOutput,
) -> Result<serde_json::Value> {
    let DevnetCommand::Up {
        launch,
        managed,
        reconcile,
        recover_lease_etag,
        yes,
    } = command
    else {
        unreachable!()
    };
    ensure!(
        yes,
        "devnet up creates billed AWS resources; inspect devnet render and pass --yes"
    );
    let cancel = cancellation()?;
    let (store, binding, file, mut deployment) = if let Some(selector) = launch.saved {
        saved_node_launch(
            ExistingArgs {
                selector,
                store: launch.launch.store,
                profile: launch.profile.unwrap_or_else(|| "devnet".into()),
            },
            reconcile,
            &cancel,
            output,
        )?
    } else {
        node_launch(launch, Some(&cancel), Some(output))?
    };
    output.network_id = Some(binding.network_id);
    if !output.format.machine() {
        describe_target(&deployment, "deploy private nodes");
    }
    let output = std::cell::RefCell::new(output);
    let mut backend = LiveBackend::new(
        &deployment,
        file.directory(),
        &data_path(managed.managed_dir, "tools")?,
        cancel,
        recover_lease_etag,
    )?;
    backend.observe_commands(|command| output.borrow_mut().observe_command(command));
    let operation = foundation::apply_with_progress(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        reconcile,
        &mut |receipt, phase| output.borrow_mut().observe(receipt, phase),
    )?;
    let observations = operation
        .phases
        .iter()
        .find(|p| p.name == "readiness")
        .map(|p| &p.status);
    let scheduled = match observations {
        Some(zdn::state::PhaseStatus::Succeeded { result }) => result["scheduledProducer"]
            .as_bool()
            .context("readiness did not report producer state")?,
        _ => eyre::bail!("node readiness did not complete"),
    };
    Ok(
        json!({"nodeReady":true,"networkId":binding.network_id,"outputs":deployment.outputs,"observations":observations,"operationId":operation.operation_id,"scheduledProducer":scheduled,"paymentQualification":"pending","launchReady":false}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.devnet_destroy")
)]
pub fn devnet_destroy(
    command: DevnetCommand,
    output: &mut cli_output::OperationOutput,
) -> Result<serde_json::Value> {
    let DevnetCommand::Destroy {
        existing: args,
        managed,
        delete_data,
        reconcile,
        recover_lease_etag,
        yes,
    } = command
    else {
        unreachable!()
    };
    ensure!(yes,"devnet destroy removes hosts/network; pass --yes (disks/artifacts remain unless --delete-data is set)");
    let (store, binding, file, mut deployment) = existing(args)?;
    output.network_id = Some(binding.network_id);
    if deployment.cluster.is_none() {
        ensure!(
            deployment.foundation_runtime.is_none(),
            "saved deployment is a health-test foundation; use foundation destroy"
        );
        // Source launch saves its inputs before a verified image/node request
        // exists. Cleanup still uses the original deployment ownership checks.
        let inputs: zdn::state::OperationInput =
            foundation::read_json(&file.directory().join("source-build-inputs.json"))
                .context("saved deployment has no source launch inputs; use foundation destroy")?;
        inputs.validate()?;
        ensure!(
            inputs.source_manifest_sha256.is_some() && inputs.archive_sha256.is_some(),
            "incomplete source launch inputs"
        );
    }
    let mut backend = LiveBackend::new(
        &deployment,
        file.directory(),
        &data_path(managed.managed_dir, "tools")?,
        cancellation()?,
        recover_lease_etag,
    )?;
    let operation = foundation::destroy_with_progress(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        delete_data,
        reconcile,
        &mut |receipt, phase| output.observe(receipt, phase),
    )?;
    Ok(
        json!({"destroyed":true,"networkId":binding.network_id,"operationId":operation.operation_id,"cleanup":deployment.cleanup,"sharedBackendPreserved":true,"retainedDataContinuesToCostMoney":!delete_data}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.status_report")
)]
fn status_report(
    store: &StateStore,
    binding: &zdn::state::Binding,
    deployment: &Deployment,
) -> Result<serde_json::Value> {
    let (api, _) = zdn::credentials::client(
        &deployment.team,
        aws::AwsSelection {
            profile: deployment.spec.aws_profile.clone(),
            account_id: deployment.spec.scope.account_id.clone(),
            region: deployment.spec.scope.region.clone(),
        },
        &store.root().join("credentials"),
    )?;
    api.verify_identity()?;
    let reservation = NetworkReservation::new(
        deployment.spec.scope.clone(),
        deployment.spec.network_id,
        deployment.owner_id,
    )?;
    let lease = aws::inspect_lease(&S3Metadata::new(&api, &deployment.team)?, &reservation)?;
    // Inventory checks deployment resources, not the shared backend. Keep that
    // unknown distinct from a failed preservation check in a cleanup receipt.
    let mut inventory = json!(foundation_live::inventory(&api, deployment)?);
    inventory["shared_backend_preserved"] = serde_json::Value::Null;
    Ok(
        json!({"networkId":binding.network_id,"destroyed":deployment.destroyed,"inventory":inventory,"lastOperation":deployment.last_operation,"lease":lease.map(|v|json!({"record":v.record,"etag":v.etag})),"savedOutputs":deployment.outputs,"savedRuntime":deployment.runtime,"liveReadinessChecked":false,"sharedBackendChecked":false}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.profile_path")
)]
pub(super) fn profile_path(store: &StateStore, name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "local profile name must contain ASCII letters, digits, hyphens, or underscores"
    );
    let directory = store.root().join("profiles");
    foundation::private_directory(&directory)?;
    Ok(directory.join(format!("{name}.json")))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.load_profile")
)]
pub(super) fn load_profile(store: &StateStore, name: &str) -> Result<LocalProfile> {
    let profile: LocalProfile = foundation::read_json(&profile_path(store, name)?)
        .context("run zdn setup bootstrap or setup import for this local profile")?;
    profile.validate()?;
    Ok(profile)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.profile_lock")
)]
fn profile_lock(path: &Path) -> Result<fs::File> {
    use fs2::FileExt;
    let path = path.with_extension("profile.lock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_file(),
            "profile lock must be a regular file"
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(path)?;
    lock.try_lock_exclusive()
        .context("another setup is using this local profile")?;
    Ok(lock)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.save_profile")
)]
fn save_profile(store: &StateStore, name: &str, profile: &LocalProfile) -> Result<()> {
    profile.validate()?;
    let path = profile_path(store, name)?;
    if path.exists() {
        let old: LocalProfile = foundation::read_json(&path)?;
        ensure!(
            old == *profile,
            "local profile already has different settings; choose a new --profile name"
        );
    }
    foundation::write_json(&path, profile)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.setup")
)]
pub fn setup(command: SetupCommand) -> Result<()> {
    match command {
        SetupCommand::RemoveParticipant(args) => removal::participant(args),
        SetupCommand::RemoveTeam(args) => removal::team(args),
        SetupCommand::Participant(args) => connect_cli::participant(*args),
        SetupCommand::RolePlan {
            from,
            aws_profile,
            trusted_principals,
        } => {
            let team = TeamDefinition::load(&from)?;
            let request = AccessRequest {
                administrator: aws::AwsSelection {
                    profile: aws_profile,
                    account_id: team.aws.account_id.clone(),
                    region: team.aws.region.clone(),
                },
                team,
                trusted_principals,
                existing: None,
            };
            let recovery_notice = if request.team.deployment.is_none() {
                "Offline proposal uses default names. Legacy recovery can select different policy names from its checkpoint before the saved Pulumi preview."
            } else {
                "Offline proposal uses the team's recorded identities. No AWS policy or checkpoint was checked."
            };
            print_json(
                &json!({"pulumiYaml":serde_yaml::to_string(&request.render()?)?,"callerPolicy":request.caller_policy()?,"backend":access::admin_backend(&request.team)?,"cloudChanges":false,
                    "proposalOnly":true,"checkpointChecked":false,"namingSource":if request.team.deployment.is_some(){"teamDefinition"}else{"defaults"},"recoveryNotice":recovery_notice}),
            )
        }
        SetupCommand::Bootstrap {
            store,
            scope,
            aws_profile,
            access,
            managed,
            profile,
            bucket,
            prefix,
            recovered_key,
            export,
            yes,
        } => {
            ensure!(yes, "setup creates a billed S3/KMS backend; pass --yes to create it in the selected account");
            let mut access = *access;
            if !access.trusted_principals.is_empty() {
                access
                    .developer_aws_profile
                    .get_or_insert_with(|| aws_profile.clone());
            }
            let store = open_store(store)?;
            let path = profile_path(&store, &profile)?;
            let _profile_lock = profile_lock(&path)?;
            if let Some(export) = &export {
                match fs::symlink_metadata(export) {
                    Ok(_) => {
                        let old = load_profile(&store, &profile).context(
                            "existing team export requires a matching saved local profile",
                        )?;
                        ensure!(
                            TeamDefinition::load(export)? == old.team,
                            "team export has different settings; choose a new destination"
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let selection = aws::AwsSelection {
                profile: aws_profile.clone(),
                account_id: scope.account_id.clone(),
                region: scope.region.clone(),
            };
            access.validate(&selection)?;
            if access.developer_aws_profile.is_some() {
                ensure!(
                    prefix != "zdn-admin" && !prefix.starts_with("zdn-admin/"),
                    "deployment state overlaps administrator state"
                );
            }
            let managed =
                if access.developer_aws_profile.is_some() && access.existing_role_arn.is_none() {
                    let directory = data_path(managed.managed_dir, "tools")?;
                    zdn::pulumi::ManagedTools::resolve(&directory)?;
                    Some(directory)
                } else {
                    None
                };
            let local_aws_profile = access
                .developer_aws_profile
                .clone()
                .unwrap_or_else(|| aws_profile.clone());
            let request = aws::BootstrapRequest {
                team_id: scope.team_id,
                account_id: scope.account_id,
                region: scope.region,
                bucket,
                prefix,
            };
            if path.exists() {
                let old = load_profile(&store, &profile)?;
                ensure!(old.team.deployment.is_some() == access.developer_aws_profile.is_some(), "existing local profiles cannot change deployment access mode; preserve the profile for its existing networks and use a new team setup");
                ensure!(
                    old.aws_profile == local_aws_profile
                        && old.team.aws.account_id == selection.account_id
                        && old.team.aws.region == selection.region
                        && old.team.team_id == request.team_id
                        && old.team.state.backend
                            == format!("s3://{}/{}", request.bucket, request.prefix),
                    "bootstrap would change an existing local profile"
                );
            }
            let api = AwsCli::new(selection.clone())?;
            if access.developer_aws_profile.is_some() {
                let mut source_selection = selection.clone();
                source_selection.profile = local_aws_profile.clone();
                let source = AwsCli::new(source_selection.clone())?;
                access_bootstrap::verify_source_identity(
                    &source,
                    &source_selection,
                    &access.trusted_principals,
                )?;
            }
            eprintln!(
                "zdn: setup team {} in AWS {}/{} with state s3://{}/{}",
                request.team_id, request.account_id, request.region, request.bucket, request.prefix
            );
            let mut team = aws::bootstrap(
                &api,
                &selection,
                &request,
                &path.with_extension("bootstrap.json"),
                recovered_key.as_deref(),
            )?;
            if access.developer_aws_profile.is_some() {
                let request = AccessRequest {
                    team,
                    administrator: selection,
                    trusted_principals: access.trusted_principals,
                    existing: access.existing_role_arn.map(|role_arn| DeploymentAccess {
                        role_arn,
                        management: RoleManagement::External,
                        runtime_boundary_arn: access
                            .runtime_boundary_arn
                            .expect("clap requires runtime boundary"),
                    }),
                };
                let directory = path.with_extension("access");
                let cancel = cancellation()?;
                let mut stack: Box<dyn access_bootstrap::AccessStack> =
                    if request.existing.is_some() {
                        Box::new(access_bootstrap::NoStack)
                    } else {
                        Box::new(access_bootstrap::live_stack(
                            &request,
                            &directory,
                            managed
                                .as_deref()
                                .context("managed tools are required for IAM setup")?,
                            cancel.clone(),
                        )?)
                    };
                team = access_bootstrap::provision(
                    &api,
                    &request,
                    &directory,
                    stack.as_mut(),
                    access.reconcile,
                )?;
                // Do not publish a local profile until the source can assume
                // the role and read this exact backend using that identity.
                let developer = LocalProfile {
                    team: team.clone(),
                    aws_profile: local_aws_profile.clone(),
                };
                let (api, _) = zdn::credentials::client(
                    &team,
                    developer.selection(),
                    &store.root().join("credentials"),
                )?;
                access_bootstrap::verify_developer_backend(
                    &api,
                    api.selection(),
                    &team,
                    &foundation_live::SystemRuntime::default(),
                    &cancel,
                ).with_context(|| format!(
                    "IAM setup is saved; deployment-role assumption/backend check did not finish. Check the reported error and source-profile sign-in. If a caller-side sts:AssumeRole grant is missing, the required grant is: {}. Repeat the same setup to finish",request.caller_policy().unwrap_or_default()))?;
            }
            save_profile(
                &store,
                &profile,
                &LocalProfile {
                    team: team.clone(),
                    aws_profile: local_aws_profile,
                },
            )?;
            if let Some(path) = export {
                team.save_export(&path)?;
            }
            print_json(&json!({"profile":profile,"team":team,"hostCreated":false}))
        }
        SetupCommand::Import {
            store,
            from,
            aws_profile,
            profile,
        } => {
            let store = open_store(store)?;
            let team = TeamDefinition::load(&from)?;
            let local = LocalProfile { team, aws_profile };
            local.validate()?;
            let path = profile_path(&store, &profile)?;
            let _profile_lock = profile_lock(&path)?;
            if path.exists() {
                ensure!(
                    load_profile(&store, &profile)? == local,
                    "local profile already has different settings"
                );
            }
            let (api, _) = zdn::credentials::client(
                &local.team,
                local.selection(),
                &store.root().join("credentials"),
            )?;
            aws::verify_backend(&api, api.selection(), &local.team)?;
            save_profile(&store, &profile, &local)?;
            print_json(&json!({"profile":profile,"team":local.team,"hostCreated":false}))
        }
    }
}

enum LaunchMode<'a> {
    Node,
    Foundation(Option<&'a Path>),
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.launch")
)]
fn launch(
    args: LaunchArgs,
    mode: LaunchMode<'_>,
) -> Result<(StateStore, zdn::state::Binding, DeploymentFile, Deployment)> {
    let config = Config::load(&args.config.config)?;
    let store = open_store(args.store)?;
    let profile = load_profile(&store, &config.profile)?;
    let (_, context) = binding_context(&BindingArgs {
        config: args.config,
        store: StoreArgs {
            state_dir: Some(store.root().into()),
        },
        scope: BindingScopeArgs {
            team_id: Some(profile.team.team_id.clone()),
            account_id: Some(profile.team.aws.account_id.clone()),
            region: Some(profile.team.aws.region.clone()),
        },
    })?;
    let binding = store.bind(&context, &config.name)?;
    let file = DeploymentFile::open(store.root(), binding.network_id)?;
    let deployment = if file.exists() {
        let saved = file.load()?;
        ensure!(
            saved.team == profile.team && saved.spec.aws_profile == profile.aws_profile,
            "foundation profile differs from its saved settings"
        );
        ensure!(args.ami_id.as_ref().is_none_or(|v| v == &saved.spec.ami_id)
            && args.availability_zone.as_ref().is_none_or(|v| v == &saved.spec.availability_zone)
            && config.node.resources.preset == saved.spec.size,
            "foundation AMI, availability zone, and size are fixed; use a new network binding for different host settings");
        if let LaunchMode::Foundation(helper) = mode {
            saved.require_native_execution()?;
            if let Some(helper) = helper {
                let runtime = saved.foundation_runtime.as_ref().context(
                    "existing legacy requests cannot change foundation runtime selection",
                )?;
                let candidate =
                    zdn::foundation_runtime::FoundationRuntime::stage(helper, file.directory())?;
                ensure!(
                    serde_json::to_value(runtime)? == serde_json::to_value(candidate)?,
                    "foundation helper differs from saved request"
                );
            }
        }
        if let Some(runtime) = &saved.foundation_runtime {
            runtime.verify_local(file.directory())?;
        }
        saved
    } else {
        let spec = FoundationSpec {
            scope: profile.team.scope(),
            network_id: binding.network_id,
            aws_profile: profile.aws_profile,
            ami_id: args
                .ami_id
                .context("first foundation launch requires --ami-id")?,
            availability_zone: args
                .availability_zone
                .context("first foundation launch requires --availability-zone")?,
            size: config.node.resources.preset,
            retain_chain_disk: true,
        };
        let mut deployment = Deployment::new(spec, profile.team)?;
        if let LaunchMode::Foundation(helper) = mode {
            let helper = helper.context("first foundation request requires --host-helper implementing zdn-foundation-health/v1alpha1")?;
            ensure!(
                deployment.team.deployment.is_some(),
                "native foundation requires runtime access setup"
            );
            deployment.foundation_runtime = Some(
                zdn::foundation_runtime::FoundationRuntime::stage(helper, file.directory())?,
            );
        }
        deployment.render()?;
        file.save(&deployment)?;
        deployment
    };
    Ok((store, binding, file, deployment))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.existing_selection")
)]
fn existing_selection(
    args: ExistingArgs,
) -> Result<(StateStore, zdn::state::Binding, LocalProfile)> {
    let store = open_store(args.store)?;
    let profile = load_profile(&store, &args.profile)?;
    let binding = store.resolve(&profile.team.scope(), &args.selector, None)?;
    Ok((store, binding, profile))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.saved_node_launch")
)]
fn saved_node_launch(
    args: ExistingArgs,
    reconcile: bool,
    cancel: &Arc<AtomicBool>,
    output: &mut cli_output::OperationOutput,
) -> Result<(StateStore, zdn::state::Binding, DeploymentFile, Deployment)> {
    use zdn::state::PhaseStatus;
    let (store, binding, profile) = existing_selection(args)?;
    output.network_id = Some(binding.network_id);
    // Validate the snapshot before opening any backend or changing saved inputs.
    DeploymentFile::read_snapshot(store.root(), binding.network_id)?;
    let file = DeploymentFile::open(store.root(), binding.network_id)?;
    let mut deployment = file.load()?;
    ensure!(
        deployment.team == profile.team && deployment.spec.aws_profile == profile.aws_profile,
        "saved deployment profile differs from its saved team or AWS profile settings"
    );
    ensure!(
        !deployment.destroyed,
        "saved deployment was destroyed; use a new network binding"
    );
    ensure!(
        !deployment.runtime.as_ref().is_some_and(|r| r.pending()),
        "an image update is unresolved; resume devnet update before up"
    );
    if deployment.cluster.is_none() {
        let preparation = zdn::build::preparation::Preparation::read(file.directory())
            .context("saved deployment has no node ClusterRequest or complete source preparation; foundation-only requests and old incomplete builds cannot use --saved")?;
        zdn::devnet::select_native_runtime(
            Some(preparation.native_runtime_protocol.as_deref()),
            false,
        )?;
        preparation.verify(file.directory(), &deployment)?;
        ensure!(
            store.handoff_operations(&binding)?.is_empty(),
            "initial source preparation has operation history"
        );
        let build = zdn::build_job::validate_preparation(
            &file.directory().join("build"),
            &deployment.team,
            &preparation.contract,
        )?;
        output.observe_build(&build)?;
        ensure!(!build.submission_recorded || reconcile,
            "saved build was dispatched; establish controller ownership and pass --reconcile (the source controller must be quiescent)");
        let (api, _) = zdn::credentials::client(
            &deployment.team,
            aws::AwsSelection {
                profile: deployment.spec.aws_profile.clone(),
                account_id: deployment.team.aws.account_id.clone(),
                region: deployment.team.aws.region.clone(),
            },
            &file.directory().join("credentials"),
        )?;
        aws::verify_identity(&api, api.selection())?;
        zdn::build_job::run_with_progress(
            &api,
            &deployment.team,
            &preparation.contract,
            &file.directory().join("source-snapshot/source.tar"),
            &file.directory().join("build"),
            &foundation_live::SystemRuntime::default(),
            || {
                ensure!(!cancel.load(Ordering::SeqCst), "build cancelled");
                Ok(())
            },
            &mut |build| output.observe_build(build),
        )?;
        deployment.cluster = Some(preparation.stage(file.directory(), &deployment)?);
        deployment.render()?;
        file.save(&deployment)?;
    }
    deployment.require_native_execution()?;
    let request = deployment
        .cluster
        .as_ref()
        .context("missing saved node request after build verification")?;
    let mut blocking = deployment.unresolved_operation;
    for id in [deployment.last_operation, deployment.unresolved_operation]
        .into_iter()
        .flatten()
    {
        let operation = store.operation(id)?;
        ensure!(
            operation.network_id == binding.network_id && operation.scope == binding.context.scope,
            "saved operation does not belong to the selected deployment"
        );
        if operation.phases.iter().any(|p| {
            matches!(
                p.status,
                PhaseStatus::Running { .. }
                    | PhaseStatus::Unknown { .. }
                    | PhaseStatus::Failed {
                        retry_safe: false,
                        ..
                    }
            )
        }) {
            blocking = Some(id);
        }
    }
    if !reconcile {
        if let Some(id) = blocking {
            if output.format.machine() {
                return Err(foundation::ReconciliationRequired {
                    operation: store.operation(id)?,
                }
                .into());
            }
            eyre::bail!("previous operation has an uncertain outcome; inspect devnet status, then retry with --reconcile");
        }
    }
    request.verify_local(file.directory())?;
    deployment.render()?;
    Ok((store, binding, file, deployment))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.select_existing_profile")
)]
fn select_existing_profile(
    mut deployment: Deployment,
    profile: LocalProfile,
) -> Result<Deployment> {
    ensure!(
        deployment.team == profile.team,
        "saved foundation belongs to different team settings"
    );
    deployment.spec.aws_profile = profile.aws_profile;
    Ok(deployment)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.existing")
)]
fn existing(
    args: ExistingArgs,
) -> Result<(StateStore, zdn::state::Binding, DeploymentFile, Deployment)> {
    let (store, binding, profile) = existing_selection(args)?;
    let file = DeploymentFile::open(store.root(), binding.network_id)?;
    let deployment = select_existing_profile(file.load()?, profile)?;
    Ok((store, binding, file, deployment))
}

fn cancellation() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    let handler = flag.clone();
    ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
    Ok(flag)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.foundation")
)]
pub fn foundation(command: FoundationCommand) -> Result<()> {
    match command {
        FoundationCommand::Render(args) => {
            let (_, _, file, deployment) = launch(
                args.launch,
                LaunchMode::Foundation(args.host_helper.as_deref()),
            )?;
            ensure!(
                deployment.cluster.is_none(),
                "node deployment requires devnet render"
            );
            print_json(
                &json!({"networkId":deployment.spec.network_id,"receiptDirectory":file.directory(),
                "accountId":deployment.spec.scope.account_id,"region":deployment.spec.scope.region,
                "backend":deployment.team.state.backend,"spec":deployment.spec,
                "pulumiYaml":deployment.render()?.to_yaml()?,"createsZakura":false,
                "costItems":["one EC2 host","root and chain EBS volumes","one NAT gateway","one public IPv4 address","S3 state and KMS"]}),
            )
        }
        up @ FoundationCommand::Up { .. } => {
            let mut output =
                cli_output::OperationOutput::new(cli_output::Format::Human, "foundation up");
            print_json(&foundation_up(up, &mut output)?)
        }
        FoundationCommand::Status(args) => {
            let (store, binding, profile) = existing_selection(args)?;
            let deployment = select_existing_profile(
                DeploymentFile::read_snapshot(store.root(), binding.network_id)?,
                profile,
            )?;
            print_json(&status_report(&store, &binding, &deployment)?)
        }
        destroy @ FoundationCommand::Destroy { .. } => {
            let mut output =
                cli_output::OperationOutput::new(cli_output::Format::Human, "foundation destroy");
            print_json(&foundation_destroy(destroy, &mut output)?)
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.foundation_destroy")
)]
pub fn foundation_destroy(
    command: FoundationCommand,
    output: &mut cli_output::OperationOutput,
) -> Result<serde_json::Value> {
    let FoundationCommand::Destroy {
        existing: args,
        managed,
        delete_data,
        reconcile,
        recover_lease_etag,
        yes,
    } = command
    else {
        unreachable!()
    };
    ensure!(yes, "foundation destroy removes the host and network; pass --yes (chain data is retained unless --delete-data is set)");
    let (store, binding, file, mut deployment) = existing(args)?;
    output.network_id = Some(binding.network_id);
    ensure!(
        deployment.cluster.is_none(),
        "node deployment requires devnet destroy"
    );
    if !output.format.machine() {
        describe_target(
            &deployment,
            if delete_data {
                "destroy and delete data"
            } else {
                "destroy and retain data"
            },
        );
    }
    let mut backend = LiveBackend::new(
        &deployment,
        file.directory(),
        &data_path(managed.managed_dir, "tools")?,
        cancellation()?,
        recover_lease_etag,
    )?;
    let operation = foundation::destroy_with_progress(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        delete_data,
        reconcile,
        &mut |receipt, phase| output.observe(receipt, phase),
    )?;
    Ok(
        json!({"destroyed":true,"networkId":binding.network_id,"operationId":operation.operation_id,
        "cleanup":deployment.cleanup,"retainedDataContinuesToCostMoney":!delete_data,
        "sharedBackendPreserved":true}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cloud_cli.foundation_up")
)]
pub fn foundation_up(
    command: FoundationCommand,
    output: &mut cli_output::OperationOutput,
) -> Result<serde_json::Value> {
    let FoundationCommand::Up {
        launch: args,
        managed,
        reconcile,
        recover_lease_etag,
        yes,
    } = command
    else {
        unreachable!()
    };
    ensure!(
        yes,
        "foundation up creates billed AWS resources; inspect foundation render and pass --yes"
    );
    let (store, binding, file, mut deployment) = launch(
        args.launch,
        LaunchMode::Foundation(args.host_helper.as_deref()),
    )?;
    output.network_id = Some(binding.network_id);
    ensure!(
        deployment.cluster.is_none(),
        "node deployment requires devnet up"
    );
    if !output.format.machine() {
        describe_target(&deployment, "apply");
    }
    let mut backend = LiveBackend::new(
        &deployment,
        file.directory(),
        &data_path(managed.managed_dir, "tools")?,
        cancellation()?,
        recover_lease_etag,
    )?;
    let operation = foundation::apply_with_progress(
        &store,
        &file,
        &binding,
        &mut deployment,
        &mut backend,
        reconcile,
        &mut |receipt, phase| output.observe(receipt, phase),
    )?;
    Ok(
        json!({"ready":true,"service":"foundation-health","networkId":binding.network_id,
        "outputs":deployment.outputs,"operationId":operation.operation_id,"createsZakura":false}),
    )
}

fn describe_target(deployment: &Deployment, action: &str) {
    eprintln!(
        "zdn: {action} foundation {} in AWS {}/{}; stack zdn-{}; state {}",
        deployment.spec.network_id,
        deployment.spec.scope.account_id,
        deployment.spec.scope.region,
        deployment.spec.network_id.simple(),
        deployment.team.state.backend
    );
}
