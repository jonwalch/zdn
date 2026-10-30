use clap::{Args, Parser, Subcommand};
use eyre::{bail, ensure, Context, ContextCompat, Result};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
};
use uuid::Uuid;
use zdn::{
    chain::{manifest::ConsensusManifest, ChainRequest, CompatibilityRecord},
    config::{Config, ServicePreset, Size, SnapshotMode, Source},
    dependencies,
    source::{self, CaptureOptions, SnapshotReceipt},
    state::{BindingContext, BindingExport, OperationInput, Scope, StateStore},
};
mod cli_output;
mod cli_reference;
mod cloud_cli;
mod connect_cli;
mod lightwallet_cli;
#[cfg(feature = "profiling")]
mod profiling;
mod release_cli;
mod wallet_cli;

use zdn::build_export::PROTOCOL as BUILD_EXPORT_PROTOCOL;
use zdn::host::CAPACITY_PROTOCOL;

#[derive(Parser)]
#[command(
    version,
    about = "Prepare isolated Zcash devnets and validate their AWS foundation.",
    after_help = "Discovery: zdn reference prints all public long help; zdn reference --schema prints the versioned command schema. Both are offline and side-effect-free. Use zdn help COMMAND SUBCOMMAND or COMMAND SUBCOMMAND --help for one command. Read parent options too. Help is not a dry run or permission to mutate.\n\nExperimental: use disposable test coins and a dedicated development AWS account. Resources cost money; wallet keys/backups contain plaintext secrets. Keep private state outside captured source. See docs/automation.md and docs/wallet.md."
)]
struct Cli {
    /// Output contract. Place before the command; see the automation roadmap for supported commands.
    #[arg(long, value_enum, default_value = "human")]
    format: cli_output::Format,
    /// New private JSONL lifecycle event file, separate from machine stdout. Place before the command.
    #[arg(long)]
    progress_file: Option<PathBuf>,
    /// Never prompt for input, even when attached to a terminal.
    #[arg(long, global = true)]
    noninteractive: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the complete public command reference without reading state or contacting services.
    #[command(
        after_help = "Examples:\n  zdn reference\n  zdn reference --schema\n  zdn --format json reference --schema\n\nThe schema describes arguments, defaults, enums, conflicts and option placement; conditional/runtime rules remain in help text. It is not a complete validator. Internal protocols are excluded. No files are created; redirect stdout yourself if needed."
    )]
    Reference {
        /// Emit zdn-command-reference/v1alpha1 JSON instead of the full text reference.
        #[arg(long)]
        schema: bool,
    },
    /// Explicit-backend keys/scans, trusted-node history export and pool-specific balances.
    Wallet(wallet_cli::WalletArgs),
    /// Connect local applications to a private devnet through AWS Session Manager.
    Connect(connect_cli::ConnectArgs),
    /// Run a noninteractive command with verified private devnet connections.
    Exec(connect_cli::ExecArgs),
    /// Make one read-only RPC request over verified private devnet connections.
    Rpc(connect_cli::RpcArgs),
    /// Submit an already-signed transaction once, preserving uncertain outcomes.
    Submit(connect_cli::SubmitArgs),
    /// Fund a developer wallet; Ironwood by default, explicit --pool transparent unshields funds.
    Fund(wallet_cli::payment::FundArgs),
    /// Send from a named wallet's selected pool, with durable reservations and recovery.
    Send(wallet_cli::payment::SendArgs),
    /// Observe transaction acceptance, canonical inclusion and local reorg history.
    Tx(wallet_cli::payment::TxArgs),
    /// Export private service identities without credentials or local ports.
    Endpoints(connect_cli::EndpointArgs),
    /// Internal process supervisor. Never invoke directly.
    #[command(name = "__supervise-pulumi", hide = true)]
    SupervisePulumi {
        #[arg(long)]
        marker: PathBuf,
        #[arg(long)]
        token: Uuid,
        #[arg(long)]
        grace_ms: u64,
        #[arg(long)]
        timeout_ms: u64,
        #[arg(last = true, required = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Internal host command supervisor with private in-memory stdin transport.
    #[command(name = "__supervise-host-command", hide = true)]
    SuperviseHostCommand {
        #[arg(long)]
        marker: PathBuf,
        #[arg(long)]
        token: Uuid,
        #[arg(long)]
        grace_ms: u64,
        #[arg(long)]
        timeout_ms: u64,
        #[arg(long)]
        input_socket: PathBuf,
        #[arg(last = true, required = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Internal attached lightwallet client; deliberately no timeout option.
    #[command(name = "__supervise-lightwallet-client", hide = true)]
    SuperviseLightwalletClient {
        #[arg(long)]
        marker: PathBuf,
        #[arg(long)]
        token: Uuid,
        #[arg(long)]
        grace_ms: u64,
        #[arg(last = true, required = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Internal session-scoped cleanup helper. Never invoke directly.
    #[command(name = "__kill-pulumi-group", hide = true)]
    KillPulumiGroup {
        #[arg(long)]
        session: i32,
        #[arg(long)]
        group: i32,
    },
    /// Internal AWS credential_process protocol. Writes temporary credentials to stdout.
    #[command(name = "__credentials", hide = true)]
    Credentials {
        #[arg(long)]
        request: PathBuf,
    },
    /// Internal pinned-runtime capability protocol. No cloud or host effects.
    #[command(name = "__runtime-capabilities", hide = true)]
    RuntimeCapabilities {
        /// Fail unless this executable implements the requested protocol.
        #[arg(long)]
        require: Option<String>,
    },
    /// Internal pinned native node control; does not install or migrate a host.
    #[cfg(target_os = "linux")]
    #[command(name = "__host-runtime", hide = true)]
    HostRuntime {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(value_enum)]
        operation: zdn::host::runtime::control::Operation,
    },
    /// Internal pinned native first installer; canonical manifest on stdin.
    #[cfg(target_os = "linux")]
    #[command(name = "__host-install", hide = true)]
    HostInstall {
        #[arg(long)]
        protocol: String,
    },
    /// Internal native-only image update; bounded canonical request on stdin.
    #[cfg(target_os = "linux")]
    #[command(name = "__host-update", hide = true)]
    HostUpdate {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        manifest: PathBuf,
    },
    #[cfg(target_os = "linux")]
    #[command(name = "__lightwallet-install", hide = true)]
    LightwalletInstall {
        #[arg(long)]
        protocol: String,
    },
    #[cfg(target_os = "linux")]
    #[command(name = "__lightwallet-runtime", hide = true)]
    LightwalletRuntime {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(value_enum)]
        operation: zdn::host::runtime::lightwallet::Operation,
    },
    /// Internal native gateway installation, observation and read-only daemon.
    #[cfg(target_os = "linux")]
    #[command(name = "__client-gateway", hide = true)]
    ClientGateway {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(value_enum)]
        operation: zdn::host::runtime::gateway::Operation,
    },
    /// Internal native foundation-only health service.
    #[command(name = "__foundation-serve", hide = true)]
    FoundationServe {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        network_id: Uuid,
        #[arg(long, value_enum)]
        size: Size,
    },
    /// Internal bounded loopback foundation health fetch.
    #[command(name = "__foundation-fetch", hide = true)]
    FoundationFetch {
        #[arg(long)]
        protocol: String,
    },
    /// Internal read-only Linux capacity probe. Does not establish host readiness.
    #[command(name = "__host-capacity", hide = true)]
    HostCapacity {
        #[arg(long)]
        protocol: String,
        /// Filesystem containing proc/ and sys/; defaults to the running host.
        #[arg(long, default_value = "/")]
        root: PathBuf,
        /// Ignore this service's own cgroup, as required for foundation readiness.
        #[arg(long)]
        exclude_current_cgroup: bool,
    },
    /// Internal build-result exporter. Does not build or upload an image.
    #[command(name = "__build-export", hide = true)]
    BuildExport {
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        config_download: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create devnet.yaml without replacing an existing file.
    Init(InitArgs),
    /// Validate configuration syntax and supported settings; makes no cloud calls.
    Check(ConfigArgs),
    /// Print a draft plan, sizing, chain request, and unresolved launch requirements.
    Plan(ConfigArgs),
    /// Prepare chain inputs or bootstrap and inspect an existing local node.
    Chain {
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// Verify pinned node image inputs without running Docker locally.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Resolve and verify a digest-pinned deployment package without executing artifacts.
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Prepare and authenticate exact-release catalogs with explicit trusted keys.
    Release {
        #[command(subcommand)]
        command: release_cli::ReleaseCommand,
    },
    /// Inspect lightwalletd data or render its candidate private service; no cloud changes.
    Lightwallet {
        #[command(subcommand)]
        command: lightwallet_cli::LightwalletCommand,
    },
    /// Render, deploy, inspect and remove private Zakura nodes with scheduled blocks; wallets stay local.
    Devnet {
        #[command(subcommand)]
        command: cloud_cli::DevnetCommand,
    },
    /// Build captured local source (or use a pinned image), then deploy private nodes.
    #[command(after_help = cloud_cli::UP_HELP)]
    Up {
        #[command(flatten)]
        launch: cloud_cli::NodeLaunchArgs,
        #[command(flatten)]
        managed: ManagedArgs,
        /// Inspect saved/live state before retrying an interrupted or uncertain operation; not a first-run flag.
        #[arg(long)]
        reconcile: bool,
        /// Exact expired lease ETag from status; requires --reconcile and a stopped previous controller.
        #[arg(long, requires = "reconcile")]
        recover_lease_etag: Option<String>,
        /// Explicit consent to create billed AWS resources/builds; never implied by --noninteractive.
        #[arg(long)]
        yes: bool,
    },
    /// Capture local Git source in a new directory with source.tar and receipt.json.
    Snapshot {
        #[command(flatten)]
        config: ConfigArgs,
        /// New snapshot directory outside the captured source; existing destinations are never replaced. Contains source.tar and receipt.json.
        #[arg(long)]
        output: PathBuf,
        /// Exact source-relative untracked file to include; repeat for multiple files.
        #[arg(long)]
        include: Vec<PathBuf>,
    },
    /// Check local prerequisites and managed files. Does not sign in to AWS.
    Doctor(ManagedArgs),
    /// Inspect or install the checksum-pinned Pulumi tool set.
    Deps {
        #[command(subcommand)]
        command: DepsCommand,
    },
    /// Manage local network bindings; these do not reserve a cloud ID.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Prepare and inspect durable operation records; no phases are executed.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    /// Bootstrap or import an organization-owned AWS state backend.
    Setup {
        #[command(subcommand)]
        command: cloud_cli::SetupCommand,
    },
    /// Render, launch, inspect, and remove one private AWS test host.
    Foundation {
        #[command(subcommand)]
        command: cloud_cli::FoundationCommand,
    },
    #[command(external_subcommand)]
    Unavailable(Vec<String>),
}

#[derive(Args, Clone)]
struct ConfigArgs {
    /// Devnet YAML configuration; defaults to devnet.yaml in the current directory. Keep its profile/inputs stable for recovery.
    #[arg(long, default_value = "devnet.yaml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Verify pinned OCI bytes or trusted local Docker metadata, without running Docker or establishing live readiness.
    #[command(
        after_help = "Supply at least one of --config or --inspect (both are allowed). --manifest is raw OCI JSON, not a consensus manifest. Example: zdn image verify --record image.json --manifest image-manifest.json --config image-config.json. A verified digest proves byte identity, not publisher trust or payment qualification. See docs/image-contract.md."
    )]
    Verify {
        /// Saved image provenance/capability record JSON with pinned digests.
        #[arg(long)]
        record: PathBuf,
        /// Exact raw OCI image manifest bytes matching the record.
        #[arg(long)]
        manifest: PathBuf,
        /// Exact raw OCI configuration bytes; required unless --inspect is supplied.
        #[arg(long, required_unless_present = "inspect")]
        config: Option<PathBuf>,
        /// Saved trusted host's Docker inspection JSON; required unless --config is supplied. Does not execute Docker.
        #[arg(long, required_unless_present = "config")]
        inspect: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Resolve a package and check byte identities/declarations, not publisher trust or live qualification.
    Verify {
        /// Local package manifest JSON; its HTTPS artifact sources may download pinned files.
        #[arg(long)]
        manifest: PathBuf,
        /// Independently trusted SHA256 of the exact package manifest bytes.
        #[arg(long)]
        sha256: String,
    },
    /// Copy a verified package into a new self-contained data-only local directory (Linux/macOS).
    Export {
        /// Local package manifest JSON; its HTTPS artifact sources may download pinned files.
        #[arg(long)]
        manifest: PathBuf,
        /// Independently trusted SHA256 of the package manifest, not a hash invented from untrusted bytes.
        #[arg(long)]
        sha256: String,
        /// New destination directory; existing paths are never replaced. Artifacts are not executed.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChainCommand {
    /// Wait for authenticated RPC and matching effective rules, reloading a rotating cookie.
    WaitRpc {
        /// Reviewed consensus manifest JSON defining expected chain/rules.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        rpc: NodeRpcArgs,
    },
    /// Load a verified saved chain into an existing node with its producer stopped.
    #[command(
        after_help = "This writes chain state through authenticated local RPC. Keep ALL producers stopped throughout. Example: zdn chain bootstrap --manifest chain.json --bundle chain.tar --cookie-file /private/node/.cookie --producer-stopped. Do not infer consensus/payment qualification from a successful import. See docs/bootstrap-readiness.md."
    )]
    Bootstrap {
        /// Reviewed consensus manifest JSON against which the saved chain is checked.
        #[arg(long)]
        manifest: PathBuf,
        /// Saved chain bundle with matching raw blocks/checkpoints; never a wallet backup.
        #[arg(long)]
        bundle: PathBuf,
        #[command(flatten)]
        rpc: NodeRpcArgs,
        /// Attest that every producer remains stopped throughout this operation.
        #[arg(long, required = true)]
        producer_stopped: bool,
    },
    /// Check effective rules and actual stored history; producer checks also request a template.
    Readiness {
        /// Reviewed consensus manifest JSON defining expected rules/history.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        rpc: NodeRpcArgs,
        /// Follower checks history; producer also checks block-template readiness. Neither qualifies payments.
        #[arg(long, value_enum, default_value = "follower")]
        role: zdn::chain::runtime_config::NodeRole,
    },
    /// Run the designated persistent block producer; unresolved calls are never retried.
    Produce {
        /// Reviewed consensus manifest JSON; must match the running node.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        rpc: NodeRpcArgs,
        /// Private durable directory on the node's chain-data disk.
        #[arg(long)]
        state_dir: PathBuf,
        /// Full UUID of this deployment; must match the journal and runtime identity.
        #[arg(long)]
        deployment_id: Uuid,
        /// Stable node identity, e.g. node-1; must match the durable journal.
        #[arg(long)]
        node_id: String,
        /// Scheduled block interval in seconds; normal service uses 25, not a performance budget.
        #[arg(long, default_value_t = 25)]
        interval_secs: u64,
        /// Deadline in seconds for observing a previously uncertain generation result; never blindly retries it.
        #[arg(long, default_value_t = 30)]
        reconciliation_deadline_secs: u64,
        /// Optional finite qualification run; normal host services omit this.
        #[arg(long)]
        max_blocks: Option<u64>,
        /// Skip scheduled waits, retaining per-block validation and journaling.
        #[arg(long, requires = "max_blocks")]
        unpaced: bool,
    },
    /// Inspect the durable producer journal and local lock without contacting a node.
    ProducerStatus {
        /// Expected consensus manifest JSON used to bind the journal identity.
        #[arg(long)]
        manifest: PathBuf,
        /// Existing private producer journal directory; not the controller's --state-dir.
        #[arg(long)]
        state_dir: PathBuf,
        /// Full deployment UUID associated with this journal.
        #[arg(long)]
        deployment_id: Uuid,
        /// Exact saved node identity, e.g. node-1.
        #[arg(long)]
        node_id: String,
    },
    /// Validate a candidate JSON manifest and print its normalized rules and fingerprint.
    Inspect {
        /// Candidate consensus manifest JSON; structural validation is not launch qualification.
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Check declared raw genesis/seed byte identities and save a new bundle.
    Import {
        /// Reviewed consensus manifest with expected block hashes/checkpoints.
        #[arg(long)]
        manifest: PathBuf,
        /// Directory with raw block files named by ten-digit height, such as 0000000000.bin.
        #[arg(long)]
        blocks_dir: PathBuf,
        /// New bundle file; an existing file is never replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Recheck saved bundle bytes against the expected consensus manifest.
    Verify {
        /// Expected consensus manifest JSON.
        #[arg(long)]
        manifest: PathBuf,
        /// Saved chain bundle to verify; no node is started or contacted.
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Render a candidate Zakura network TOML fragment; does not validate it with a node.
    RenderConfig {
        /// Reviewed consensus manifest JSON defining the network fragment.
        #[arg(long)]
        manifest: PathBuf,
        /// Optional ASCII network label; otherwise derived from the consensus fingerprint.
        #[arg(long)]
        network_name: Option<String>,
        /// Numeric unicast IP address with an explicit, nonzero port.
        #[arg(long, default_value = "127.0.0.1:18233")]
        listen_addr: String,
        /// Explicit numeric peer endpoint; repeat for multiple peers. No default peers.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Also save TOML to a new file. The parent must exist; no file is replaced.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Render candidate per-node runtime TOML and startup arguments; starts no process.
    RenderRuntime {
        /// Reviewed consensus manifest JSON; renderer output is not live-node qualification.
        #[arg(long)]
        manifest: PathBuf,
        /// Full deployment UUID from the network binding.
        #[arg(long)]
        deployment_id: Uuid,
        /// Stable lowercase node identifier, such as node-0.
        #[arg(long)]
        node_id: String,
        /// Absolute Linux path inside the future node container.
        #[arg(long, default_value = "/var/lib/zdn")]
        data_root: String,
        /// Numeric unicast P2P endpoint with a nonzero port.
        #[arg(long, default_value = "127.0.0.1:18233")]
        listen_addr: String,
        /// Explicit numeric P2P peer endpoint; repeat for multiple peers.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Numeric loopback endpoint for cookie-authenticated node RPC.
        #[arg(long, default_value = "127.0.0.1:18232")]
        rpc_listen_addr: String,
        /// Producer config requires a reward address; scheduling is a later step.
        #[arg(long, value_enum, default_value = "follower")]
        role: zdn::chain::runtime_config::NodeRole,
        /// Explicit Testnet P2PKH or P2SH reward address for a producer.
        #[arg(long)]
        reward_address: Option<String>,
        /// Also save TOML to a new local file; this does not install or start it.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Args)]
struct NodeRpcArgs {
    /// Numeric loopback IP:port, either local node RPC or an existing private tunnel.
    #[arg(long, default_value = "127.0.0.1:18232")]
    rpc_endpoint: String,
    /// Private file containing the running node's RPC cookie. Never a command-line secret.
    #[arg(long)]
    cookie_file: PathBuf,
    /// Per-request RPC timeout in seconds, distinct from the overall command deadline.
    #[arg(long, default_value_t = 10)]
    request_timeout_secs: u64,
    /// Overall observation/bootstrap deadline in seconds; expiration does not prove remote rollback.
    #[arg(long, default_value_t = 120)]
    deadline_secs: u64,
}

#[derive(Args)]
#[command(
    after_help = "Choose exactly one source mode in noninteractive use: --source CHECKOUT, --release EXACT_ID or --image REGISTRY/REPO@sha256:DIGEST. These conflict; --revision requires --source and captures a committed revision instead of working files. Example: zdn init --source /path/to/reviewed-node --nodes 1 --name demo. This writes configuration only, not a running network. services node-only is sufficient for CLI wallet payments; no wallet backend is downloaded. See docs/source-capture.md and docs/wallet.md."
)]
struct InitArgs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Human-readable network label; not a reserved cloud identity.
    #[arg(long, default_value = "my-feature")]
    name: String,
    /// Saved local ZDN profile alias to use for this config; not the administrator AWS CLI profile.
    #[arg(long, default_value = "devnet")]
    profile: String,
    /// Node adapter; only zakura is supported.
    #[arg(long, default_value = "zakura")]
    adapter: String,
    /// Local checkout; includes tracked working files without a commit or push.
    #[arg(long, conflicts_with_all = ["release", "image"])]
    source: Option<PathBuf>,
    /// Exact candidate release identifier. No release has been qualified yet.
    #[arg(long, conflicts_with_all = ["source", "image", "revision"])]
    release: Option<String>,
    /// Candidate image with an immutable @sha256: digest.
    #[arg(long, conflicts_with_all = ["source", "release", "revision"])]
    image: Option<String>,
    /// Capture this commit instead of working files; requires --source.
    #[arg(long, requires = "source")]
    revision: Option<String>,
    /// Dockerfile relative to the captured Git root; requires --source. Default: docker/Dockerfile.
    #[arg(long, requires = "source", conflicts_with_all = ["release", "image"])]
    dockerfile: Option<PathBuf>,
    /// Build context relative to the captured Git root; requires --source. Default: . (the root).
    #[arg(long, requires = "source", conflicts_with_all = ["release", "image"])]
    build_context: Option<PathBuf>,
    /// Resource sizing preset; an experimental configuration, not a production budget recommendation.
    #[arg(long, value_enum, default_value = "medium")]
    size: Size,
    /// Number of private nodes (1..=3); use --nodes 1 for a smaller first network.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(1..=3))]
    nodes: u16,
    /// Optional services: node-only disables all; lightwallet enables lightwalletd;
    /// planned requests wallet, lightwallet, and faucet, including unsupported services.
    #[arg(long, value_enum, default_value = "node-only")]
    service_preset: ServicePreset,
}

#[derive(Args)]
struct ManagedArgs {
    /// Default: $XDG_DATA_HOME/zdn/tools or $HOME/.local/share/zdn/tools.
    #[arg(long)]
    managed_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum DepsCommand {
    /// Print pinned versions, URLs, hashes, and supported host platforms.
    List,
    /// Download, verify, and atomically install pinned tools. Uses the network.
    Install(ManagedArgs),
}

#[derive(Args, Clone)]
struct StoreArgs {
    /// Default: $XDG_DATA_HOME/zdn/state or $HOME/.local/share/zdn/state.
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[derive(Args)]
struct ScopeArgs {
    /// Organization-owned team namespace used with account/region for local identity scoping.
    #[arg(long)]
    team_id: String,
    /// Explicit 12-digit account ID; offline commands do not verify AWS access.
    #[arg(long)]
    account_id: String,
    /// AWS region for this team; offline identity commands do not verify access.
    #[arg(long)]
    region: String,
}
impl ScopeArgs {
    fn scope(&self) -> Scope {
        Scope {
            team_id: self.team_id.clone(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
        }
    }
}

#[derive(Args)]
struct BindingArgs {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(flatten)]
    store: StoreArgs,
    #[command(flatten)]
    scope: BindingScopeArgs,
}

#[derive(Args)]
struct BindingScopeArgs {
    /// Omit all scope flags to use the configuration's saved local profile.
    #[arg(long, requires_all = ["account_id", "region"])]
    team_id: Option<String>,
    /// Explicit 12-digit account ID; requires --team-id and --region, must match any saved profile.
    #[arg(long, requires_all = ["team_id", "region"])]
    account_id: Option<String>,
    /// Explicit AWS region; requires --team-id and --account-id. Omit all three to use config.profile.
    #[arg(long, requires_all = ["team_id", "account_id"])]
    region: Option<String>,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create a binding or reuse its full ID; a name edit updates only its label.
    #[command(
        after_help = "Before launch: zdn identity bind --manifest chain.json. This registers reviewed consensus bytes and prints the network UUID without allocating cloud resources. Use that UUID for predeployment wallet creation, then keep the same config/profile/state for up. Omit all scope flags to use config.profile, or supply all three consistently. Example: zdn wallet create NETWORK_UUID --name funding. See docs/wallet.md."
    )]
    Bind {
        #[command(flatten)]
        binding: BindingArgs,
        /// Save the reviewed wallet manifest for this network before deployment.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Print a portable attachment record for the current binding.
    Export(BindingArgs),
    /// Attach an exported binding with an explicit expected full ID and scope.
    Attach {
        #[command(flatten)]
        binding: BindingArgs,
        /// Reviewed binding export JSON; contains identity, not AWS credentials or cloud reservation.
        #[arg(long)]
        from: PathBuf,
        /// Independently expected full network UUID, checked against the export and explicit scope/context.
        #[arg(long)]
        network_id: Uuid,
    },
    /// List locally known bindings in one team, account, and region.
    List {
        #[command(flatten)]
        store: StoreArgs,
        #[command(flatten)]
        scope: ScopeArgs,
    },
    /// Resolve a full ID, unique prefix, or label. Ambiguous labels fail.
    Resolve {
        /// Full network UUID, unique prefix or unambiguous local label in the explicit scope.
        selector: String,
        #[command(flatten)]
        store: StoreArgs,
        #[command(flatten)]
        scope: ScopeArgs,
    },
}

#[derive(Args)]
struct ReceiptInputs {
    #[command(flatten)]
    config: ConfigArgs,
    /// Saved snapshot directory, required for a local-source operation.
    #[arg(long)]
    snapshot: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ReceiptCommand {
    /// Save pending deployment phases for an existing local binding. Does not deploy.
    Create {
        #[command(flatten)]
        binding: BindingArgs,
        /// Previously captured snapshot directory; required for a local-source operation. No cloud phases run.
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
    /// Inspect one saved local operation record; does not poll or resume external work.
    Inspect {
        /// Exact saved operation UUID (not a network UUID or image-update UUID).
        operation_id: Uuid,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Verify saved inputs and print decisions. Does not resume external effects.
    ResumePlan {
        /// Exact saved operation UUID whose original inputs will be checked.
        operation_id: Uuid,
        #[command(flatten)]
        store: StoreArgs,
        #[command(flatten)]
        inputs: ReceiptInputs,
    },
    /// Record cancellation intent. Does not cancel any external job.
    Cancel {
        /// Exact saved operation UUID. Intent is durable, not evidence that a remote effect stopped.
        operation_id: Uuid,
        #[command(flatten)]
        store: StoreArgs,
    },
}

fn main() -> ExitCode {
    #[cfg(feature = "profiling")]
    if let Err(error) = profiling::init() {
        eprintln!("zdn: could not initialize profiling: {error:#}");
        return ExitCode::FAILURE;
    }
    run_main()
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.main")
)]
fn run_main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let requested_format = cli_output::requested_format(&arguments);
    let cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error) => {
            if !requested_format.machine() {
                error.exit();
            }
            let record = match error.kind() {
                clap::error::ErrorKind::DisplayHelp => cli_output::event(
                    None,
                    "help",
                    "succeeded",
                    json!({"text": error.to_string()}),
                ),
                clap::error::ErrorKind::DisplayVersion => cli_output::event(
                    None,
                    "version",
                    "succeeded",
                    json!({"text": error.to_string()}),
                ),
                _ => cli_output::failure(
                    None,
                    "invalid-arguments",
                    "Invalid command arguments; consult command help.",
                ),
            };
            return machine_record(requested_format, &record, error.exit_code() as u8);
        }
    };
    if cli.format.machine() {
        return run_machine(cli);
    }
    if cli.progress_file.is_some() {
        eprintln!(
            "zdn: --progress-file requires a machine format and a supported lifecycle command"
        );
        return ExitCode::FAILURE;
    }
    if let Commands::Exec(args) = cli.command {
        return connect_cli::exec(args);
    }
    if let Commands::Submit(args) = cli.command {
        return connect_cli::submit(args, cli_output::Format::Human);
    }
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zdn: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.machine_record")
)]
fn machine_record(format: cli_output::Format, record: &serde_json::Value, code: u8) -> ExitCode {
    match cli_output::write(format, record) {
        Ok(()) => ExitCode::from(code),
        Err(_) => {
            eprintln!("zdn: could not write machine output");
            ExitCode::FAILURE
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.run_machine")
)]
fn run_machine(cli: Cli) -> ExitCode {
    let command = match &cli.command {
        Commands::Reference { .. } => "reference",
        Commands::Init(_) => "init",
        Commands::Check(_) => "check",
        Commands::Plan(_) => "plan",
        Commands::Receipt { command: ReceiptCommand::Inspect { .. } } => "receipt inspect",
        Commands::Receipt { command: ReceiptCommand::ResumePlan { .. } } => "receipt resume-plan",
        Commands::Foundation { command: cloud_cli::FoundationCommand::Up { .. } } => "foundation up",
        Commands::Foundation { command: cloud_cli::FoundationCommand::Destroy { .. } } => "foundation destroy",
        Commands::Devnet { command: cloud_cli::DevnetCommand::Destroy { .. } } => "devnet destroy",
        Commands::Devnet { command: cloud_cli::DevnetCommand::Up { .. } } => "devnet up",
        Commands::Devnet { command: cloud_cli::DevnetCommand::Update(_) } => "devnet update",
        Commands::Devnet { command: cloud_cli::DevnetCommand::List { .. } } => "devnet list",
        Commands::Devnet { command: cloud_cli::DevnetCommand::Status(_) } => "devnet status",
        Commands::Devnet { command: cloud_cli::DevnetCommand::Health { .. } } => "devnet health",
        Commands::Doctor(_) => "doctor",
        Commands::Package { command: PackageCommand::Verify { .. } } => "package verify",
        Commands::Package { command: PackageCommand::Export { .. } } => "package export",
        Commands::Release { command: release_cli::ReleaseCommand::Verify(_) } => "release verify",
        Commands::Release { command: release_cli::ReleaseCommand::Resolve { .. } } => "release resolve",
        Commands::Release { command: release_cli::ReleaseCommand::Sign { .. } } => "release sign",
        Commands::Up { .. } => "up",
        Commands::Rpc(_) => "rpc",
        Commands::Submit(_) => "submit",
        _ => return machine_record(cli.format, &cli_output::failure(
            None, "unsupported-format-command", "Machine format supports init, check, plan, receipt inspect, receipt resume-plan, foundation up, foundation destroy, devnet destroy, devnet up/up, devnet update, devnet list, devnet status, devnet health, doctor, package verify/export, release verify/resolve/sign, rpc and submit. No command was executed.",
        ), 1),
    };
    let lifecycle = matches!(
        command,
        "foundation up"
            | "foundation destroy"
            | "devnet destroy"
            | "devnet up"
            | "devnet update"
            | "up"
    );
    let mut operation_output = cli_output::OperationOutput::new(cli.format, command);
    if let Some(path) = &cli.progress_file {
        if !lifecycle {
            return machine_record(
                cli.format,
                &cli_output::failure(
                    Some(command),
                    "unsupported-progress-command",
                    "Progress files support lifecycle commands only. No command was executed.",
                ),
                1,
            );
        }
        if operation_output.set_progress_file(path).is_err() {
            return machine_record(
                cli.format,
                &cli_output::failure(
                    Some(command),
                    "progress-file-failed",
                    "Could not create a new private progress file. No command was executed.",
                ),
                1,
            );
        }
    }
    if cli.format == cli_output::Format::Jsonl || cli.progress_file.is_some() {
        let started = cli_output::event(
            Some(command),
            "command-started",
            "running",
            serde_json::Value::Null,
        );
        if operation_output.progress(&started).is_err() {
            return machine_record(
                cli.format,
                &cli_output::failure(
                    Some(command),
                    "progress-write-failed",
                    "Could not write command progress. No command was executed.",
                ),
                1,
            );
        }
    }
    // Machine streams never prompt. Output format does not authorize cloud work.
    let result = match cli.command {
        Commands::Reference { schema } => Ok(cli_reference::data(schema)),
        Commands::Rpc(args) => return connect_cli::machine_rpc(args, cli.format),
        Commands::Submit(args) => return connect_cli::submit(args, cli.format),
        Commands::Init(args) => init(args, true),
        Commands::Check(args) => check(args),
        Commands::Plan(args) => plan(args),
        Commands::Receipt { command } => machine_receipt(command),
        Commands::Doctor(args) => data_path(args.managed_dir, "tools").and_then(|root| {
            let mut report = dependencies::doctor(&dependencies::SystemProcessRunner, Some(&root));
            // Neither version strings nor local diagnostics belong in machine output.
            for check in &mut report.checks {
                check.detail = if check.ok {
                    "verified"
                } else {
                    "unavailable-or-invalid"
                }
                .into();
            }
            Ok(serde_json::to_value(report)?)
        }),
        Commands::Package {
            command: PackageCommand::Verify { manifest, sha256 },
        } => verify_package(&manifest, &sha256),
        Commands::Package {
            command:
                PackageCommand::Export {
                    manifest,
                    sha256,
                    output,
                },
        } => export_package(&manifest, &sha256, &output),
        Commands::Release { command } => release_cli::run(command),
        Commands::Foundation {
            command: command @ cloud_cli::FoundationCommand::Up { .. },
        } => cloud_cli::foundation_up(command, &mut operation_output),
        Commands::Foundation { command } => {
            cloud_cli::foundation_destroy(command, &mut operation_output)
        }
        Commands::Devnet {
            command: command @ cloud_cli::DevnetCommand::Up { .. },
        } => cloud_cli::devnet_up(command, &mut operation_output),
        Commands::Devnet {
            command: cloud_cli::DevnetCommand::Update(args),
        } => cloud_cli::devnet_update(args, &mut operation_output),
        Commands::Devnet {
            command:
                command @ (cloud_cli::DevnetCommand::List { .. }
                | cloud_cli::DevnetCommand::Status(_)
                | cloud_cli::DevnetCommand::Health { .. }),
        } => cloud_cli::devnet_discovery(command),
        Commands::Devnet { command } => cloud_cli::devnet_destroy(command, &mut operation_output),
        Commands::Up {
            launch,
            managed,
            reconcile,
            recover_lease_etag,
            yes,
        } => cloud_cli::devnet_up(
            cloud_cli::DevnetCommand::Up {
                launch,
                managed,
                reconcile,
                recover_lease_etag,
                yes,
            },
            &mut operation_output,
        ),
        _ => unreachable!(),
    };
    let (record, code) = match result {
        Ok(data) => {
            // An observation can complete successfully without establishing readiness.
            // Keep its report even when the command must exit unsuccessfully.
            let incomplete =
                matches!(command, "doctor" | "devnet health") && data["ready"] == false;
            let mut record = if incomplete {
                let (code, message) = if command == "doctor" {
                    (
                        "prerequisites-incomplete",
                        "Local prerequisites are incomplete; inspect the checks in the report.",
                    )
                } else {
                    (
                        "health-not-ready",
                        "Fresh live readiness was not established; inspect the health report.",
                    )
                };
                let mut record = cli_output::failure(Some(command), code, message);
                record["data"] = data;
                record
            } else {
                cli_output::event(Some(command), "result", "succeeded", data)
            };
            if matches!(command, "devnet status" | "devnet health") {
                record["networkId"] = record["data"]["networkId"].clone();
            }
            if command.starts_with("receipt ") {
                record["networkId"] = record["data"]["networkId"].clone();
                record["operationId"] = record["data"]["operationId"].clone();
                if cli.format == cli_output::Format::Jsonl {
                    for phase in record["data"]["phases"].as_array().unwrap() {
                        let mut observed = cli_output::event(
                            Some(command),
                            "saved-phase",
                            "observed",
                            phase.clone(),
                        );
                        observed["networkId"] = record["networkId"].clone();
                        observed["operationId"] = record["operationId"].clone();
                        if cli_output::write(cli.format, &observed).is_err() {
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            (record, u8::from(incomplete))
        }
        Err(error) => {
            // Do not expose user input, config contents, paths or subprocess output.
            // Stable command-level errors deliberately make no automatic retry promise.
            let (code, message) = match command {
                "init" => ("initialization-failed", "Configuration creation failed; check explicit source inputs and the new output path."),
                "check" => ("configuration-check-failed", "Configuration could not be read or did not pass validation."),
                "receipt inspect" | "receipt resume-plan" => ("receipt-report-failed", "Saved receipt could not be read or the supplied inputs did not match. No operation was executed."),
                "foundation up" => ("foundation-up-failed", "Foundation apply failed; inspect saved state and reconcile uncertain effects before retrying."),
                "foundation destroy" => ("foundation-destroy-failed", "Foundation teardown failed; inspect saved state and reconcile uncertain effects before retrying."),
                "devnet destroy" => ("devnet-destroy-failed", "Devnet teardown failed; inspect saved state and reconcile uncertain effects before retrying."),
                "devnet up" | "up" => ("devnet-up-failed", "Devnet apply failed; inspect saved state and build receipts and reconcile uncertain effects before retrying."),
                "devnet update" => ("devnet-update-failed", "Image update failed; inspect saved update and operation receipts and reconcile uncertain effects before resuming."),
                "devnet list" => ("devnet-list-failed", "Local deployment discovery failed; check the selected profile and local state."),
                "devnet status" => ("devnet-status-failed", "Deployment inventory could not be inspected. Live readiness was not checked."),
                "devnet health" => ("devnet-health-failed", "Health checks could not be completed; check saved deployment proofs and access."),
                "doctor" => ("doctor-failed", "Local prerequisites could not be inspected."),
                "package verify" => ("package-verification-failed", "Package byte integrity or compatibility declarations could not be verified. No artifacts were executed."),
                "package export" => ("package-export-failed", "Package could not be verified or exported. Inspect the output path before retrying; existing paths are never replaced."),
                "release verify" => ("release-verification-failed", "Catalog declarations could not be authenticated with the explicitly trusted keys."),
                "release resolve" => ("release-resolution-failed", "Exact release could not be authenticated, resolved or exported. Inspect the output path before retrying."),
                "release sign" => ("release-signing-failed", "Catalog could not be signed or the new signature published. Inspect the output path before retrying."),
                _ => ("plan-failed", "Configuration could not be read or a valid plan could not be constructed."),
            };
            let mut record = cli_output::failure(Some(command), code, message);
            if let Some(blocked) = error.downcast_ref::<zdn::foundation::ReconciliationRequired>() {
                let report = match cli_output::receipt(&blocked.operation, None) {
                    Ok(report) => report,
                    Err(_) => return ExitCode::FAILURE,
                };
                record["error"]["retryClassification"] = json!("reconcile-required");
                record["data"] = json!({"blockingReceipt": report});
            }
            if let Some(mismatch) =
                error.downcast_ref::<zdn::immutable_inputs::ImmutableInputError>()
            {
                if record["data"].is_null() {
                    record["data"] = json!({});
                }
                record["data"]["immutableInputs"] = json!(&mismatch.report);
            }
            (record, 1)
        }
    };
    let record = if lifecycle {
        match operation_output.finish(record) {
            Ok(record) => record,
            Err(_) => return ExitCode::FAILURE,
        }
    } else {
        record
    };
    if operation_output.write_file(&record).is_err() {
        let mut failure = cli_output::failure(Some(command), "progress-write-failed", "Could not write terminal progress. Inspect saved state before retrying; execution was not replayed.");
        failure["data"] = record["data"].clone();
        if !record["error"].is_null() {
            failure["error"]["retryClassification"] =
                record["error"]["retryClassification"].clone();
        }
        return match operation_output.finish(failure) {
            Ok(failure) => machine_record(cli.format, &failure, 1),
            Err(_) => ExitCode::FAILURE,
        };
    }
    machine_record(cli.format, &record, code)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.machine_receipt")
)]
fn machine_receipt(command: ReceiptCommand) -> Result<serde_json::Value> {
    let (id, store, inputs) = match command {
        ReceiptCommand::Inspect {
            operation_id,
            store,
        } => (operation_id, store, None),
        ReceiptCommand::ResumePlan {
            operation_id,
            store,
            inputs,
        } => (operation_id, store, Some(inputs)),
        _ => unreachable!(),
    };
    let root = data_path(store.state_dir, "state")?;
    // Observation must not initialize a missing state store.
    ensure!(
        root.is_dir() && root.join("state.json").is_file(),
        "saved local state is missing"
    );
    let store = StateStore::open(root)?;
    let receipt = store.operation(id)?;
    let inspect = vec![
        "zdn".to_owned(),
        "--format".into(),
        "json".into(),
        "receipt".into(),
        "inspect".into(),
        id.to_string(),
        "--state-dir".into(),
        store
            .root()
            .to_str()
            .context("state path must be UTF-8")?
            .to_owned(),
    ];
    let mut recovery =
        vec![json!({"argv": inspect, "mutates": false, "requiresAuthorization": false})];
    let expected_inputs = if let Some(inputs) = inputs {
        let config = Config::load(&inputs.config.config)?;
        let expected = operation_inputs(
            &config,
            &inputs.config.config,
            inputs.snapshot.as_deref(),
            false,
        )?;
        let mut argv = vec![
            "zdn".to_owned(),
            "--format".into(),
            "json".into(),
            "receipt".into(),
            "resume-plan".into(),
            id.to_string(),
            "--state-dir".into(),
            store
                .root()
                .to_str()
                .context("state path must be UTF-8")?
                .to_owned(),
            "--config".into(),
            fs::canonicalize(&inputs.config.config)?
                .to_str()
                .context("config path must be UTF-8")?
                .to_owned(),
        ];
        if let Some(snapshot) = inputs.snapshot {
            argv.push("--snapshot".into());
            argv.push(
                fs::canonicalize(snapshot)?
                    .to_str()
                    .context("snapshot path must be UTF-8")?
                    .to_owned(),
            );
        }
        recovery.push(json!({"argv": argv, "mutates": false, "requiresAuthorization": false}));
        Some(expected)
    } else {
        None
    };
    let mut report = cli_output::receipt(&receipt, expected_inputs.as_ref())?;
    report["recovery"] = json!(recovery);
    Ok(report)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.verify_package")
)]
fn verify_package(manifest: &Path, sha256: &str) -> Result<serde_json::Value> {
    let resolved = zdn::package::resolve(manifest, sha256, &Default::default())?;
    Ok(json!({"apiVersion":"zdn-package-verification/v1alpha1",
        "packageSha256":sha256,"artifactSetSha256":resolved.artifact_set.fingerprint()?,
        "artifactSet":resolved.artifact_set,"byteIntegrityVerified":true,
        "compatibilityDeclarationsMatched":true,"artifactExecutionVerified":false,
        "publisherAuthenticated":false,"qualification":"pending","launchReady":false}))
}

fn export_package(manifest: &Path, sha256: &str, output: &Path) -> Result<serde_json::Value> {
    let resolved = zdn::package::resolve(manifest, sha256, &Default::default())?;
    release_cli::export(&resolved, output)
}

#[cfg_attr(feature = "profiling", tracing::instrument(skip_all, name = "cli.run"))]
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Reference { schema } => {
            let data = cli_reference::data(schema);
            if schema {
                print_json(&data)
            } else {
                io::stdout()
                    .lock()
                    .write_all(data["text"].as_str().unwrap().as_bytes())?;
                Ok(())
            }
        }
        Commands::SupervisePulumi {
            marker,
            token,
            grace_ms,
            timeout_ms,
            args,
        } => zdn::pulumi_process::supervise(
            &marker,
            token,
            Duration::from_millis(grace_ms),
            Duration::from_millis(timeout_ms),
            &args,
        ),
        Commands::SuperviseHostCommand {
            marker,
            token,
            grace_ms,
            timeout_ms,
            input_socket,
            args,
        } => zdn::pulumi_process::supervise_host(
            &marker,
            token,
            Duration::from_millis(grace_ms),
            Duration::from_millis(timeout_ms),
            &args,
            &input_socket,
        ),
        Commands::SuperviseLightwalletClient {
            marker,
            token,
            grace_ms,
            args,
        } => zdn::pulumi_process::supervise_lightwallet_client(
            &marker,
            token,
            Duration::from_millis(grace_ms),
            &args,
        ),
        Commands::KillPulumiGroup { session, group } => {
            zdn::pulumi_process::kill_session_group(session, group)
        }
        Commands::Credentials { request } => {
            // Never add verbose/debug output to this protocol.
            let credentials = zdn::credentials::run_process(&request)
                .map_err(|_| eyre::eyre!("deployment credentials unavailable; check source profile login and sts:AssumeRole permission"))?;
            print_json(&credentials)
        }
        Commands::RuntimeCapabilities { require } => {
            let mut capabilities = vec![BUILD_EXPORT_PROTOCOL];
            if cfg!(target_os = "linux") {
                capabilities.push(CAPACITY_PROTOCOL);
                capabilities.push(zdn::foundation_host::PROTOCOL);
                if cfg!(target_arch = "x86_64") {
                    capabilities.push(zdn::host::runtime::PROTOCOL);
                    capabilities.push(zdn::host::runtime::INSTALL_PROTOCOL);
                    capabilities.push(zdn::client_gateway::native::PROTOCOL);
                    capabilities.push(zdn::lightwallet_service::native::PROTOCOL);
                    capabilities.push(zdn::lightwallet_service::native::INSTALL_PROTOCOL);
                    #[cfg(target_os = "linux")]
                    capabilities.push(zdn::host::runtime::update::PROTOCOL);
                }
            }
            ensure!(
                require.as_deref().is_none_or(|p| capabilities.contains(&p)),
                "unsupported runtime capability"
            );
            print_json(&json!({
                "apiVersion":"zdn-native-runtime/v1alpha1",
                "capabilities":capabilities,
            }))
        }
        #[cfg(target_os = "linux")]
        Commands::HostRuntime {
            protocol,
            manifest,
            operation,
        } => {
            ensure!(
                protocol == zdn::host::runtime::PROTOCOL,
                "unsupported host runtime protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&cancelled);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            if let Some(report) =
                zdn::host::runtime::control::execute(&manifest, operation, &cancelled)?
            {
                print_json(&report)?;
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Commands::HostInstall { protocol } => {
            ensure!(
                protocol == zdn::host::runtime::INSTALL_PROTOCOL,
                "unsupported host install protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&cancelled);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            match zdn::host::runtime::install::execute(&cancelled) {
                Ok(report) => print_json(&report),
                Err(stage) => {
                    // Saved installer transports preserve stdout but suppress
                    // stderr. Emit only the fixed stage, never its source error.
                    print_json(&json!({
                        "apiVersion": "zdn-host-install-failure/v1alpha1",
                        "stage": stage,
                    }))?;
                    Err(stage.into())
                }
            }
        }
        #[cfg(target_os = "linux")]
        Commands::HostUpdate { protocol, manifest } => {
            ensure!(
                protocol == zdn::host::runtime::update::PROTOCOL,
                "unsupported native image update protocol"
            );
            use std::{
                io::Read,
                sync::{
                    atomic::{AtomicBool, Ordering},
                    Arc,
                },
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&cancelled);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(zdn::host::runtime::revision::MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
            print_json(&zdn::host::runtime::update::execute(
                &manifest, &bytes, &cancelled,
            )?)
        }
        #[cfg(target_os = "linux")]
        Commands::LightwalletInstall { protocol } => {
            ensure!(
                protocol == zdn::lightwallet_service::native::INSTALL_PROTOCOL,
                "unsupported lightwallet install protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let stop = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&stop);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            print_json(&zdn::host::runtime::lightwallet::execute_install(&stop)?)
        }
        #[cfg(target_os = "linux")]
        Commands::LightwalletRuntime {
            protocol,
            manifest,
            operation,
        } => {
            ensure!(
                protocol == zdn::lightwallet_service::native::PROTOCOL,
                "unsupported lightwallet runtime protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let stop = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&stop);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            if let Some(report) =
                zdn::host::runtime::lightwallet::execute(&manifest, operation, &stop)?
            {
                print_json(&report)?;
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Commands::ClientGateway {
            protocol,
            manifest,
            operation,
        } => {
            ensure!(
                protocol == zdn::client_gateway::native::PROTOCOL,
                "unsupported native gateway protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let stop = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&stop);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            if let Some(report) = zdn::host::runtime::gateway::execute(&manifest, operation, &stop)?
            {
                print_json(&report)?;
            }
            Ok(())
        }
        Commands::FoundationServe {
            protocol,
            network_id,
            size,
        } => {
            ensure!(
                cfg!(target_os = "linux") && protocol == zdn::foundation_host::PROTOCOL,
                "unsupported foundation runtime protocol"
            );
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let cancel = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&cancel);
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            let health = zdn::foundation_host::observe(
                network_id,
                size,
                Path::new("/"),
                Path::new("/var/lib/zdn-chain"),
            )?;
            ensure!(
                !cancel.load(Ordering::SeqCst),
                "foundation health cancelled"
            );
            zdn::foundation::write_json(Path::new("/var/lib/zdn/foundation-ready.json"), &health)?;
            let listener = std::net::TcpListener::bind(("127.0.0.1", zdn::infra::READINESS_PORT))?;
            zdn::foundation_host::serve(
                listener,
                network_id,
                size,
                Path::new("/"),
                Path::new("/var/lib/zdn-chain"),
                &cancel,
            )
        }
        Commands::FoundationFetch { protocol } => {
            ensure!(
                cfg!(target_os = "linux") && protocol == zdn::foundation_host::PROTOCOL,
                "unsupported foundation runtime protocol"
            );
            let endpoint = std::net::SocketAddr::from(([127, 0, 0, 1], zdn::infra::READINESS_PORT));
            let body = zdn::foundation_runtime::fetch(endpoint, Duration::from_secs(600))?;
            io::stdout().write_all(body.as_bytes())?;
            Ok(())
        }
        Commands::HostCapacity {
            protocol,
            root,
            exclude_current_cgroup,
        } => {
            ensure!(
                protocol == CAPACITY_PROTOCOL,
                "unsupported host-capacity protocol"
            );
            ensure!(cfg!(target_os = "linux"), "host capacity requires Linux");
            use zdn::host::capacity::{observe, CgroupScope};
            let scope = if exclude_current_cgroup {
                CgroupScope::AncestorsOnly
            } else {
                CgroupScope::CurrentAndAncestors
            };
            print_json(&observe(&root, scope)?)
        }
        Commands::BuildExport {
            protocol,
            contract,
            repository,
            registry,
            config_download,
            output,
        } => {
            ensure!(
                protocol == BUILD_EXPORT_PROTOCOL,
                "unsupported build-export protocol"
            );
            let contract = serde_json::from_slice(&zdn::devnet::read_bounded(&contract, 65536)?)?;
            zdn::build_export::export_downloaded_config(
                &contract,
                &repository,
                &registry,
                &config_download,
                &output,
                &zdn::dependencies::HttpDownloader::default(),
            )
        }
        Commands::Init(args) => print_json(&init(args, cli.noninteractive)?),
        Commands::Check(args) => print_json(&check(args)?),
        Commands::Plan(args) => print_json(&plan(args)?),
        Commands::Devnet { command } => cloud_cli::devnet(command),
        Commands::Lightwallet { command } => lightwallet_cli::run(command),
        Commands::Package {
            command: PackageCommand::Verify { manifest, sha256 },
        } => print_json(&verify_package(&manifest, &sha256)?),
        Commands::Package {
            command:
                PackageCommand::Export {
                    manifest,
                    sha256,
                    output,
                },
        } => print_json(&export_package(&manifest, &sha256, &output)?),
        Commands::Release { command } => print_json(&release_cli::run(command)?),
        Commands::Image {
            command:
                ImageCommand::Verify {
                    record,
                    manifest,
                    config,
                    inspect,
                },
        } => {
            let record = zdn::image::ImageRecord::from_json(&zdn::devnet::read_bounded(
                &record,
                zdn::image::MAX_RECORD_BYTES as u64,
            )?)?;
            let verified = zdn::image::validate_manifest_bytes(
                &record,
                &zdn::devnet::read_bounded(&manifest, zdn::image::MAX_MANIFEST_BYTES as u64)?,
            )?;
            if let Some(path) = config {
                zdn::image::validate_config_bytes(
                    &record,
                    &verified,
                    &zdn::devnet::read_bounded(&path, zdn::image::MAX_CONFIG_BYTES as u64)?,
                )?;
            }
            if let Some(path) = inspect {
                print_json(&zdn::image::validate_docker_inspect(
                    &record,
                    &verified,
                    &zdn::devnet::read_bounded(&path, zdn::image::MAX_INSPECT_BYTES as u64)?,
                )?)
            } else {
                print_json(
                    &json!({"apiVersion":zdn::image::VALIDATION_API_VERSION,"image":record.image,"savedImageInputsVerified":true,"nodeRuntimeVerified":false,"launchReady":false}),
                )
            }
        }
        Commands::Chain {
            command: ChainCommand::WaitRpc { manifest, rpc },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            zdn::chain::startup::wait_for_rpc(
                &manifest,
                &rpc.rpc_endpoint,
                &rpc.cookie_file,
                &zdn::chain::rpc::SystemClock::default(),
                Duration::from_secs(rpc.request_timeout_secs),
                Duration::from_secs(rpc.deadline_secs),
            )?;
            print_json(&json!({
                "apiVersion": "zdn-chain-rpc-startup/v1alpha1",
                "effectiveRulesVerified": true,
                "launchReady": false
            }))
        }
        Commands::Chain {
            command:
                ChainCommand::Bootstrap {
                    manifest,
                    bundle,
                    rpc,
                    producer_stopped,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let client = zdn::chain::rpc::HttpNodeRpc::new(&rpc.rpc_endpoint, &rpc.cookie_file)?;
            let report = zdn::chain::bootstrap::load_seed_history(
                &manifest,
                &bundle,
                &client,
                &zdn::chain::rpc::SystemClock::default(),
                &zdn::chain::bootstrap::BootstrapOptions {
                    producer_stopped,
                    request_timeout: Duration::from_secs(rpc.request_timeout_secs),
                    deadline: Duration::from_secs(rpc.deadline_secs),
                    ..Default::default()
                },
            )?;
            print_json(&report)
        }
        Commands::Chain {
            command:
                ChainCommand::Readiness {
                    manifest,
                    rpc,
                    role,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let client = zdn::chain::rpc::HttpNodeRpc::new(&rpc.rpc_endpoint, &rpc.cookie_file)?;
            let report = zdn::chain::readiness::check_readiness(
                &manifest,
                &client,
                &zdn::chain::rpc::SystemClock::default(),
                &zdn::chain::readiness::ReadinessOptions {
                    role,
                    request_timeout: Duration::from_secs(rpc.request_timeout_secs),
                    deadline: Duration::from_secs(rpc.deadline_secs),
                    ..Default::default()
                },
            )?;
            print_json(&report)
        }
        Commands::Chain {
            command:
                ChainCommand::Produce {
                    manifest,
                    rpc,
                    state_dir,
                    deployment_id,
                    node_id,
                    interval_secs,
                    reconciliation_deadline_secs,
                    max_blocks,
                    unpaced,
                },
        } => {
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            use zdn::chain::producer::{run_producer, ProducerIdentity, ProducerOptions};
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let identity = ProducerIdentity::new(deployment_id, node_id, &manifest)?;
            let mut options = ProducerOptions::new(state_dir, identity);
            options.interval = Duration::from_secs(interval_secs);
            options.request_timeout = Duration::from_secs(rpc.request_timeout_secs);
            options.readiness_deadline = Duration::from_secs(rpc.deadline_secs);
            options.reconciliation_deadline = Duration::from_secs(reconciliation_deadline_secs);
            options.max_blocks = max_blocks;
            options.unpaced = unpaced;
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler = Arc::clone(&cancelled);
            // ctrlc's termination feature includes SIGTERM, the normal systemd stop signal.
            ctrlc::set_handler(move || handler.store(true, Ordering::SeqCst))?;
            let client = zdn::chain::rpc::HttpNodeRpc::new(&rpc.rpc_endpoint, &rpc.cookie_file)?;
            print_json(&run_producer(
                &manifest,
                &client,
                &zdn::chain::rpc::SystemClock::default(),
                &options,
                &cancelled,
            )?)
        }
        Commands::Chain {
            command:
                ChainCommand::ProducerStatus {
                    manifest,
                    state_dir,
                    deployment_id,
                    node_id,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let identity =
                zdn::chain::producer::ProducerIdentity::new(deployment_id, node_id, &manifest)?;
            print_json(&zdn::chain::producer::read_status(&state_dir, &identity)?)
        }
        Commands::Chain {
            command: ChainCommand::Inspect { manifest },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let normalized = manifest.normalized()?;
            print_json(&json!({
                "apiVersion": "zdn-chain-inspection/v1alpha1",
                "structurallyValid": true,
                "launchReady": false,
                "qualification": "pending",
                "consensusFingerprint": normalized.fingerprint()?,
                "normalizedManifest": normalized,
                "remaining": [
                    "Import genesis/seed bytes and validate decoded history and checkpoints with the selected node",
                    "Qualify the chain recipe and matching node, wallet, and lightwalletd versions (H0)",
                    "Qualify runtime parsing, saved-history bootstrap and readiness with the selected node, and add chain deployment"
                ]
            }))
        }
        Commands::Chain {
            command:
                ChainCommand::Import {
                    manifest,
                    blocks_dir,
                    output,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            print_json(&zdn::chain::artifacts::import_bundle(
                &manifest,
                &blocks_dir,
                &output,
            )?)
        }
        Commands::Chain {
            command: ChainCommand::Verify { manifest, bundle },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            print_json(&zdn::chain::artifacts::verify_bundle(&manifest, &bundle)?)
        }
        Commands::Chain {
            command:
                ChainCommand::RenderConfig {
                    manifest,
                    network_name,
                    listen_addr,
                    peers,
                    output,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let rendered = zdn::chain::node_config::render_network_config(
                &manifest,
                &zdn::chain::node_config::RenderOptions {
                    network_name,
                    listen_addr,
                    peers,
                },
            )?;
            if let Some(output) = output {
                write_new_file(&output, rendered.config_toml.as_bytes())?;
            }
            print_json(&rendered)
        }
        Commands::Chain {
            command:
                ChainCommand::RenderRuntime {
                    manifest,
                    deployment_id,
                    node_id,
                    data_root,
                    listen_addr,
                    peers,
                    rpc_listen_addr,
                    role,
                    reward_address,
                    output,
                },
        } => {
            let manifest: ConsensusManifest = zdn::foundation::read_json(&manifest)?;
            let rendered = zdn::chain::runtime_config::render_runtime_config(
                &manifest,
                &zdn::chain::runtime_config::RuntimeOptions {
                    network: zdn::chain::node_config::RenderOptions {
                        network_name: None,
                        listen_addr,
                        peers,
                    },
                    deployment_id,
                    node_id,
                    data_root,
                    rpc_listen_addr,
                    role,
                    reward_address,
                },
            )?;
            if let Some(output) = output {
                write_new_file(&output, rendered.config_toml.as_bytes())?;
            }
            print_json(&rendered)
        }
        Commands::Snapshot {
            config: args,
            output,
            include,
        } => {
            let config = Config::load(&args.config)?;
            let source = config
                .source_root(&args.config)?
                .context("snapshot requires a local node.source.path")?;
            print_json(&source::capture(&CaptureOptions {
                source,
                output,
                revision: config.node.source.revision,
                include,
            })?)
        }
        Commands::Up {
            launch,
            managed,
            reconcile,
            recover_lease_etag,
            yes,
        } => cloud_cli::devnet(cloud_cli::DevnetCommand::Up {
            launch,
            managed,
            reconcile,
            recover_lease_etag,
            yes,
        }),
        Commands::Doctor(args) => {
            let root = data_path(args.managed_dir, "tools")?;
            let report = dependencies::doctor(&dependencies::SystemProcessRunner, Some(&root));
            print_json(&report)?;
            ensure!(
                report.ready,
                "prerequisites are incomplete; see the checks above"
            );
            Ok(())
        }
        Commands::Deps { command } => match command {
            DepsCommand::List => print_json(&dependencies::builtin_manifest()?),
            DepsCommand::Install(args) => print_json(&dependencies::install_builtin(&data_path(
                args.managed_dir,
                "tools",
            )?)?),
        },
        Commands::Identity { command } => identity(command),
        Commands::Wallet(args) => wallet_cli::run(args),
        Commands::Fund(args) => wallet_cli::payment::fund(args),
        Commands::Send(args) => wallet_cli::payment::send(args),
        Commands::Tx(args) => wallet_cli::payment::tx(args),
        Commands::Receipt { command } => receipt(command),
        Commands::Setup { command } => cloud_cli::setup(command),
        Commands::Connect(args) => connect_cli::connect(args),
        Commands::Exec(_) => unreachable!("exec exit status is handled by main"),
        Commands::Rpc(args) => connect_cli::rpc(args),
        Commands::Submit(_) => unreachable!("submission outcome is handled by main"),
        Commands::Endpoints(args) => connect_cli::export(args),
        Commands::Foundation { command } => cloud_cli::foundation(command),
        Commands::Unavailable(args) => {
            let command = args.first().map(String::as_str).unwrap_or_default();
            if [
                "deploy", "destroy", "fund", "send", "tx", "status", "logs", "resume",
            ]
            .contains(&command)
            {
                bail!("{command} is not implemented yet; use init, check, plan, snapshot, doctor, deps, identity, receipt, setup, or foundation. No cloud action was started")
            }
            bail!("unknown command {command:?}; run zdn --help")
        }
    }
}

/// Publish a complete private file without following or replacing an existing output.
fn write_new_file(path: &Path, mut bytes: &[u8]) -> Result<()> {
    write_new_file_from(path, &mut bytes)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.write_new_file")
)]
fn write_new_file_from(path: &Path, input: &mut impl Read) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(path.file_name().is_some(), "output must name a new file");
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("create temporary file in output directory")?;
    io::copy(input, &mut temporary)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).with_context(|| {
        format!(
            "publish new file {}; existing outputs are never replaced",
            path.display()
        )
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "file {} was published, but its output directory could not be synced",
                path.display()
            )
        })?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.check")
)]
fn check(args: ConfigArgs) -> Result<serde_json::Value> {
    let config = Config::load(&args.config)?;
    Ok(
        json!({"valid": true, "configSha256": config.fingerprint()?, "launchReady": false,
        "capabilities": zdn::devnet::capabilities(&config)?}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.plan")
)]
fn plan(args: ConfigArgs) -> Result<serde_json::Value> {
    let config = Config::load(&args.config)?;
    let chain = ChainRequest::from_config(&config)?;
    let compatibility = CompatibilityRecord::pending(&chain)?;
    Ok(json!({
        "apiVersion": "zdn-plan/v1alpha1", "launchReady": false,
        "capabilities": zdn::devnet::capabilities(&config)?,
        "configSha256": config.fingerprint()?, "config": config,
        "perNode": config.node.resources.preset.allocation(),
        "lightwalletImplementation": "lightwalletd",
        "chainRequest": chain, "compatibility": compatibility,
        "remaining": ["Complete and qualify the chain recipe and client versions (H0)",
            "Qualify deployment prerequisites and live node readiness; wallet and faucet services remain unsupported",
            "Complete human payment and client compatibility qualification"]
    }))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.init")
)]
fn init(mut args: InitArgs, noninteractive: bool) -> Result<serde_json::Value> {
    ensure!(
        args.adapter == "zakura",
        "only the zakura adapter is supported"
    );
    if args.source.is_none() && args.release.is_none() && args.image.is_none() {
        ensure!(!noninteractive && io::stdin().is_terminal(), "select --source PATH, --release VERSION, or --image DIGEST when input is not interactive");
        eprintln!("Choose source: 1) local Zakura checkout  2) candidate Zakura release (not yet qualified)");
        match prompt("Source [1]: ")?.as_str() {
            "" | "1" => {
                let path = prompt("Checkout path [.]: ")?;
                args.source = Some(if path.is_empty() {
                    PathBuf::from(".")
                } else {
                    path.into()
                });
            }
            "2" => args.release = Some(prompt("Exact candidate release version: ")?),
            _ => bail!("select 1 or 2"),
        }
    }
    let path = args
        .source
        .map(|source| {
            let path = fs::canonicalize(&source)
                .with_context(|| format!("resolve source {}", source.display()))?;
            let root = fs::canonicalize(git(&path, &["rev-parse", "--show-toplevel"])?)?;
            ensure!(
                path == root,
                "select the Git worktree root as --source: {}",
                root.display()
            );
            Ok::<_, eyre::Report>(path)
        })
        .transpose()?;
    let snapshot = path.as_ref().map(|_| {
        if args.revision.is_some() {
            SnapshotMode::Revision
        } else {
            SnapshotMode::Worktree
        }
    });
    let mut config = Config::draft(
        args.name,
        args.profile,
        Source {
            path,
            snapshot,
            revision: args.revision,
            release: args.release,
            image: args.image,
        },
        args.size,
    )?;
    if let Some(build) = config.node.build.as_mut() {
        if let Some(dockerfile) = args.dockerfile {
            build.dockerfile = dockerfile;
        }
        if let Some(context) = args.build_context {
            build.context = context;
        }
    }
    config.network.nodes = args.nodes;
    config.services = args.service_preset.services();
    config.validate()?;
    config.write_new(&args.config.config)?;
    Ok(
        json!({"config": args.config.config, "configSha256": config.fingerprint()?, "launchReady": false,
        "capabilities": zdn::devnet::capabilities(&config)?}),
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.identity")
)]
fn identity(command: IdentityCommand) -> Result<()> {
    match command {
        IdentityCommand::Bind {
            binding: args,
            manifest,
        } => {
            let (config, context) = binding_context(&args)?;
            let store = open_store(args.store)?;
            let binding = store.bind(&context, &config.name)?;
            if let Some(manifest) = manifest {
                connect_cli::register_wallet_manifest(&store, binding.network_id, &manifest)?;
            }
            print_json(&binding)
        }
        IdentityCommand::Export(args) => {
            let (_, context) = binding_context(&args)?;
            print_json(&open_store(args.store)?.binding(&context)?.to_export())
        }
        IdentityCommand::Attach {
            binding,
            from,
            network_id,
        } => {
            let (_, context) = binding_context(&binding)?;
            let exported: BindingExport = serde_json::from_slice(&read_small(&from)?)?;
            print_json(&open_store(binding.store)?.attach(&context, network_id, &exported)?)
        }
        IdentityCommand::List { store, scope } => {
            print_json(&open_store(store)?.list(&scope.scope())?)
        }
        IdentityCommand::Resolve {
            selector,
            store,
            scope,
        } => print_json(&open_store(store)?.resolve(&scope.scope(), &selector, None)?),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.receipt")
)]
fn receipt(command: ReceiptCommand) -> Result<()> {
    match command {
        ReceiptCommand::Create { binding, snapshot } => {
            let (config, context) = binding_context(&binding)?;
            let inputs =
                operation_inputs(&config, &binding.config.config, snapshot.as_deref(), true)?;
            let store = open_store(binding.store)?;
            let binding = store.binding(&context)?;
            print_json(&store.begin_operation(
                &binding,
                "deployment",
                inputs,
                &[
                    "reserve-network",
                    "resolve-image",
                    "apply-infrastructure",
                    "check-readiness",
                ],
            )?)
        }
        ReceiptCommand::Inspect {
            operation_id,
            store,
        } => print_json(&open_store(store)?.operation(operation_id)?),
        ReceiptCommand::ResumePlan {
            operation_id,
            store,
            inputs,
        } => {
            let config = Config::load(&inputs.config.config)?;
            let inputs = operation_inputs(
                &config,
                &inputs.config.config,
                inputs.snapshot.as_deref(),
                false,
            )?;
            print_json(&open_store(store)?.resume(operation_id, &inputs)?)
        }
        ReceiptCommand::Cancel {
            operation_id,
            store,
        } => {
            let store = open_store(store)?;
            let receipt = store.operation(operation_id)?;
            print_json(&store.request_cancel(operation_id, receipt.revision)?)
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.binding_context")
)]
fn binding_context(args: &BindingArgs) -> Result<(Config, BindingContext)> {
    let config = Config::load(&args.config.config)?;
    let checkout = match config.source_root(&args.config.config)? {
        Some(source) => Some(source),
        None => config_checkout(&args.config.config)?,
    };
    let (worktree, branch) = if let Some(checkout) = checkout {
        let root = PathBuf::from(git(&checkout, &["rev-parse", "--show-toplevel"])?);
        let branch = git(&checkout, &["branch", "--show-current"])?;
        (Some(root), (!branch.is_empty()).then_some(branch))
    } else {
        (None, None)
    };
    let scope = match (
        &args.scope.team_id,
        &args.scope.account_id,
        &args.scope.region,
    ) {
        (Some(team_id), Some(account_id), Some(region)) => Scope {
            team_id: team_id.clone(),
            account_id: account_id.clone(),
            region: region.clone(),
        },
        (None, None, None) => {
            cloud_cli::load_profile(&open_store(args.store.clone())?, &config.profile)?
                .team
                .scope()
        }
        _ => bail!("supply all scope flags or omit them to use the saved profile"),
    };
    // An explicit offline scope remains supported, but cannot contradict a saved profile.
    let store = open_store(args.store.clone())?;
    let profile_path = cloud_cli::profile_path(&store, &config.profile)?;
    match fs::symlink_metadata(profile_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        result => {
            result?;
            let profile = cloud_cli::load_profile(&store, &config.profile)?;
            ensure!(
                profile.team.scope() == scope,
                "explicit binding scope differs from the saved profile"
            );
        }
    }
    Ok((
        config,
        BindingContext::new(&args.config.config, worktree, branch, scope)?,
    ))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.config_checkout")
)]
fn config_checkout(config_path: &Path) -> Result<Option<PathBuf>> {
    let path = fs::canonicalize(config_path)?;
    let parent = path.parent().context("config has no parent")?;
    // Both normal and linked worktrees have a .git entry. Discover the entry
    // first so a non-Git configuration needs no failed Git command. Once an
    // entry is present, all Git errors (including a damaged repository or a
    // missing executable) must propagate instead of creating an unscoped ID.
    for ancestor in parent.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(Some(parent.to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect configuration checkout"),
        }
    }
    Ok(None)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.operation_inputs")
)]
fn operation_inputs(
    config: &Config,
    config_path: &Path,
    snapshot: Option<&Path>,
    verify_live_source: bool,
) -> Result<OperationInput> {
    let mut inputs = OperationInput {
        config_sha256: config.fingerprint()?,
        source_manifest_sha256: None,
        archive_sha256: None,
    };
    match (&config.node.source.path, snapshot) {
        (Some(_), Some(directory)) => {
            let bytes = read_small(&directory.join("receipt.json"))?;
            let saved: SnapshotReceipt =
                serde_json::from_slice(&bytes).context("invalid source snapshot receipt")?;
            ensure!(
                saved.schema_version == 1,
                "unsupported source snapshot receipt version"
            );
            if verify_live_source {
                ensure!(
                    Some(&saved.source_root) == config.source_root(config_path)?.as_ref(),
                    "snapshot belongs to a different source directory"
                );
            }
            ensure!(
                matches!(
                    (config.node.source.snapshot, saved.mode),
                    (
                        None | Some(SnapshotMode::Worktree),
                        source::SnapshotMode::Worktree
                    ) | (Some(SnapshotMode::Revision), source::SnapshotMode::Revision)
                ),
                "snapshot mode does not match the configuration"
            );
            if verify_live_source {
                if let Some(revision) = &config.node.source.revision {
                    let selected = git(
                        &saved.source_root,
                        &[
                            "rev-parse",
                            "--verify",
                            "--end-of-options",
                            &format!("{revision}^{{commit}}"),
                        ],
                    )?;
                    ensure!(saved.head == selected, "snapshot commit does not match the configured revision; capture the requested revision");
                }
            }
            let path = directory.join("source.tar");
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "snapshot archive must be a regular file"
            );
            let mut archive = fs::File::open(&path)?;
            let mut digest = Sha256::new();
            let length = io::copy(&mut archive, &mut digest)?;
            let actual = hex::encode(digest.finalize());
            ensure!(
                length == saved.archive_bytes && actual == saved.archive_sha256,
                "saved source archive failed its size or SHA-256 check"
            );
            inputs.source_manifest_sha256 = Some(hex::encode(Sha256::digest(bytes)));
            inputs.archive_sha256 = Some(actual);
            // Creation validates the live source directory and selected
            // commit above. Resume instead requires these exact hashes in
            // StateStore::resume, preserving that original source identity
            // even after the checkout is moved, changed, or removed.
        }
        (Some(_), None) => {
            bail!("local source requires --snapshot DIRECTORY; capture once with zdn snapshot")
        }
        (None, Some(_)) => bail!("release/image operations must omit --snapshot"),
        (None, None) => {}
    }
    inputs.validate()?;
    Ok(inputs)
}

fn open_store(args: StoreArgs) -> Result<StateStore> {
    StateStore::open(data_path(args.state_dir, "state")?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.data_path")
)]
fn data_path(explicit: Option<PathBuf>, child: &str) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let base = if let Some(path) = std::env::var_os("XDG_DATA_HOME").filter(|p| !p.is_empty()) {
        let path = PathBuf::from(path);
        ensure!(
            path.is_absolute(),
            "XDG_DATA_HOME must be absolute or unset"
        );
        path
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .context("set HOME, XDG_DATA_HOME, or an explicit data directory")?,
        )
        .join(".local/share")
    };
    Ok(base.join("zdn").join(child))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.read_small")
)]
fn read_small(path: &Path) -> Result<Vec<u8>> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "receipt must be a regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "receipt exceeds 16 MiB");
    Ok(bytes)
}

#[cfg_attr(feature = "profiling", tracing::instrument(skip_all, name = "cli.git"))]
fn git(path: &Path, args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(path).args(args);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command.env("GIT_NO_LAZY_FETCH", "1");
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("GIT_NO_REPLACE_OBJECTS", "1");
    let output = dependencies::run_command(&mut command, Duration::from_secs(5))?;
    ensure!(
        output.success,
        "Git source lookup failed: {}",
        output.stderr.trim()
    );
    Ok(output.stdout.trim_end_matches('\n').to_owned())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "cli.prompt")
)]
fn prompt(message: &str) -> Result<String> {
    eprint!("{message}");
    io::stderr().flush()?;
    let mut line = String::new();
    ensure!(
        io::stdin().read_line(&mut line)? > 0,
        "input ended before source selection"
    );
    Ok(line.trim().to_owned())
}

fn print_json(value: &impl Serialize) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}
