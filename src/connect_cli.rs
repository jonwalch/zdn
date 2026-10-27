//! Private local connections. Exported files never carry a credential bridge.
use super::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use zdn::{
    aws::{AwsCli, AwsSelection, LocalProfile},
    endpoints::{EndpointFile, Service},
    foundation::{self, Deployment, DeploymentFile},
};

#[derive(Args)]
pub struct EndpointArgs {
    /// Full network ID, unique prefix, or unambiguous saved label.
    network: String,
    #[command(flatten)]
    store: StoreArgs,
    /// Saved local ZDN profile alias, not the AWS CLI profile of an invited participant.
    #[arg(long, default_value = "devnet")]
    profile: String,
    /// New credential-free JSON file. Existing files are never replaced.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  zdn connect NETWORK\n  zdn connect --endpoints endpoints.json --aws-profile participant\n\nKeep this process running while using the printed loopback URLs. Ctrl-C closes owned tunnels/sessions, not the AWS devnet. Requires authenticated AWS CLI v2 and a Session Manager plugin newer than 1.2.497.0. Readiness checks identity; it does not qualify wallet payments. --json is a readiness record followed by a running process, not the root --format protocol. See docs/connections.md."
)]
pub struct ConnectArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Emit one JSON readiness record. Keep this process running afterwards.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
#[command(
    after_help = "Example: zdn exec NETWORK -- ./my-integration-test --case private-network\n\nZDN verifies tunnels/identity before starting the program, supplies ZDN_RPC_URL, optional ZDN_LIGHTWALLET_GRPC_URL, ZDN_NETWORK_ID and ZDN_CONSENSUS_FINGERPRINT, and cleans up owned sessions/descendants afterwards. The devnet keeps running. No shell is implied, stdin is closed, stdout/stderr pass through. Caller environment/credentials remain: this is NOT a sandbox for untrusted programs. Root --format json/jsonl is unsupported; use --events-file for separate JSONL events. No reconnect or automatic child retry. See docs/connections.md."
)]
pub struct ExecArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// New private JSONL event file; child stdout/stderr remain unchanged.
    #[arg(long)]
    events_file: Option<PathBuf>,
    /// Noninteractive program and arguments, following --. No shell is implied.
    #[arg(last = true, required = true)]
    command: Vec<std::ffi::OsString>,
}

#[derive(Args)]
#[command(allow_missing_positional = true)]
pub struct RpcArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Exact read-only method exposed by the private participant gateway.
    #[arg(help = format!("Read-only gateway RPC method; supported: {}. This interface never calls mutating methods.", READ_ONLY_RPC_METHODS.join(", ")))]
    method: String,
    /// JSON array or object of method parameters.
    #[arg(long, default_value = "[]")]
    params: String,
}

#[derive(Args)]
#[command(
    after_help = "Example: zdn submit NETWORK --transaction-file signed-transaction.hex\n\nThis broadcasts already-signed bytes once; no signing or --yes prompt. Preserve the result and transaction hash. outcome-unknown means the node may have accepted it: do not blindly rerun or create a replacement payment. Cleanup may fail independently of submission; inspect both fields. Root --format json/jsonl provides the versioned result. See docs/connections.md."
)]
pub struct SubmitArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Already-signed transaction as hexadecimal text. Sent once, never retried.
    #[arg(long)]
    transaction_file: PathBuf,
}

#[derive(Args)]
pub struct WalletHistoryArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Reviewed consensus manifest override; omit to use saved deployment/identity-bind registration. Must match selected network fingerprint and wallet schedule.
    #[arg(long)]
    manifest: Option<PathBuf>,
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub(super) enum SubmissionOutcome {
    NotDispatched,
    NodeRejected { code: i32 },
    Acknowledged { txid: String },
    OutcomeUnknown,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum SubmissionCleanup {
    NoSessions,
    Complete,
    Incomplete,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmissionReport {
    api_version: &'static str,
    #[serde(flatten)]
    outcome: SubmissionOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consensus_fingerprint: Option<String>,
    cleanup: SubmissionCleanup,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

// This is a separate read-only policy, not all methods the gateway permits.
// New gateway methods must not silently become available through this command.
const READ_ONLY_RPC_METHODS: &[&str] = &[
    "getinfo",
    "getdeprecationinfo",
    "getblockchaininfo",
    "getaddressbalance",
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
const MAX_RPC_BYTES: usize = 8 * 1024 * 1024;

#[derive(Args)]
struct ConnectionArgs {
    /// Saved network UUID, unique prefix or unambiguous label; required unless --endpoints. Use UUID before launch, label after up.
    #[arg(required_unless_present = "endpoints", conflicts_with = "endpoints")]
    network: Option<String>,
    /// Reviewed credential-free endpoint JSON; requires your own --aws-profile and conflicts with NETWORK/--profile/--state-dir.
    #[arg(long, requires = "aws_profile", conflicts_with_all = ["network", "profile", "state_dir"])]
    endpoints: Option<PathBuf>,
    /// Your AWS CLI login profile (required with --endpoints); never supplied by an exported endpoint file.
    #[arg(long)]
    aws_profile: Option<String>,
    #[command(flatten)]
    store: StoreArgs,
    /// Local ZDN profile (default devnet) for a saved network; conflicts with --endpoints. Not an AWS CLI profile.
    #[arg(long)]
    profile: Option<String>,
    /// Fixed IPv4 loopback RPC listener port (1..=65535); omitted selects an available ephemeral port. Occupied ports fail.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    rpc_port: Option<u16>,
    /// Fixed loopback lightwalletd port (1..=65535); omitted is ephemeral if enabled. Explicit request fails when service is disabled.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    grpc_port: Option<u16>,
    /// Tunnel/listener/service startup deadline in seconds (1..=300); does not authorize reconnection/rebroadcast.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=300))]
    startup_timeout_secs: u64,
}

impl ConnectionArgs {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.selected")
    )]
    fn selected(&self) -> Result<(Option<Deployment>, EndpointFile)> {
        if let Some(path) = &self.endpoints {
            Ok((None, EndpointFile::load(path)?))
        } else {
            let (deployment, file) = saved(
                self.store.clone(),
                self.profile.as_deref().unwrap_or("devnet"),
                self.network.as_deref().context("select a network")?,
            )?;
            Ok((Some(deployment), file))
        }
    }
}

impl WalletHistoryArgs {
    /// Named balance uses its first positional for NETWORK, not a private key path.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.named_network")
    )]
    pub fn named_network(&mut self, network: Option<PathBuf>) -> Result<()> {
        ensure!(
            self.connection.network.is_none(),
            "named balance accepts only one network selector"
        );
        ensure!(
            self.connection.endpoints.is_none() || network.is_none(),
            "do not combine a network selector with --endpoints"
        );
        self.connection.network = network
            .map(|path| {
                path.into_os_string()
                    .into_string()
                    .map_err(|_| eyre::eyre!("network selector must be UTF-8"))
            })
            .transpose()?;
        Ok(())
    }

    /// Local-only selection: no AWS identity, service probe or tunnel is started.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.selection")
    )]
    pub fn selection(&self) -> Result<(ConsensusManifest, EndpointFile)> {
        let (deployment, endpoints) = self.connection.selected()?;
        let manifest = match &self.manifest {
            Some(path) => foundation::read_json(path)?,
            None => deployment
                .as_ref()
                .context("imported endpoints require an explicit --manifest")?
                .cluster
                .as_ref()
                .context("saved deployment has no consensus manifest")?
                .manifest
                .clone(),
        };
        let manifest = manifest.normalized()?;
        super::wallet_cli::history::check_manifest(&manifest)?;
        ensure!(
            endpoints.consensus_fingerprint == manifest.fingerprint()?,
            "wallet manifest does not match the selected endpoint consensus fingerprint"
        );
        if deployment.is_some() {
            let store = open_store(self.connection.store.clone())?;
            check_registered_manifest(&store, endpoints.network_id, &manifest)?;
        }
        Ok((manifest, endpoints))
    }

    /// Fresh keys can be bound before deployment supplies private RPC routing.
    pub fn creation_scope(&self) -> Result<(uuid::Uuid, String)> {
        if self.connection.endpoints.is_some() {
            let (_, identity) = self.selection()?;
            return Ok((identity.network_id, identity.consensus_fingerprint));
        }
        let (store, _, binding) = local_binding(
            self.connection.store.clone(),
            self.connection.profile.as_deref().unwrap_or("devnet"),
            self.connection
                .network
                .as_deref()
                .context("select a network")?,
        )?;
        if store
            .root()
            .join("foundation")
            .join(binding.network_id.to_string())
            .symlink_metadata()
            .map_or_else(
                |e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(false)
                    } else {
                        Err(e)
                    }
                },
                |_| Ok(true),
            )?
        {
            let (_, identity) = self.selection()?;
            return Ok((identity.network_id, identity.consensus_fingerprint));
        }
        let registered = registered_manifest(&store, binding.network_id)?;
        let manifest: ConsensusManifest = match &self.manifest {
            Some(path) => foundation::read_json(path)?,
            None => serde_json::from_str(
                &registered.as_ref().context("before deployment, register reviewed bytes with zdn identity bind --manifest FILE or supply --manifest")?.manifest_json,
            )?,
        };
        let manifest = manifest.normalized()?;
        super::wallet_cli::history::check_manifest(&manifest)?;
        check_registered_manifest(&store, binding.network_id, &manifest)?;
        Ok((binding.network_id, manifest.fingerprint()?))
    }
}

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegisteredManifest {
    network_id: Uuid,
    manifest_json: String,
}

fn registered_manifest(store: &StateStore, network_id: Uuid) -> Result<Option<RegisteredManifest>> {
    let directory = store.root().join("wallet-manifests");
    match fs::symlink_metadata(&directory) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => ensure!(
            result?.is_dir(),
            "wallet manifest directory must be a real directory"
        ),
    }
    let path = directory.join(format!("{network_id}.json"));
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        result => {
            result?;
            let record: RegisteredManifest = foundation::read_json(&path)?;
            ensure!(
                record.network_id == network_id,
                "registered wallet manifest network mismatch"
            );
            let manifest: ConsensusManifest = serde_json::from_str(&record.manifest_json)?;
            super::wallet_cli::history::check_manifest(&manifest.normalized()?)?;
            Ok(Some(record))
        }
    }
}

pub(crate) fn check_registered_manifest(
    store: &StateStore,
    network_id: Uuid,
    manifest: &ConsensusManifest,
) -> Result<()> {
    if let Some(record) = registered_manifest(store, network_id)? {
        let registered: ConsensusManifest = serde_json::from_str(&record.manifest_json)?;
        ensure!(
            registered.fingerprint()? == manifest.fingerprint()?,
            "manifest differs from this network's registered wallet manifest"
        );
    }
    Ok(())
}

pub(crate) fn register_wallet_manifest(
    store: &StateStore,
    network_id: Uuid,
    path: &Path,
) -> Result<()> {
    let bytes = zdn::devnet::read_bounded(path, 512 * 1024)?;
    let manifest: ConsensusManifest = serde_json::from_slice(&bytes)?;
    super::wallet_cli::history::check_manifest(&manifest.normalized()?)?;
    let record = RegisteredManifest {
        network_id,
        manifest_json: String::from_utf8(bytes)?,
    };
    // A deployment directory, even with missing or damaged metadata, is authority.
    let deployed = store.root().join("foundation").join(network_id.to_string());
    match fs::symlink_metadata(&deployed) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        result => {
            result?;
            let deployment = DeploymentFile::read_snapshot(store.root(), network_id)?;
            ensure!(
                deployment
                    .cluster
                    .context("saved deployment has no consensus manifest")?
                    .manifest
                    .fingerprint()?
                    == manifest.fingerprint()?,
                "registered manifest differs from saved deployment"
            );
        }
    }
    if let Some(saved) = registered_manifest(store, network_id)? {
        ensure!(
            saved.manifest_json == record.manifest_json,
            "reviewed wallet manifest bytes are already registered; refusing replacement"
        );
        return Ok(());
    }
    let directory = store.root().join("wallet-manifests");
    foundation::private_directory(&directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&serde_json::to_vec(&record)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(directory.join(format!("{network_id}.json")))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn local_binding(
    store: StoreArgs,
    profile: &str,
    selector: &str,
) -> Result<(StateStore, LocalProfile, zdn::state::Binding)> {
    ensure!(
        !profile.is_empty()
            && profile.len() <= 128
            && profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid local profile name"
    );
    let root = data_path(store.state_dir, "state")?;
    ensure!(
        root.is_dir(),
        "local state is missing; select a deployed devnet or use --endpoints with --aws-profile"
    );
    let store = StateStore::open(root)?;
    let local: LocalProfile = foundation::read_json(
        &store
            .root()
            .join("profiles")
            .join(format!("{profile}.json")),
    )
    .context("local profile is missing; use its saved --profile name")?;
    local.validate()?;
    let binding = store.resolve(&local.team.scope(), selector, None)?;
    Ok((store, local, binding))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.saved")
)]
fn saved(store: StoreArgs, profile: &str, selector: &str) -> Result<(Deployment, EndpointFile)> {
    let (store, local, binding) = local_binding(store, profile, selector)?;
    let mut deployment = DeploymentFile::read_snapshot(store.root(), binding.network_id)?;
    ensure!(
        deployment.team == local.team,
        "saved deployment belongs to different team settings"
    );
    deployment.spec.aws_profile = local.aws_profile;
    let expected = EndpointFile::from_deployment(&deployment)?;
    let file = EndpointFile::load(
        &store
            .root()
            .join("foundation")
            .join(binding.network_id.to_string())
            .join("client-endpoints.json"),
    )
    .context("private client service installation has not completed; finish devnet up first")?;
    ensure!(
        file == expected,
        "saved private endpoint identities differ from the deployment"
    );
    Ok((deployment, file))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.export")
)]
pub fn export(args: EndpointArgs) -> Result<()> {
    let (_, endpoints) = saved(args.store, &args.profile, &args.network)?;
    endpoints.save_new(&args.output)?;
    print_json(
        &json!({"networkId":endpoints.network_id,"output":args.output,"credentialsIncluded":false,"liveReadinessChecked":false}),
    )
}

#[cfg(not(unix))]
pub fn connect(_: ConnectArgs) -> Result<()> {
    bail!("private connections currently require macOS or Linux")
}

#[cfg(unix)]
pub fn connect(args: ConnectArgs) -> Result<()> {
    connect_with(args.connection, args.json, None, None).map(|_| ())
}

#[cfg(not(unix))]
pub fn exec(_: ExecArgs) -> ExitCode {
    eprintln!("zdn: scoped execution currently requires macOS or Linux");
    ExitCode::from(125)
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.exec")
)]
pub fn exec(args: ExecArgs) -> ExitCode {
    let mut events = match args
        .events_file
        .as_deref()
        .map(ExecEvents::create)
        .transpose()
    {
        Ok(events) => events,
        Err(_) => {
            eprintln!("zdn: cannot create private exec event file; select a new file in an existing directory");
            return ExitCode::from(125);
        }
    };
    if let Some(events) = &mut events {
        if events
            .write("command-started", "running", Value::Null)
            .is_err()
        {
            eprintln!("zdn: cannot write exec events; command not started");
            return ExitCode::from(125);
        }
    }
    let result = connect_with(args.connection, false, Some(args.command), events.as_mut());
    let mut code = match &result {
        Ok(Some(status)) => status
            .exit_code
            .or_else(|| status.signal.map(|signal| 128 + signal))
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(125),
        Ok(None) => 125,
        Err(error) => {
            eprintln!("zdn: {error:#}");
            let cancelled = error
                .downcast_ref::<zdn::connections::ExecError>()
                .is_some_and(|error| error.cancelled && !error.cleanup_incomplete);
            if cancelled {
                130
            } else {
                125
            }
        }
    };
    if let Some(events) = &mut events {
        let failure = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<zdn::connections::ExecError>());
        let child_status = result
            .as_ref()
            .ok()
            .and_then(|status| status.as_ref())
            .or_else(|| failure.and_then(|error| error.child_status.as_ref()));
        let cleanup_incomplete = failure.is_some_and(|error| error.cleanup_incomplete);
        let mut record = cli_output::event(
            Some("exec"),
            "result",
            if code == 0 { "succeeded" } else { "failed" },
            json!({
                "exitCode": code,
                "childStatus": child_status.map(|status| json!({"exitCode": status.exit_code, "signal": status.signal})),
                "cancelled": failure.is_some_and(|error| error.cancelled),
                "tunnelFailed": failure.is_some_and(|error| error.tunnel_failed),
                "cleanup": if cleanup_incomplete { "incomplete" } else if result.is_ok() || failure.is_some() { "complete" } else { "no-sessions" },
                "eventsFailed": events.failed
            }),
        );
        if code != 0 {
            record["error"] = json!({"code": "exec-failed", "message": "Scoped execution failed",
                "retryClassification": if cleanup_incomplete || child_status.is_some() { "reconcile-required" } else { "blocked" }});
        }
        record["networkId"] = json!(events.network_id);
        if events.write_record(&record).is_err() {
            eprintln!("zdn: cannot write terminal exec event; execution was not replayed");
            if let Some(status) = child_status {
                eprintln!(
                    "zdn: child exit code {:?}, signal {:?}",
                    status.exit_code, status.signal
                );
            }
            code = 125;
        }
    }
    ExitCode::from(code)
}

#[cfg(unix)]
struct ExecEvents {
    file: std::fs::File,
    network_id: Option<Uuid>,
    failed: bool,
}

#[cfg(unix)]
impl ExecEvents {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.events.create")
    )]
    fn create(path: &Path) -> Result<Self> {
        let file = cli_output::create_event_file(path)?;
        Ok(Self {
            file,
            network_id: None,
            failed: false,
        })
    }

    fn write(&mut self, kind: &str, outcome: &str, data: Value) -> Result<()> {
        let mut record = cli_output::event(Some("exec"), kind, outcome, data);
        record["networkId"] = json!(self.network_id);
        self.write_record(&record)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.events.write_record")
    )]
    fn write_record(&mut self, record: &Value) -> Result<()> {
        let result: Result<()> = (|| {
            serde_json::to_writer(&mut self.file, record)?;
            writeln!(self.file)?;
            self.file.flush()?;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result.context("cannot write exec event file")
    }
}

pub fn rpc(args: RpcArgs) -> Result<()> {
    print_json(&rpc_result(args, cli_output::Format::Human, &mut None)?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.machine_rpc")
)]
pub fn machine_rpc(args: RpcArgs, format: cli_output::Format) -> ExitCode {
    let mut network_id = None;
    let (mut record, code) = match rpc_result(args, format, &mut network_id) {
        Ok(result) => (
            cli_output::event(
                Some("rpc"),
                "result",
                "succeeded",
                json!({"result": result}),
            ),
            0,
        ),
        Err(_) => (
            cli_output::failure(
                Some("rpc"),
                "rpc-failed",
                "Private RPC or connection lifecycle failed; no automatic retry is offered.",
            ),
            1,
        ),
    };
    record["networkId"] = json!(network_id);
    machine_record(format, &record, code)
}

#[cfg(not(unix))]
fn rpc_result(_: RpcArgs, _: cli_output::Format, _: &mut Option<Uuid>) -> Result<Value> {
    bail!("private RPC currently requires macOS or Linux")
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.rpc_result")
)]
fn rpc_result(
    args: RpcArgs,
    format: cli_output::Format,
    network_id: &mut Option<Uuid>,
) -> Result<Value> {
    ensure!(
        READ_ONLY_RPC_METHODS.contains(&args.method.as_str())
            && zdn::client_gateway::ALLOWED_METHODS.contains(&args.method.as_str()),
        "select an exact read-only participant RPC method; transaction submission is not supported"
    );
    ensure!(
        args.params.len() <= MAX_RPC_BYTES,
        "RPC parameters exceed their size limit"
    );
    let params: Value = serde_json::from_str(&args.params)
        .map_err(|_| eyre::eyre!("RPC parameters must be valid JSON"))?;
    ensure!(
        params.is_array() || params.is_object(),
        "RPC parameters must be a JSON array or object"
    );
    let request = serde_json::to_string(&json!({
        "jsonrpc":"2.0", "id":"zdn-read", "method":args.method, "params":params
    }))?;
    ensure!(
        request.len() <= MAX_RPC_BYTES,
        "RPC request exceeds its size limit"
    );
    let connection = prepare_connection(args.connection, None)?;
    *network_id = Some(connection.endpoints.network_id);
    zdn::connections::once(
        &connection.options,
        &connection.targets,
        &connection.cancelled,
        |local| {
            let address = connection.verify(local)?;
            connection.report_ready(format, "rpc")?;
            read_rpc(address, &request)
        },
    )
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.submit")
)]
pub fn submit(args: SubmitArgs, format: cli_output::Format) -> ExitCode {
    #[cfg(not(unix))]
    if !format.machine() {
        eprintln!("zdn: transaction submission currently requires macOS or Linux");
        return ExitCode::FAILURE;
    }
    let mut report = SubmissionReport {
        api_version: zdn::client_gateway::SUBMISSION_API_VERSION,
        outcome: SubmissionOutcome::NotDispatched,
        transaction_sha256: None,
        network_id: None,
        consensus_fingerprint: None,
        cleanup: SubmissionCleanup::NoSessions,
        diagnostic: None,
    };
    #[cfg(not(unix))]
    let operation: Result<()> = {
        let _ = args;
        Err(eyre::eyre!(
            "transaction submission currently requires macOS or Linux"
        ))
    };
    #[cfg(unix)]
    let operation = (|| -> Result<()> {
        ensure!(
            fs::metadata(&args.transaction_file)
                .context("cannot inspect transaction file")?
                .is_file(),
            "transaction input must be a regular file"
        );
        let mut bytes = Vec::new();
        fs::File::open(&args.transaction_file)
            .context("cannot open transaction file")?
            .take(MAX_RPC_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .context("cannot read transaction file")?;
        ensure!(
            bytes.len() <= MAX_RPC_BYTES,
            "transaction file exceeds its size limit"
        );
        let transaction = std::str::from_utf8(&bytes)
            .map_err(|_| eyre::eyre!("transaction file must be hexadecimal text"))?
            .trim_ascii();
        ensure!(
            !transaction.is_empty()
                && transaction.len().is_multiple_of(2)
                && transaction.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "transaction file must contain nonempty, even-length hexadecimal text"
        );
        // Input identity only: Zcash transaction IDs are not SHA256(raw bytes).
        report.transaction_sha256 = Some(hex::encode(Sha256::digest(hex::decode(transaction)?)));
        let request = serde_json::to_string(&json!({
            "jsonrpc":"2.0", "id":"zdn-submit", "method":"sendrawtransaction",
            "params":[transaction.to_ascii_lowercase()]
        }))?;
        ensure!(
            request.len() <= MAX_RPC_BYTES,
            "submission request exceeds its size limit"
        );
        let connection = prepare_connection(args.connection, None)?;
        report.network_id = Some(connection.endpoints.network_id);
        report.consensus_fingerprint = Some(connection.endpoints.consensus_fingerprint.clone());
        let operation = zdn::connections::once(
            &connection.options,
            &connection.targets,
            &connection.cancelled,
            |local| {
                let address = connection.verify(local)?;
                connection.report_ready(format, "submit")?;
                // A lost gateway reply might follow a successful node write.
                // Preserve any subsequently known outcome even if cleanup fails.
                report.outcome = SubmissionOutcome::OutcomeUnknown;
                report.outcome = submit_rpc(address, &request)?;
                Ok(())
            },
        );
        report.cleanup = if operation.as_ref().err().is_some_and(|error| {
            error
                .downcast_ref::<zdn::connections::CleanupError>()
                .is_some()
        }) {
            SubmissionCleanup::Incomplete
        } else {
            SubmissionCleanup::Complete
        };
        operation
    })();
    let success =
        operation.is_ok() && matches!(report.outcome, SubmissionOutcome::Acknowledged { .. });
    if format.machine() {
        let mut record = if success {
            cli_output::event(Some("submit"), "result", "succeeded", Value::Null)
        } else {
            let mut record = cli_output::failure(Some("submit"), "submission-failed", "Submission command failed; inspect its retained outcome and cleanup status. Do not blindly resubmit.");
            if matches!(
                report.outcome,
                SubmissionOutcome::Acknowledged { .. } | SubmissionOutcome::OutcomeUnknown
            ) || matches!(report.cleanup, SubmissionCleanup::Incomplete)
            {
                record["error"]["retryClassification"] = json!("reconcile-required");
            }
            record
        };
        record["networkId"] = json!(report.network_id);
        // Machine errors never export paths or arbitrary runtime diagnostics.
        record["data"] = json!({"submission": report});
        return machine_record(format, &record, u8::from(!success));
    }
    if let Err(error) = operation {
        report.diagnostic = Some(format!("{error:#}"));
    }
    if let Err(error) = print_json(&report) {
        eprintln!("zdn: cannot publish submission outcome: {error:#}; do not blindly resubmit");
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

enum RpcReply {
    Result(Value),
    Error { code: i32, data: Option<Value> },
}

/// Allowlisted session failures: never retain endpoint bodies or transport text.
#[derive(Debug)]
pub(super) enum WalletRpcError {
    Cancelled,
    BudgetExceeded,
    Transport,
    ReadRejected,
    InvalidResponse,
}

impl WalletRpcError {
    pub(super) fn classification(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::BudgetExceeded => "session-budget",
            Self::Transport => "rpc-transport",
            Self::ReadRejected => "rpc-rejected",
            Self::InvalidResponse => "rpc-response",
        }
    }
}

impl std::fmt::Display for WalletRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "wallet operation cancelled",
            Self::BudgetExceeded => "wallet operation exceeded its 300-second budget",
            Self::Transport => "private RPC request failed; no retry was attempted",
            Self::ReadRejected => "private node RPC rejected the read request",
            Self::InvalidResponse => "private RPC returned an invalid response",
        })
    }
}
impl std::error::Error for WalletRpcError {}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.read_rpc")
)]
fn read_rpc(address: std::net::SocketAddr, request: &str) -> Result<Value> {
    match request_rpc(address, request, "zdn-read")? {
        (200, RpcReply::Result(value)) => Ok(value),
        (200, RpcReply::Error { code, .. }) => Err(eyre::Report::new(WalletRpcError::ReadRejected)
            .wrap_err(format!(
                "private node RPC rejected the read request (code {code})"
            ))),
        _ => bail!("private RPC returned an unexpected HTTP response"),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.submit_rpc")
)]
fn submit_rpc(address: std::net::SocketAddr, request: &str) -> Result<SubmissionOutcome> {
    match request_rpc(address, request, "zdn-submit")? {
        (200, RpcReply::Result(Value::String(txid)))
            if txid.len() == 64 && txid.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(SubmissionOutcome::Acknowledged {
                txid: txid.to_ascii_lowercase(),
            })
        }
        (200, RpcReply::Error { code, data: None }) => Ok(SubmissionOutcome::NodeRejected { code }),
        (
            status,
            RpcReply::Error {
                code,
                data: Some(data),
            },
        ) if data["apiVersion"] == zdn::client_gateway::SUBMISSION_API_VERSION => {
            match (status, data["outcome"].as_str()) {
                (200, Some("node-rejected")) => Ok(SubmissionOutcome::NodeRejected { code }),
                (502, Some("not-dispatched")) => Ok(SubmissionOutcome::NotDispatched),
                _ => Ok(SubmissionOutcome::OutcomeUnknown),
            }
        }
        _ => Ok(SubmissionOutcome::OutcomeUnknown),
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.request_rpc")
)]
fn request_rpc(address: std::net::SocketAddr, request: &str, id: &str) -> Result<(u16, RpcReply)> {
    let response = match ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(Duration::from_secs(10))
        .build()
        .post(&format!("http://{address}/"))
        .set("Content-Type", "application/json")
        .send_string(request)
    {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return Err(WalletRpcError::Transport.into()),
    };
    let status = response.status();
    ensure!(
        response.header("Location").is_none(),
        "private RPC returned an unexpected HTTP response"
    );
    ensure!(
        response.header("Content-Encoding").is_none(),
        "private RPC returned encoded content"
    );
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RPC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            eyre::Report::new(WalletRpcError::Transport)
                .wrap_err("private RPC response could not be read")
        })?;
    ensure!(
        bytes.len() <= MAX_RPC_BYTES,
        "private RPC response exceeds its size limit"
    );
    let mut answer: Value = serde_json::from_slice(&bytes)
        .map_err(|_| eyre::eyre!("private RPC returned invalid JSON"))?;
    let object = answer
        .as_object()
        .context("private RPC returned an invalid response envelope")?;
    ensure!(
        object
            .keys()
            .all(|key| ["jsonrpc", "id", "result", "error"].contains(&key.as_str()))
            && answer["jsonrpc"] == "2.0"
            && answer["id"] == id,
        "private RPC returned an invalid response envelope or mismatched request ID"
    );
    if let Some(error) = object.get("error").filter(|error| !error.is_null()) {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .context("private RPC returned an invalid error response")?;
        ensure!(
            error.get("message").is_some_and(Value::is_string) && answer["result"].is_null(),
            "private RPC returned an invalid error response"
        );
        return Ok((
            status,
            RpcReply::Error {
                code,
                data: answer
                    .get_mut("error")
                    .and_then(Value::as_object_mut)
                    .and_then(|error| error.remove("data")),
            },
        ));
    }
    let value = answer
        .as_object_mut()
        .and_then(|object| object.remove("result"))
        .context("private RPC response has no result")?;
    Ok((status, RpcReply::Result(value)))
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.connect_with")
)]
fn connect_with(
    args: ConnectionArgs,
    json_output: bool,
    command: Option<Vec<std::ffi::OsString>>,
    mut events: Option<&mut ExecEvents>,
) -> Result<Option<zdn::connections::ExecStatus>> {
    use zdn::connections;
    let scoped = command.is_some();
    // Capture the caller's environment before preparing any AWS bridge. The
    // workload keeps its cwd and never inherits bridge-only credentials/files.
    let child_spec = command
        .map(|mut args| -> Result<zdn::pulumi::CommandSpec> {
            ensure!(!args.is_empty(), "select a command after --");
            let name = args.remove(0);
            let environment = zdn::credentials::environment()?;
            let path = Path::new(&name);
            let program = if path.is_absolute() || path.components().count() > 1 {
                std::path::absolute(path).context("cannot resolve scoped command path")?
            } else {
                executable(&name, &environment)?
            };
            ensure!(
                program.is_file()
                    && nix::unistd::access(&program, nix::unistd::AccessFlags::X_OK).is_ok(),
                "scoped command is not executable"
            );
            let cwd = std::env::current_dir()?;
            let mut env: BTreeMap<_, _> = std::env::vars_os().collect();
            for key in [
                "ZDN_RPC_URL",
                "ZDN_LIGHTWALLET_GRPC_URL",
                "ZDN_NETWORK_ID",
                "ZDN_CONSENSUS_FINGERPRINT",
            ] {
                env.remove(std::ffi::OsStr::new(key));
            }
            Ok(zdn::pulumi::CommandSpec {
                label: "scoped-command".into(),
                program,
                args,
                env,
                diagnostics_dir: cwd.clone(),
                cwd,
                limits: zdn::pulumi::ProcessLimits {
                    timeout: Duration::from_secs(24 * 60 * 60),
                    shutdown_grace: Duration::from_secs(5),
                    ..Default::default()
                },
            })
        })
        .transpose()?;
    let connection = prepare_connection(args, None)?;
    let endpoints = &connection.endpoints;
    if let Some(events) = &mut events {
        events.network_id = Some(endpoints.network_id);
    }
    let ready = |local: &[connections::LocalEndpoint]| {
        connection.verify(local)?;
        if let Some(mut child) = child_spec {
            child.env.insert(
                "ZDN_NETWORK_ID".into(),
                endpoints.network_id.to_string().into(),
            );
            child.env.insert(
                "ZDN_CONSENSUS_FINGERPRINT".into(),
                endpoints.consensus_fingerprint.clone().into(),
            );
            for endpoint in local {
                let key = match endpoints.targets[endpoint.target_index].service {
                    Service::NodeRpc => "ZDN_RPC_URL",
                    Service::LightwalletGrpc => "ZDN_LIGHTWALLET_GRPC_URL",
                };
                child
                    .env
                    .insert(key.into(), format!("http://{}", endpoint.address).into());
            }
            return Ok(Some(child));
        }
        let services: Vec<_> = local.iter().map(|p| {
            let service = endpoints.targets[p.target_index].service;
            json!({"service":service.name(),"endpoint":format!("http://{}",p.address),"authentication":"AWS Session Manager","tls":false})
        }).collect();
        if json_output {
            print_json(
                &json!({"networkId":endpoints.network_id,"consensusFingerprint":endpoints.consensus_fingerprint,"services":services,"lightwalletEnabled":endpoints.target(Service::LightwalletGrpc).is_some(),"paymentQualified":false}),
            )?;
        } else {
            println!("Connected to {}", endpoints.network_id);
            for service in &services {
                println!(
                    "{}: {}",
                    service["service"].as_str().unwrap(),
                    service["endpoint"].as_str().unwrap()
                );
            }
            if endpoints.target(Service::LightwalletGrpc).is_none() {
                println!("lightwallet gRPC: disabled");
            }
            println!("Keep this command running. Ctrl-C closes the connections; the devnet keeps running.");
        }
        io::stdout().flush()?;
        Ok(None)
    };
    if scoped {
        connections::exec_with_progress(
            &connection.options,
            &connection.targets,
            &connection.cancelled,
            |local| ready(local)?.context("scoped command is missing"),
            &mut |event| {
                if let Some(events) = &mut events {
                    events.write(
                        match event {
                            connections::ExecEvent::ConnectionReady => "connection-ready",
                            connections::ExecEvent::ChildStarted => "child-started",
                        },
                        "running",
                        Value::Null,
                    )?;
                }
                Ok(())
            },
        )
        .map(Some)
    } else {
        connections::run(
            &connection.options,
            &connection.targets,
            &connection.cancelled,
            |local| ready(local).map(|_| ()),
        )
        .map(|_| None)
    }
}

#[cfg(unix)]
struct PreparedConnection {
    options: zdn::connections::ConnectOptions,
    targets: Vec<zdn::connections::TunnelTarget>,
    endpoints: EndpointFile,
    cancelled: Arc<AtomicBool>,
    // Tunnel credential-process files must outlive every session and cleanup.
    _bridge: tempfile::TempDir,
}

#[cfg(unix)]
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.prepare_connection")
)]
fn prepare_connection(
    args: ConnectionArgs,
    expected_identity: Option<&EndpointFile>,
) -> Result<PreparedConnection> {
    use zdn::connections::{self, ConnectOptions, TunnelTarget};
    // Parse and validate all user files before creating a bridge or invoking AWS.
    let (deployment, endpoints) = args.selected()?;
    if let Some(expected) = expected_identity {
        ensure!(
            endpoints == *expected,
            "wallet endpoint identity changed after local selection"
        );
    }
    ensure!(
        args.grpc_port.is_none() || endpoints.target(Service::LightwalletGrpc).is_some(),
        "lightwallet gRPC is disabled for this devnet"
    );
    ensure!(
        args.rpc_port.is_none() || args.rpc_port != args.grpc_port,
        "RPC and gRPC local ports must differ"
    );
    let selection = AwsSelection {
        profile: args
            .aws_profile
            .or_else(|| deployment.as_ref().map(|d| d.spec.aws_profile.clone()))
            .context("endpoint files require --aws-profile")?,
        account_id: endpoints.scope.account_id.clone(),
        region: endpoints.scope.region.clone(),
    };
    let mut environment = zdn::credentials::environment()?;
    selection.validate_environment(&environment)?;
    normalize_connection_paths(&mut environment)?;
    let aws_program = executable("aws", &environment)?;
    let plugin_program = executable("session-manager-plugin", &environment)
        .context("install the AWS Session Manager plugin before connecting")?;
    connections::verify_plugin(&plugin_program, &environment)?;
    let bridge = tempfile::Builder::new()
        .prefix("zdn-connect-identity-")
        .tempdir()?;
    if let Some(deployment) = &deployment {
        let directory = fs::canonicalize(bridge.path())?;
        if let Some(files) = zdn::credentials::prepare(
            &deployment.team,
            &selection,
            &directory,
            &std::env::current_exe()?,
            &environment,
        )? {
            zdn::credentials::apply_files(&mut environment, &files)?;
        }
    }
    let api = AwsCli::with_environment(selection.clone(), &aws_program, environment.clone())?
        .expect_role(
            deployment
                .as_ref()
                .and_then(|d| d.team.deployment.as_ref().map(|a| a.role_arn.clone())),
        )?;
    api.verify_cli_version()?;
    api.verify_identity()?;
    endpoints.validate_live_documents(&api)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
    environment.retain(|key, _| {
        !key.starts_with("AWS_")
            || [
                "AWS_CONFIG_FILE",
                "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_CA_BUNDLE",
            ]
            .contains(&key.as_str())
    });
    for (key, value) in [
        ("AWS_PROFILE", selection.profile.as_str()),
        ("AWS_REGION", selection.region.as_str()),
        ("AWS_DEFAULT_REGION", selection.region.as_str()),
        ("AWS_SDK_LOAD_CONFIG", "1"),
        ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ] {
        environment.insert(key.into(), value.into());
    }
    let targets = endpoints
        .targets
        .iter()
        .map(|target| TunnelTarget {
            instance_id: target.instance_id.clone(),
            document_name: endpoints.document_name(target.service),
            remote_port: target.service.remote_port(),
            local_port: match target.service {
                Service::NodeRpc => args.rpc_port,
                Service::LightwalletGrpc => args.grpc_port,
            },
        })
        .collect::<Vec<_>>();
    let options = ConnectOptions {
        aws_program,
        helper_program: std::env::current_exe()?,
        env: environment,
        profile: selection.profile,
        region: selection.region,
        startup_timeout: Duration::from_secs(args.startup_timeout_secs),
        shutdown_grace: Duration::from_secs(5),
    };
    Ok(PreparedConnection {
        options,
        targets,
        endpoints,
        cancelled,
        _bridge: bridge,
    })
}

/// Keep collection, the optional backend scan, and the final tip observation in
/// one verified session. Return nothing until liveness and cleanup also succeed.
/// Consumers may take the temporary payload file but must retain the pinned tip, digest
/// and anchor for the final observation.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.with_wallet_history")
)]
pub fn with_wallet_history<T>(
    args: WalletHistoryArgs,
    expected_identity: Option<EndpointFile>,
    classify: bool,
    consume: impl FnOnce(
        &mut super::wallet_cli::history::History,
        Option<&super::wallet_cli::mempool::Mempool>,
    ) -> Result<T>,
) -> Result<(T, Value)> {
    use super::wallet_cli::{history, mempool};
    with_wallet_rpc(args, expected_identity, |manifest, identity, rpc| {
        let mut history = if classify {
            history::collect_current(manifest, &mut |m, p| rpc.read(m, p))?
        } else {
            history::collect(manifest, &mut |m, p| rpc.read(m, p))?
        };
        let mempool = if classify {
            ensure!(
                history.observe(&mut |m, p| rpc.read(m, p))?["scan_lag_blocks"] == 0,
                "chain tip changed; retry with a new classified snapshot"
            );
            Some(mempool::collect(&mut |m, p| rpc.read(m, p))?)
        } else {
            None
        };
        let value = consume(&mut history, mempool.as_ref())?;
        if let Some(mempool) = &mempool {
            mempool.recheck(&mut |m, p| rpc.read(m, p))?;
        }
        let mut observation = history.observe(&mut |m, p| rpc.read(m, p))?;
        if classify {
            ensure!(
                observation["scan_lag_blocks"] == 0,
                "chain tip changed; retry with a new classified snapshot"
            );
            observation["mempool_snapshot_rechecked"] = json!(true);
            observation["local_reservations_checked"] = json!(false);
        }
        observation["network_id"] = json!(identity.network_id);
        observation["consensus_fingerprint"] = json!(identity.consensus_fingerprint);
        Ok((value, observation))
    })
}

/// One identity-checked private session for snapshot, payment and recovery work.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.with_wallet_rpc")
)]
pub(super) fn with_wallet_rpc<T>(
    args: WalletHistoryArgs,
    expected_identity: Option<EndpointFile>,
    consume: impl FnOnce(&ConsensusManifest, &EndpointFile, &mut WalletRpc<'_>) -> Result<T>,
) -> Result<T> {
    let (manifest, identity) = args.selection()?;
    ensure!(
        expected_identity
            .as_ref()
            .is_none_or(|expected| expected == &identity),
        "named wallet endpoint identity changed after local selection"
    );
    let connection = prepare_connection(args.connection, Some(&identity))?;
    zdn::connections::once(
        &connection.options,
        &connection.targets,
        &connection.cancelled,
        |local| {
            let address = connection.verify(local)?;
            let mut rpc = WalletRpc {
                address,
                started: std::time::Instant::now(),
                cancelled: &connection.cancelled,
            };
            consume(&manifest, &identity, &mut rpc)
        },
    )
}

pub(super) struct WalletRpc<'a> {
    address: std::net::SocketAddr,
    started: std::time::Instant,
    cancelled: &'a AtomicBool,
}

impl WalletRpc<'_> {
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.wallet_rpc.check")
    )]
    pub(super) fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(WalletRpcError::Cancelled.into());
        }
        if self.started.elapsed() >= Duration::from_secs(300) {
            return Err(WalletRpcError::BudgetExceeded.into());
        }
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.wallet_rpc.read")
    )]
    pub fn read(&mut self, method: &str, params: Value) -> Result<Value> {
        self.check()?;
        ensure!(
            READ_ONLY_RPC_METHODS.contains(&method)
                && zdn::client_gateway::ALLOWED_METHODS.contains(&method),
            "wallet requires a read-only RPC method"
        );
        let request = serde_json::to_string(
            &json!({"jsonrpc":"2.0","id":"zdn-read","method":method,"params":params}),
        )?;
        let result = read_rpc(self.address, &request).map_err(|error| {
            if error.downcast_ref::<WalletRpcError>().is_some() {
                error
            } else {
                error.wrap_err(WalletRpcError::InvalidResponse)
            }
        })?;
        self.check()?;
        Ok(result)
    }

    /// Only the node's explicit -5 means absent; a failed read is never absence.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.wallet_rpc.transaction")
    )]
    pub fn transaction(&mut self, txid: &str) -> Result<Option<Value>> {
        self.check()?;
        ensure!(
            super::wallet_cli::hex_bytes(txid, 32),
            "invalid transaction ID"
        );
        let request = serde_json::to_string(
            &json!({"jsonrpc":"2.0","id":"zdn-read","method":"getrawtransaction","params":[txid,1]}),
        )?;
        let result = match request_rpc(self.address, &request, "zdn-read")? {
            (200, RpcReply::Result(value)) => Some(value),
            (200, RpcReply::Error { code: -5, data })
                if data.as_ref().is_none_or(Value::is_null) =>
            {
                None
            }
            _ => bail!("transaction observation failed; absence is unknown"),
        };
        self.check()?;
        Ok(result)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.wallet_rpc.submit")
    )]
    pub fn submit(&mut self, raw: &str) -> Result<SubmissionOutcome> {
        self.check()?;
        ensure!(
            !raw.is_empty()
                && raw.len().is_multiple_of(2)
                && raw.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid signed transaction bytes"
        );
        let request = serde_json::to_string(
            &json!({"jsonrpc":"2.0","id":"zdn-submit","method":"sendrawtransaction","params":[raw]}),
        )?;
        ensure!(
            request.len() <= MAX_RPC_BYTES,
            "submission request exceeds its size limit"
        );
        submit_rpc(self.address, &request)
    }
}

#[cfg(unix)]
impl PreparedConnection {
    /// A readiness observation is not a durable operation or payment qualification.
    /// Output failure or cancellation here must prevent the following RPC write.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.report_ready")
    )]
    fn report_ready(&self, format: cli_output::Format, command: &str) -> Result<()> {
        if format == cli_output::Format::Jsonl {
            let services: Vec<_> = self
                .endpoints
                .targets
                .iter()
                .map(|target| target.service.name())
                .collect();
            let mut record = cli_output::event(
                Some(command),
                "connection-ready",
                "observed",
                json!({
                    "consensusFingerprint": self.endpoints.consensus_fingerprint,
                    "services": services, "paymentQualified": false
                }),
            );
            record["networkId"] = json!(self.endpoints.network_id);
            cli_output::write(format, &record)?;
        }
        ensure!(
            !self.cancelled.load(Ordering::SeqCst),
            "connection cancelled before RPC dispatch"
        );
        Ok(())
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "connect_cli.verify_connection")
    )]
    fn verify(&self, local: &[zdn::connections::LocalEndpoint]) -> Result<std::net::SocketAddr> {
        let endpoints = &self.endpoints;
        let rpc = local
            .iter()
            .find(|p| endpoints.targets[p.target_index].service == Service::NodeRpc)
            .context("missing node RPC tunnel")?;
        check_service_identity(endpoints, rpc.address)?;
        if let Some(grpc) = local
            .iter()
            .find(|p| endpoints.targets[p.target_index].service == Service::LightwalletGrpc)
        {
            use zdn::lightwallet::LightwalletRpc;
            let wallet = zdn::lightwallet::GrpcLightwalletRpc::new(&grpc.address.to_string())?;
            let block = wallet
                .latest_block(Duration::from_secs(10))
                .context("lightwallet gRPC is not ready")?;
            ensure!(
                block.hash.len() == 32,
                "lightwallet returned an invalid block identity"
            );
            let body = request_json(
                rpc.address,
                "",
                Some(
                    json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[block.height]}),
                ),
            )?;
            let mut bytes = block.hash;
            bytes.reverse();
            ensure!(
                body["result"] == hex::encode(bytes),
                "lightwallet and node RPC do not agree on the observed chain"
            );
        }
        ensure!(
            !self.cancelled.load(Ordering::SeqCst),
            "connection cancelled before readiness"
        );
        Ok(rpc.address)
    }
}

/// AWS preflight runs in the caller's directory, but session subprocesses use a
/// private temporary directory. Keep all selected file and executable paths
/// referring to the same locations without requiring optional files to exist.
#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.normalize_connection_paths")
)]
fn normalize_connection_paths(environment: &mut BTreeMap<String, String>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    for key in [
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CA_BUNDLE",
    ] {
        if let Some(value) = environment.get_mut(key) {
            if !value.is_empty() && !value.starts_with('~') && Path::new(value).is_relative() {
                *value = cwd
                    .join(&*value)
                    .to_str()
                    .context("non-UTF-8 AWS configuration path")?
                    .into();
            }
        }
    }
    if let Some(value) = environment.get_mut("PATH") {
        let paths = std::env::split_paths(value).map(|path| {
            if path.is_relative() {
                cwd.join(path)
            } else {
                path
            }
        });
        *value = std::env::join_paths(paths)?
            .into_string()
            .map_err(|_| eyre::eyre!("non-UTF-8 executable search path"))?;
    }
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.executable")
)]
fn executable(
    name: impl AsRef<std::ffi::OsStr>,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf> {
    let name = name.as_ref();
    let paths = env.get("PATH").context("PATH is unavailable")?;
    std::env::split_paths(paths)
        .map(|p| p.join(name))
        .find(|p| {
            if !p.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                nix::unistd::access(p, nix::unistd::AccessFlags::X_OK).is_ok()
            }
            #[cfg(not(unix))]
            {
                true
            }
        })
        .map(std::path::absolute)
        .transpose()?
        .with_context(|| {
            format!(
                "{} is not installed or is not on PATH",
                name.to_string_lossy()
            )
        })
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.request_json")
)]
fn request_json(address: std::net::SocketAddr, path: &str, body: Option<Value>) -> Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(Duration::from_secs(10))
        .build();
    let url = format!("http://{address}/{path}");
    let result = match body {
        Some(body) => agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string()),
        None => agent.get(&url).call(),
    }
    .map_err(|_| eyre::eyre!("private node RPC did not answer its readiness request"))?;
    let mut bytes = Vec::new();
    result
        .into_reader()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "private RPC readiness response exceeds its limit"
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| eyre::eyre!("private RPC returned invalid readiness JSON"))
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.check_service_identity")
)]
fn check_service_identity(endpoints: &EndpointFile, address: std::net::SocketAddr) -> Result<()> {
    let value = request_json(address, "health", None)?;
    ensure!(
        value["apiVersion"] == zdn::client_gateway::OBSERVATION_API_VERSION
            && value["deploymentId"] == endpoints.network_id.to_string()
            && value["nodeId"] == "node-1"
            && value["consensusFingerprint"] == endpoints.consensus_fingerprint
            && value["status"] == "ready",
        "private RPC gateway does not match the selected devnet or is not ready"
    );
    Ok(())
}

#[derive(Args)]
pub struct ParticipantArgs {
    /// Operator-owned team definition for the administrator state backend.
    #[arg(long)]
    from: PathBuf,
    /// Reviewed endpoint JSON for the exact devnet; never credentials or deletion ownership.
    #[arg(long)]
    endpoints: PathBuf,
    /// Authenticated administrator AWS CLI source profile permitted to manage participant IAM grants.
    #[arg(long)]
    aws_profile: String,
    /// Exact IAM user or role ARN allowed to assume the participant role.
    #[arg(long = "trust-principal", required = true)]
    trusted_principals: Vec<String>,
    #[command(flatten)]
    store: StoreArgs,
    #[command(flatten)]
    managed: ManagedArgs,
    /// Print the proposed role and policy without changing local or cloud state.
    #[arg(long, conflicts_with_all = ["yes", "reconcile"])]
    plan: bool,
    /// Refresh the participant stack before retrying an uncertain operation.
    #[arg(long)]
    reconcile: bool,
    /// Explicit consent to create the restricted participant role; inspect --plan first.
    #[arg(long)]
    yes: bool,
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "connect_cli.participant")
)]
pub fn participant(args: ParticipantArgs) -> Result<()> {
    let team = zdn::aws::TeamDefinition::load(&args.from)?;
    let request = zdn::participant::ParticipantRequest {
        administrator: AwsSelection {
            profile: args.aws_profile,
            account_id: team.aws.account_id.clone(),
            region: team.aws.region.clone(),
        },
        team,
        endpoints: EndpointFile::load(&args.endpoints)?,
        trusted_principals: args.trusted_principals,
    }
    .normalized()?;
    let session_names = request
        .endpoints
        .participant_session_names(&request.trusted_principals)?;
    if args.plan {
        return print_json(
            &json!({"roleArn":request.endpoints.participant_role_arn(),"roleSessionNames":session_names,"pulumiYaml":serde_yaml::to_string(&request.render()?)?,"cloudChanges":false}),
        );
    }
    ensure!(
        args.yes,
        "participant setup creates a restricted AWS role; inspect --plan or pass --yes"
    );
    let api = AwsCli::new(request.administrator.clone())?;
    api.verify_cli_version()?;
    api.verify_identity()?;
    let managed = data_path(args.managed.managed_dir, "tools")?;
    zdn::pulumi::ManagedTools::resolve(&managed)?;
    let store = open_store(args.store)?;
    let directory = zdn::participant::receipt_directory(&store, &request)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
    let mut stack = zdn::participant::live_stack(&request, &directory, &managed, cancel)?;
    let role = zdn::participant::provision(&api, &request, &directory, &mut stack, args.reconcile)?;
    print_json(
        &json!({"networkId":request.endpoints.network_id,"participantRoleArn":role,"roleSessionNames":session_names,"receiptDirectory":directory,"stateAccessGranted":false,"deploymentAccessGranted":false}),
    )
}
