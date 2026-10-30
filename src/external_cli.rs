//! Explicit controller commands for the versioned external branch. These do not
//! execute ordinary chain commands, select a wallet, or make cloud mutations.
use clap::{Args, Subcommand};
use eyre::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use zdn::{
    devnet::external::{self, ExternalRequest},
    public_chain_adapter::{
        contract::{self, Pin, RenderOptions},
        package::{CoreTrust, PreparedExternalChain, PublicPackage},
    },
};

#[derive(Args)]
pub struct PublicInput {
    /// Absolute directory containing only fixed public package inputs.
    #[arg(long)]
    public_directory: PathBuf,
    /// Explicit core trust JSON: package/executable pins and selection SHA256.
    #[arg(long)]
    trust: PathBuf,
}

#[derive(Subcommand)]
pub enum Command {
    /// Render a pinned qualification request without dispatching it or contacting AWS.
    #[cfg(target_os = "linux")]
    ControlScript {
        /// Canonical original host runtime manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Canonical, single-use qualification request; pins the effective runtime.
        #[arg(long)]
        request: PathBuf,
        /// New script file; never overwritten or automatically executed.
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect exact public bytes without executing or requiring a companion.
    Inspect(PublicInput),
    /// Recompile fixed public inputs with the explicitly trusted companion.
    Compile(PublicInput),
    /// Stage a new fixed-slot external node/image/helper artifact set offline.
    Stage {
        #[command(flatten)]
        public: PublicInput,
        /// Explicit external ZDN configuration with package and adapter pins.
        #[arg(long)]
        config: PathBuf,
        /// Requirement-bound node image record JSON.
        #[arg(long)]
        image_record: PathBuf,
        /// Exact OCI registry manifest bytes pinned by the image record.
        #[arg(long)]
        image_manifest: PathBuf,
        /// Exact OCI image configuration bytes pinned by the registry manifest.
        #[arg(long)]
        image_config: PathBuf,
        /// Pinned Linux ZDN host helper executable, not a node binary.
        #[arg(long)]
        host_helper: PathBuf,
        /// Optional completed feature-bound source-build contract.
        #[arg(long)]
        build_contract: Option<PathBuf>,
        /// New output directory; failed partial exports must not be reused.
        #[arg(long)]
        output: PathBuf,
    },
    /// Recompile and check all saved external artifact/image bytes offline.
    Verify {
        /// Immutable external-request.json file.
        #[arg(long)]
        request: PathBuf,
        /// Independently retained SHA256 of the exact request bytes.
        #[arg(long)]
        sha256: String,
        /// Absolute fixed-slot artifact directory.
        #[arg(long)]
        directory: PathBuf,
    },
    /// Freeze phase-one key provisioning without node startup or peer authority.
    IdentityManifest {
        /// Immutable external-request.json file.
        #[arg(long)]
        request: PathBuf,
        /// Independently retained SHA256 of the exact request bytes.
        #[arg(long)]
        sha256: String,
        /// Absolute fixed-slot artifact directory.
        #[arg(long)]
        directory: PathBuf,
        /// Immutable external volume ownership JSON, including exact request pin.
        #[arg(long)]
        provisioning: PathBuf,
        /// Fixed named authenticated S3 sources JSON.
        #[arg(long)]
        sources: PathBuf,
        /// Peerless follower options with empty expectedNodeId and no reward address.
        #[arg(long)]
        options: PathBuf,
        /// New phase-one manifest output file; never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Optional new authenticated host bootstrap script; renders only, never executes.
        #[arg(long)]
        bootstrap_output: Option<PathBuf>,
    },
    /// Freeze exact host delivery/runtime bytes after pinned cohort completion.
    HostManifest {
        /// Immutable external-request.json file.
        #[arg(long)]
        request: PathBuf,
        /// Independently retained SHA256 of the exact request bytes.
        #[arg(long)]
        sha256: String,
        /// Absolute fixed-slot artifact directory.
        #[arg(long)]
        directory: PathBuf,
        /// Fixed named authenticated S3 objects, not companion-selected paths.
        #[arg(long)]
        sources: PathBuf,
        /// Typed public render options JSON; native identities come from inventory.
        #[arg(long)]
        options: PathBuf,
        /// Authenticated native cohort metadata from saved deployment outputs.
        #[arg(long)]
        cohort: PathBuf,
        /// Existing private persistent native inventory directory.
        #[arg(long)]
        inventory_directory: PathBuf,
        /// Retained exact inventory byte-count and SHA256 pin JSON.
        #[arg(long)]
        inventory_pin: PathBuf,
        /// New immutable host manifest output file; never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Produce exact runtime bytes only from a complete pinned native inventory.
    Render {
        #[command(flatten)]
        public: PublicInput,
        /// Typed public render options JSON; native identities come from inventory.
        #[arg(long)]
        options: PathBuf,
        /// Authenticated cohort metadata from recorded deployment outputs.
        #[arg(long)]
        cohort: PathBuf,
        /// Existing private persistent native inventory directory.
        #[arg(long)]
        inventory_directory: PathBuf,
        /// Retained exact byte-count/SHA256 pin from lifecycle evidence.
        #[arg(long)]
        inventory_pin: PathBuf,
        /// New node TOML output file; never overwritten or automatically started.
        #[arg(long)]
        output: PathBuf,
    },
}

fn read<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    Ok(contract::parse(&zdn::devnet::read_bounded(
        path,
        4 * 1024 * 1024,
    )?)?)
}
fn public(input: &PublicInput) -> Result<(CoreTrust, Vec<u8>)> {
    ensure!(
        input.public_directory.is_absolute(),
        "public directory must be absolute"
    );
    let trust: CoreTrust = read(&input.trust)?;
    let bytes = zdn::devnet::read_bounded(
        &input.public_directory.join("package.json"),
        contract::MAX_METADATA as u64,
    )?;
    trust.package.check(&bytes)?;
    Ok((trust, bytes))
}

fn publish_new(output: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "external_cli.run")
)]
pub fn run(command: Command) -> Result<Value> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    match command {
        #[cfg(target_os = "linux")]
        Command::ControlScript {
            manifest,
            request,
            output,
        } => {
            use zdn::host::external::runtime::{self, qualification};
            let original = runtime::Manifest::from_slice(&zdn::devnet::read_bounded(
                &manifest,
                runtime::MAX_BYTES,
            )?)?;
            let request = qualification::Request::from_slice(&zdn::devnet::read_bounded(
                &request,
                qualification::MAX_REQUEST,
            )?)?;
            let script = request.render(&original)?;
            publish_new(&output, script.as_bytes())?;
            Ok(
                json!({"schema":qualification::SCHEMA,"request":Pin::of(&request.bytes()?),"script":Pin::of(script.as_bytes()),"dispatched":false}),
            )
        }
        Command::Inspect(input) => {
            let (trust, bytes) = public(&input)?;
            let inspected = PublicPackage::from_json(&bytes, &trust.package)?;
            Ok(
                json!({"schema":"zdn-external-inspection/v1","package":trust.package,
                "compiled":inspected.compiled_result,"executionAuthorized":false,"launchReady":false}),
            )
        }
        Command::Compile(input) => {
            let (trust, bytes) = public(&input)?;
            let prepared = PreparedExternalChain::prepare(
                &bytes,
                &input.public_directory,
                &trust,
                deadline,
                &cancelled,
            )?;
            let result = serde_json::to_vec(prepared.compiled())?;
            Ok(
                json!({"schema":"zdn-external-compile/v1","result":prepared.compiled(),"pin":Pin::of(&result),"launchReady":false}),
            )
        }
        Command::Stage {
            public: input,
            config,
            image_record,
            image_manifest,
            image_config,
            host_helper,
            build_contract,
            output,
        } => {
            let (trust, _) = public(&input)?;
            let config = zdn::config::Config::load(&config)?;
            let build = build_contract
                .as_deref()
                .map(read::<zdn::build::BuildContract>)
                .transpose()?;
            let request = external::stage(
                &config,
                &trust,
                &external::Paths {
                    public_directory: &input.public_directory,
                    image_record: &image_record,
                    image_manifest: &image_manifest,
                    image_config: &image_config,
                    helper: &host_helper,
                    build: build.as_ref(),
                },
                &output,
                deadline,
                &cancelled,
            )?;
            Ok(
                json!({"schema":external::SCHEMA,"request":Pin::of(&request.bytes()?),
                "nativeFingerprint":request.compiled.native_fingerprint,"launchReady":false}),
            )
        }
        Command::Verify {
            request,
            sha256,
            directory,
        } => {
            let bytes = zdn::devnet::read_bounded(&request, 4 * 1024 * 1024)?;
            ensure!(
                Pin::of(&bytes).sha256 == sha256,
                "external request pin differs"
            );
            let request = ExternalRequest::from_slice(&bytes)?;
            let prepared = request.prepare(&directory, deadline, &cancelled)?;
            Ok(
                json!({"schema":"zdn-external-verification/v1","nativeFingerprint":prepared.compiled().native_fingerprint,
                "request":Pin::of(&bytes),"launchReady":false}),
            )
        }
        Command::IdentityManifest {
            request,
            sha256,
            directory,
            provisioning,
            sources,
            options,
            output,
            bootstrap_output,
        } => {
            let bytes = zdn::devnet::read_bounded(&request, 4 * 1024 * 1024)?;
            ensure!(
                Pin::of(&bytes).sha256 == sha256,
                "external request pin differs"
            );
            let manifest = zdn::host::external::identity::Manifest::new(
                ExternalRequest::from_slice(&bytes)?,
                read(&provisioning)?,
                read(&sources)?,
                read(&options)?,
                &directory,
                deadline,
                &cancelled,
            )?;
            let bytes = manifest.bytes()?;
            let bootstrap = bootstrap_output
                .as_ref()
                .map(|_| zdn::host::runtime::bootstrap::render_external_identity(&manifest))
                .transpose()?;
            publish_new(&output, &bytes)?;
            if let (Some(path), Some(script)) = (&bootstrap_output, bootstrap) {
                publish_new(path, script.as_bytes())?;
            }
            Ok(
                json!({"schema":zdn::host::external::identity::SCHEMA,"manifest":Pin::of(&bytes),
                "servicesStarted":false,"launchReady":false}),
            )
        }
        Command::HostManifest {
            request,
            sha256,
            directory,
            sources,
            options,
            cohort,
            inventory_directory,
            inventory_pin,
            output,
        } => {
            let bytes = zdn::devnet::read_bounded(&request, 4 * 1024 * 1024)?;
            ensure!(
                Pin::of(&bytes).sha256 == sha256,
                "external request pin differs"
            );
            let request = ExternalRequest::from_slice(&bytes)?;
            let cohort: zdn::native_peers::NativeCohort = read(&cohort)?;
            let pin: Pin = read(&inventory_pin)?;
            let store = zdn::native_peers::NativeInventoryStore::open_existing(
                &inventory_directory,
                cohort,
            )?;
            let inventory = store.read_pinned(&pin)?;
            let manifest = request.host_manifest(
                &directory,
                read(&sources)?,
                read(&options)?,
                &inventory,
                &pin,
                deadline,
                &cancelled,
            )?;
            let bytes = manifest.bytes()?;
            publish_new(&output, &bytes)?;
            Ok(
                json!({"schema":zdn::host::external::SCHEMA,"manifest":Pin::of(&bytes),
                "inventory":pin,"servicesStarted":false,"launchReady":false}),
            )
        }
        Command::Render {
            public: input,
            options,
            cohort,
            inventory_directory,
            inventory_pin,
            output,
        } => {
            let (trust, bytes) = public(&input)?;
            let prepared = PreparedExternalChain::prepare(
                &bytes,
                &input.public_directory,
                &trust,
                deadline,
                &cancelled,
            )?;
            let options: RenderOptions = read(&options)?;
            let cohort: zdn::native_peers::NativeCohort = read(&cohort)?;
            let pin: Pin = read(&inventory_pin)?;
            let store = zdn::native_peers::NativeInventoryStore::open_existing(
                &inventory_directory,
                cohort,
            )?;
            let inventory = store.read_pinned(&pin)?;
            let rendered =
                prepared.render_with_inventory(options, &inventory, &pin, deadline, &cancelled)?;
            publish_new(&output, rendered.value().config_toml.as_bytes())?;
            Ok(
                json!({"schema":"zdn-external-render/v1","config":Pin::of(rendered.value().config_toml.as_bytes()),
                "result":rendered.pin(),"inventory":pin,"launchReady":false}),
            )
        }
    }
}
