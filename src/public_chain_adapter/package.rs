//! Structural offline public-package inspection. This never executes an adapter,
//! downloads tools, consults wallets, or authorizes host/cloud operations.
use super::{
    contract::{self, CompileInput, Descriptor, Pin},
    valid_hash, Failure, PinnedResult, Result, TrustedExecutable, VerifiedExecutable,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicPackage {
    pub schema: String,
    pub source_url: String,
    pub source_revision: String,
    pub license: String,
    pub host_platform: String,
    pub host_adapter: TrustedExecutable,
    pub prepared_chain_source: Pin,
    pub prepared_profile_source: Pin,
    pub descriptor: Pin,
    pub native_rules: Pin,
    pub seed_bundle: Pin,
    pub wallet_profile: Pin,
    pub compiled_result: Pin,
}

/// Retained exact bytes from the fixed slots, not caller-selected runtime paths.
pub struct InspectedPackage {
    pub manifest: PublicPackage,
    pub input: CompileInput,
    pub bundle: Vec<u8>,
    pub compiled_result: Vec<u8>,
}

/// Explicit core-owned trust decision. Neither the package nor its executable
/// may choose these pins for the caller. Package digest alone is not approval
/// to execute arbitrary bundled software.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreTrust {
    pub package: Pin,
    pub adapter_selection_sha256: String,
    pub executable: Pin,
}

/// Freshly recompiled public input retained for one host/controller operation.
/// Private fields prevent substituting a merely deserialized compile result.
pub struct PreparedExternalChain {
    inspected: InspectedPackage,
    compiled: PinnedResult<contract::Compiled>,
    executable_path: PathBuf,
    sandbox: Option<crate::host::adapter_sandbox::Sandbox>,
}

impl PreparedExternalChain {
    /// Validate every fixed slot and explicit execution trust before running
    /// the pinned companion. Recompilation must reproduce exact result bytes.
    pub fn prepare(
        manifest_bytes: &[u8],
        directory: &Path,
        trust: &CoreTrust,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        Self::prepare_execution(manifest_bytes, directory, trust, deadline, cancelled, None)
    }

    /// Host-only: absence/failure of the fixed unprivileged sandbox is fatal.
    /// Every later render retains this execution policy; there is no fallback
    /// to the controller's same-UID trusted-process primitive.
    pub fn prepare_isolated(
        manifest_bytes: &[u8],
        directory: &Path,
        trust: &CoreTrust,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self> {
        let sandbox =
            crate::host::adapter_sandbox::Sandbox::discover().map_err(|_| Failure::Unavailable)?;
        Self::prepare_execution(
            manifest_bytes,
            directory,
            trust,
            deadline,
            cancelled,
            Some(sandbox),
        )
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.package.prepare")
    )]
    fn prepare_execution(
        manifest_bytes: &[u8],
        directory: &Path,
        trust: &CoreTrust,
        deadline: Instant,
        cancelled: &AtomicBool,
        sandbox: Option<crate::host::adapter_sandbox::Sandbox>,
    ) -> Result<Self> {
        if !directory.is_absolute() || !valid_hash(&trust.adapter_selection_sha256) {
            return Err(Failure::InvalidPublicInput);
        }
        let inspected = PublicPackage::inspect(manifest_bytes, &trust.package, directory)?;
        let selection = &inspected.manifest.host_adapter;
        if selection.adapter_selection_sha256 != trust.adapter_selection_sha256
            || selection.executable_sha256 != trust.executable.sha256
            || selection.executable_bytes != trust.executable.bytes
        {
            return Err(Failure::Incompatible);
        }
        let executable_path = directory.join("host-adapter");
        let mut executable = VerifiedExecutable::verify(&executable_path, selection.clone())?;
        if let Some(sandbox) = &sandbox {
            executable = executable.with_sandbox(sandbox.clone());
        }
        let compiled =
            executable.compile(&inspected.input, &inspected.bundle, deadline, cancelled)?;
        if compiled.bytes() != inspected.compiled_result {
            return Err(Failure::InvalidOutput);
        }
        Ok(Self {
            inspected,
            compiled,
            executable_path,
            sandbox,
        })
    }

    pub fn compiled(&self) -> &contract::Compiled {
        self.compiled.value()
    }

    pub fn requirements(&self) -> Result<crate::image::ImageBuildRequirements> {
        self.compiled().image_requirements()
    }

    /// Controller render only after a complete, pinned, same-chain inventory.
    /// Recovery supplies the existing evidence pin, never an unpinned reread.
    pub fn render_with_inventory(
        &self,
        mut options: contract::RenderOptions,
        inventory: &crate::native_peers::NativeInventory,
        inventory_pin: &Pin,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> eyre::Result<PinnedResult<contract::Rendered>> {
        eyre::ensure!(
            inventory.pin()? == *inventory_pin,
            "native inventory evidence pin differs"
        );
        inventory.require_chain(
            &self.inspected.manifest.descriptor.sha256,
            &self.compiled().native_fingerprint,
        )?;
        inventory.bind_render_options(&mut options)?;
        Ok(self.render(options, deadline, cancelled)?)
    }

    /// Core envelope validation runs inside render before any saved-byte
    /// comparison. Call on install, update and recovery before effects.
    pub fn render(
        &self,
        options: contract::RenderOptions,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PinnedResult<contract::Rendered>> {
        self.render_mode(options, false, deadline, cancelled)
    }

    /// Provision native public identity without publishing a runtime config.
    /// Only an empty-key, peerless follower selection is admitted here.
    pub fn render_identity(
        &self,
        options: contract::RenderOptions,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PinnedResult<contract::Rendered>> {
        self.render_mode(options, true, deadline, cancelled)
    }

    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.package.render")
    )]
    fn render_mode(
        &self,
        options: contract::RenderOptions,
        identity_only: bool,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<PinnedResult<contract::Rendered>> {
        let mut executable = VerifiedExecutable::verify(
            &self.executable_path,
            self.inspected.manifest.host_adapter.clone(),
        )?;
        if let Some(sandbox) = &self.sandbox {
            executable = executable.with_sandbox(sandbox.clone());
        }
        executable.render(
            &contract::RenderInput {
                public: self.inspected.input.clone(),
                compiled_sha256: self.compiled.pin().sha256.clone(),
                options,
                identity_only,
            },
            &self.inspected.bundle,
            &self.compiled,
            deadline,
            cancelled,
        )
    }

    pub fn verify_rules(
        &self,
        rpc: &impl crate::chain::rpc::NodeRpc,
        timeout: Duration,
    ) -> eyre::Result<()> {
        crate::chain::readiness::PreparedRules::external(self.compiled())
            .verify(rpc, || Ok(timeout))
            .map(|_| ())
    }

    /// Wait through startup cookie creation/rotation and retain the client that
    /// authenticated the verified rules, not credentials captured before startup.
    pub fn wait_for_rpc(
        &self,
        endpoint: &str,
        cookie: &Path,
        clock: &impl crate::chain::rpc::Clock,
        timeout: Duration,
        deadline: Duration,
    ) -> eyre::Result<crate::chain::rpc::HttpNodeRpc> {
        crate::chain::startup::wait_external(
            self.compiled(),
            endpoint,
            cookie,
            clock,
            timeout,
            deadline,
        )
    }

    pub fn readiness(
        &self,
        rpc: &impl crate::chain::rpc::NodeRpc,
        clock: &impl crate::chain::rpc::Clock,
        options: &crate::chain::readiness::ReadinessOptions,
    ) -> eyre::Result<crate::chain::readiness::ReadinessReport> {
        let start = clock.elapsed();
        crate::chain::readiness::PreparedReadiness::external(self.compiled())
            .check(rpc, clock, options, start)
    }

    pub fn bootstrap(
        &self,
        rpc: &impl crate::chain::rpc::NodeRpc,
        clock: &impl crate::chain::rpc::Clock,
        options: &crate::chain::bootstrap::BootstrapOptions,
    ) -> eyre::Result<crate::chain::bootstrap::BootstrapReport> {
        use crate::chain::{
            artifacts::{ArtifactReport, VerifiedBlock, VerifiedBundle},
            manifest::BlockIdentity,
        };
        let blocks = contract::bundle_blocks(&self.inspected.bundle)?
            .into_iter()
            .zip(&self.compiled().seed_blocks)
            .map(|(bytes, block)| VerifiedBlock {
                identity: BlockIdentity {
                    height: block.height,
                    hash: block.hash.clone(),
                    bytes_sha256: block.pin.sha256.clone(),
                    bytes_length: block.pin.bytes,
                },
                bytes: bytes.to_vec(),
            })
            .collect::<Vec<_>>();
        let report = ArtifactReport {
            api_version: crate::chain::artifacts::REPORT_API_VERSION.into(),
            consensus_fingerprint: self.compiled().native_fingerprint.clone(),
            bundle_sha256: self.inspected.input.seed_bundle.sha256.clone(),
            bundle_bytes: self.inspected.input.seed_bundle.bytes,
            block_count: blocks.len(),
            block_bytes: blocks.iter().map(|b| b.bytes.len() as u64).sum(),
            byte_integrity_verified: true,
            block_decoding_verified: false,
            consensus_verified: false,
            qualification: "pending".into(),
            launch_ready: false,
        };
        crate::chain::bootstrap::load_external(
            VerifiedBundle { report, blocks },
            self.compiled(),
            rpc,
            clock,
            options,
        )
    }

    /// Reuses the existing lock/journal/uncertain-generation reconciliation.
    pub fn produce(
        &self,
        rpc: &impl crate::chain::rpc::NodeRpc,
        clock: &impl crate::chain::rpc::Clock,
        options: &crate::chain::producer::ProducerOptions,
        cancelled: &AtomicBool,
    ) -> eyre::Result<crate::chain::producer::ProducerReport> {
        crate::chain::producer::run_external(self.compiled(), rpc, clock, options, cancelled)
    }
}

impl PublicPackage {
    /// Structural identity only: does not open any slot or require an installed
    /// companion. Suitable for offline ownership inspection, not authorization.
    pub fn from_json(bytes: &[u8], pin: &Pin) -> Result<Self> {
        if bytes.len() > contract::MAX_METADATA {
            return Err(Failure::InvalidPublicInput);
        }
        pin.check(bytes)?;
        let manifest: Self = contract::parse(bytes)?;
        if manifest.schema != "zdn-external-package/v1"
            || manifest.host_platform != "linux/amd64"
            || !manifest.source_url.starts_with("https://")
            || manifest.source_url.len() > 1024
            || manifest.source_revision.len() != 40
            || !manifest
                .source_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || manifest.license.is_empty()
            || manifest.license.len() > 128
            || !valid_hash(&manifest.host_adapter.adapter_selection_sha256)
        {
            return Err(Failure::InvalidPublicInput);
        }
        for (pin, limit) in [
            (&manifest.prepared_chain_source, contract::MAX_BUNDLE as u64),
            (
                &manifest.prepared_profile_source,
                contract::MAX_METADATA as u64,
            ),
            (&manifest.descriptor, contract::MAX_METADATA as u64),
            (&manifest.native_rules, contract::MAX_METADATA as u64),
            (&manifest.wallet_profile, contract::MAX_METADATA as u64),
            (&manifest.seed_bundle, contract::MAX_BUNDLE as u64),
            (&manifest.compiled_result, 4 * 1024 * 1024),
        ] {
            if pin.bytes == 0 || pin.bytes > limit || !valid_hash(&pin.sha256) {
                return Err(Failure::InvalidPublicInput);
            }
        }
        Ok(manifest)
    }

    /// Reads only six flat public slots; never traverses/uploads a directory.
    /// The manifest digest identifies bytes, not a trusted publisher or signer.
    #[cfg_attr(
        feature = "profiling",
        tracing::instrument(skip_all, name = "adapter.package.inspect")
    )]
    pub fn inspect(bytes: &[u8], pin: &Pin, directory: &Path) -> Result<InspectedPackage> {
        let manifest = Self::from_json(bytes, pin)?;
        fn slot(root: &Path, name: &str, pin: &Pin, limit: u64) -> Result<Vec<u8>> {
            if pin.bytes == 0 || pin.bytes > limit {
                return Err(Failure::InvalidPublicInput);
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(root.join(name))
                .map_err(|_| Failure::Unavailable)?;
            if !file.metadata().map_err(|_| Failure::Unavailable)?.is_file() {
                return Err(Failure::InvalidPublicInput);
            }
            let mut bytes = vec![];
            file.take(pin.bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Failure::Unavailable)?;
            pin.check(&bytes)?;
            Ok(bytes)
        }
        let descriptor_bytes = slot(
            directory,
            "descriptor.json",
            &manifest.descriptor,
            contract::MAX_METADATA as u64,
        )?;
        let descriptor: Descriptor = contract::parse(&descriptor_bytes)?;
        if serde_json::to_vec(&descriptor).map_err(|_| Failure::InvalidPublicInput)?
            != descriptor_bytes
        {
            return Err(Failure::InvalidPublicInput);
        }
        let rules = slot(
            directory,
            "native-rules.json",
            &manifest.native_rules,
            contract::MAX_METADATA as u64,
        )?;
        let profile = slot(
            directory,
            "wallet-profile.json",
            &manifest.wallet_profile,
            contract::MAX_METADATA as u64,
        )?;
        let bundle = slot(
            directory,
            "seed-blocks.bin",
            &manifest.seed_bundle,
            contract::MAX_BUNDLE as u64,
        )?;
        let host_pin = Pin {
            bytes: manifest.host_adapter.executable_bytes,
            sha256: manifest.host_adapter.executable_sha256.clone(),
        };
        // Inspection authenticates this slot but never consumes its bytes.
        // Execution takes its own fresh, hash-bound private snapshot.
        slot(directory, "host-adapter", &host_pin, 128 * 1024 * 1024)?;
        let compiled_result = slot(
            directory,
            "compiled.json",
            &manifest.compiled_result,
            4 * 1024 * 1024,
        )?;
        let input = CompileInput {
            descriptor,
            native_rules_json: String::from_utf8(rules).map_err(|_| Failure::InvalidPublicInput)?,
            wallet_profile_json: String::from_utf8(profile)
                .map_err(|_| Failure::InvalidPublicInput)?,
            seed_bundle: manifest.seed_bundle.clone(),
        };
        let blocks = input.validate(&bundle)?;
        let compiled: contract::Compiled = contract::parse(&compiled_result)?;
        if serde_json::to_vec(&compiled).map_err(|_| Failure::InvalidPublicInput)?
            != compiled_result
        {
            return Err(Failure::InvalidPublicInput);
        }
        compiled.validate(&input, &blocks)?;
        Ok(InspectedPackage {
            manifest,
            input,
            bundle,
            compiled_result,
        })
    }

    /// Deliberate migration barrier: offline inspection is not deployment support.
    /// Cleanup/inspection need no companion; operational gates are still pending.
    pub fn require_operational(&self) -> Result<()> {
        Err(Failure::Incompatible)
    }
}
