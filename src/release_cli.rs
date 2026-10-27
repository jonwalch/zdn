//! Explicit-key release preparation and selection; never publishes externally.
use clap::{Args, Subcommand};
use eyre::{Context, Result};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zdn::{devnet::read_bounded, releases};

#[derive(Args)]
pub struct CatalogArgs {
    /// Local raw catalog JSON. Relative package paths use its containing directory.
    #[arg(long)]
    catalog: PathBuf,
    /// Detached 64-byte raw Ed25519 signature.
    #[arg(long)]
    signature: PathBuf,
    /// Explicitly trusted 32-byte raw Ed25519 public key; repeat for key rotation.
    #[arg(long, required = true)]
    trusted_key: Vec<PathBuf>,
}

#[derive(Subcommand)]
pub enum ReleaseCommand {
    /// Authenticate declarations only; does not fetch packages or qualify releases.
    Verify(CatalogArgs),
    /// Authenticate an exact release and export its verified package to a new local directory.
    Resolve {
        #[command(flatten)]
        catalog: CatalogArgs,
        /// Exact catalog release identifier, not a floating latest/channel selection; may resolve HTTPS artifacts.
        #[arg(long)]
        release: String,
        /// Existing parent must be caller-owned. No existing destination is replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign raw catalog declarations locally with an existing PKCS#8 Ed25519 key.
    Sign {
        /// Local raw catalog JSON bytes to sign; signing declarations does not qualify their artifacts.
        #[arg(long)]
        catalog: PathBuf,
        /// Existing private PKCS#8 file, never included in reports.
        #[arg(long)]
        key: PathBuf,
        /// New detached binary signature file. Existing paths are never replaced.
        #[arg(long)]
        output: PathBuf,
    },
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "release_cli.run")
)]
pub fn run(command: ReleaseCommand) -> Result<Value> {
    match command {
        ReleaseCommand::Verify(args) => {
            let verified = authenticate(&args)?;
            Ok(json!({"apiVersion":"zdn-release-verification/v1alpha1",
                "catalogSha256":verified.sha256(),"signer":hex::encode(verified.signer()),
                "releases":verified.catalog().releases.keys().collect::<Vec<_>>(),
                "publisherAuthenticated":true,"packagesVerified":false,
                "qualification":"pending","launchReady":false}))
        }
        ReleaseCommand::Resolve {
            catalog,
            release,
            output,
        } => {
            let verified = authenticate(&catalog)?;
            let base = catalog
                .catalog
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let resolved = verified.resolve(&release, base, &Default::default())?;
            let mut report = export(&resolved, &output)?;
            report["catalogSha256"] = json!(verified.sha256());
            report["signer"] = json!(hex::encode(verified.signer()));
            report["release"] = json!(release);
            report["publisherAuthenticated"] = json!(true);
            Ok(report)
        }
        ReleaseCommand::Sign {
            catalog,
            key,
            output,
        } => {
            let bytes = read_bounded(&catalog, releases::MAX_CATALOG_BYTES)?;
            let key = read_bounded(&key, 16 * 1024)?;
            let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key)
                .map_err(|_| eyre::eyre!("invalid PKCS#8 Ed25519 signing key"))?;
            let signature = releases::sign(&bytes, &key)?;
            crate::write_new_file(&output, &signature)?;
            Ok(json!({"apiVersion":"zdn-release-signature/v1alpha1",
                "catalogSha256":hex::encode(Sha256::digest(&bytes)),
                "signer":hex::encode(key.public_key()),"signature":output,
                "packagesVerified":false,"qualification":"pending","launchReady":false}))
        }
    }
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "release_cli.authenticate")
)]
fn authenticate(args: &CatalogArgs) -> Result<releases::VerifiedCatalog> {
    let bytes = read_bounded(&args.catalog, releases::MAX_CATALOG_BYTES)?;
    let signature = read_bounded(&args.signature, 64)?;
    let keys: Result<Vec<[u8; 32]>> = args
        .trusted_key
        .iter()
        .map(|path| {
            let bytes = read_bounded(path, 32)?;
            bytes
                .as_slice()
                .try_into()
                .context("trusted public key must be 32 raw bytes")
        })
        .collect();
    releases::verify(&bytes, &signature, &keys?)
}

#[cfg_attr(
    feature = "profiling",
    tracing::instrument(skip_all, name = "release_cli.export")
)]
pub fn export(resolved: &zdn::package::ResolvedPackage, output: &Path) -> Result<Value> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let exported = zdn::package::export(resolved.directory(), &resolved.artifact_set, output)?;
        Ok(json!({"apiVersion":"zdn-package-export/v1alpha1",
            "manifest":exported.manifest.canonicalize().context("locate exported manifest")?,
            "packageSha256":exported.sha256,
            "artifactSetSha256":resolved.artifact_set.fingerprint()?,
            "byteIntegrityVerified":true,"compatibilityDeclarationsMatched":true,
            "publisherAuthenticated":false,"artifactExecutionVerified":false,
            "qualification":"pending","launchReady":false}))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (resolved, output);
        eyre::bail!("atomic no-replace package export is unsupported on this platform")
    }
}
