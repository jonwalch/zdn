//! Explicit wallet-root backend trust; saved hashes are rechecked on every use.
use super::*;

const FILE_NAME: &str = "backend.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackendSettings {
    schema_version: u32,
    pub(crate) backend: PathBuf,
    pub(crate) backend_sha256: String,
}

/// Verify the caller-supplied pin before atomically replacing this root's settings.
pub(crate) fn set(root: &Path, backend: &Path, expected: &str) -> Result<BackendSettings> {
    let settings = BackendSettings {
        schema_version: 1,
        backend: verified_backend(backend, expected)?,
        backend_sha256: expected.to_ascii_lowercase(),
    };
    store::private_dir(root, true)?;
    let path = root.join(FILE_NAME);
    no_symlinks(&path)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => regular(&path, true)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    zdn::foundation::write_private(&path, &serde_json::to_vec_pretty(&settings)?)?;
    Ok(settings)
}

/// Resolve a complete explicit override or a saved pair, and verify the executable.
/// Never merge partial overrides with saved settings or search PATH.
pub(crate) fn resolve(
    root: &Path,
    backend: Option<&Path>,
    expected: Option<&str>,
) -> Result<(PathBuf, String)> {
    match (backend, expected) {
        (Some(backend), Some(expected)) => Ok((
            verified_backend(backend, expected)?,
            expected.to_ascii_lowercase(),
        )),
        (None, None) => {
            let path = root.join(FILE_NAME);
            no_symlinks(&path)?;
            ensure!(
                !matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "no wallet backend configured; run zdn wallet backend set --backend PATH --backend-sha256 HASH, or supply both flags for this command"
            );
            store::private_dir(root, false)?;
            regular(&path, true)?;
            ensure!(
                fs::metadata(&path)?.len() <= 16384,
                "wallet backend settings exceed size bound"
            );
            let settings: BackendSettings = serde_json::from_slice(&fs::read(&path)?)
                .map_err(|_| eyre::eyre!("invalid wallet backend settings; configure explicitly again"))?;
            ensure!(
                settings.schema_version == 1 && settings.backend.is_absolute(),
                "invalid wallet backend settings; configure explicitly again"
            );
            Ok((
                verified_backend(&settings.backend, &settings.backend_sha256)?,
                settings.backend_sha256.to_ascii_lowercase(),
            ))
        }
        _ => eyre::bail!(
            "--backend and --backend-sha256 must be supplied together; partial overrides are not allowed"
        ),
    }
}
