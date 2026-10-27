//! Tiny managed executables and a blocking, wrong-account STS response. No cloud calls.

use crate::executable;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use zdn::dependencies::{self, InstallReceipt, InstalledFile, InstalledTool};

pub fn install(root: &Path) {
    let managed = root.join("tools");
    let manifest = dependencies::builtin_manifest().unwrap();
    let platform = dependencies::current_platform().unwrap();
    let digest = manifest.digest().unwrap();
    let installation = format!("versions/{digest}-{platform}");
    let mut tools = Vec::new();
    // Reaching a Pulumi invocation is a test failure, not a simulated deployment.
    let bytes = b"#!/bin/sh\nexit 99\n";
    for artifact in &manifest.platforms[platform] {
        let mut files = Vec::new();
        for file in &artifact.files {
            let path = managed.join(&installation).join(&file.install_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            executable::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            files.push(InstalledFile {
                path: file.install_path.clone(),
                sha256: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
            });
        }
        tools.push(InstalledTool {
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            archive_sha256: artifact.sha256.clone(),
            files,
        });
    }
    let receipt = InstallReceipt {
        schema_version: 1,
        catalog_sha256: digest,
        platform: platform.into(),
        installation: installation.clone(),
        tools,
    };
    for path in [
        managed.join("active.json"),
        managed.join(installation).join("receipt.json"),
    ] {
        fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let aws = bin.join("aws");
    executable::write(&aws, r#"#!/bin/sh
case "$*" in
  --version) printf 'aws-cli/2.37.4 Python/3.13 fixture\n' ;;
  *'sts get-caller-identity'*)
    printf 'waiting' > "$ZDN_FIXTURE_WAITING"
    i=0
    while [ ! -f "$ZDN_FIXTURE_RELEASE" ] && [ "$i" -lt 500 ]; do
      /bin/sleep 0.01
      i=$((i+1))
    done
    printf '{"Account":"999999999999","Arn":"fixture-diagnostic-not-for-export","UserId":"fixture"}' ;;
  *) exit 99 ;;
esac
"#).unwrap();
    fs::set_permissions(aws, fs::Permissions::from_mode(0o755)).unwrap();
}
