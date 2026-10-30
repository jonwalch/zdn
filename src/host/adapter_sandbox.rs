//! Fixed public-input sandbox policy, separate from process supervision.
//! No installation/download, configurable command/bind map or fallback execution.
//! A host without these trusted tools or working unprivileged namespaces refuses.
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
};

use eyre::{ensure, Result};

#[derive(Clone)]
pub(crate) struct Sandbox {
    shell: PathBuf,
    setpriv: PathBuf,
    bwrap: PathBuf,
    libraries: Vec<(PathBuf, PathBuf)>,
}

impl Sandbox {
    pub(crate) fn discover() -> Result<Self> {
        ensure!(
            nix::unistd::geteuid().is_root(),
            "host sandbox requires root admission"
        );
        let shell = trusted(Path::new("/usr/bin/bash"), false)?;
        let setpriv = trusted(Path::new("/usr/bin/setpriv"), false)?;
        let bwrap = trusted(Path::new("/usr/bin/bwrap"), false)?;
        let mut libraries = Vec::new();
        for path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
            match fs::symlink_metadata(path) {
                Ok(_) => libraries.push((trusted(Path::new(path), true)?, path.into())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        ensure!(
            !libraries.is_empty(),
            "host sandbox has no trusted runtime libraries"
        );
        Ok(Self {
            shell,
            setpriv,
            bwrap,
            libraries,
        })
    }

    /// These snapshots contain public bytes only. Nothing else is mounted into
    /// the namespace: no /etc, /home, /root, /run, host /proc, cookie or IMDS.
    pub(crate) fn command(&self, snapshot: &Path) -> Result<Command> {
        fs::set_permissions(snapshot, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(snapshot.join("adapter"), fs::Permissions::from_mode(0o555))?;
        if snapshot.join("seed-blocks.bin").try_exists()? {
            fs::set_permissions(
                snapshot.join("seed-blocks.bin"),
                fs::Permissions::from_mode(0o444),
            )?;
        }
        // std::process inherits non-CLOEXEC descriptors; setpriv/bubblewrap do
        // not close them. Close in a fresh, single-threaded trusted process,
        // never in the multithreaded controller. Paths remain positional argv,
        // not interpolated command text. The exec chain preserves supervision.
        let mut command = Command::new(&self.shell);
        command.args([
            "--noprofile",
            "--norc",
            "-c",
            r#"set -eu
test -d /proc/self/fd
for path in /proc/self/fd/*; do
    fd=${path##*/}
    case "$fd" in 0|1|2) continue ;; *[!0-9]*|'') exit 125 ;; esac
    exec {fd}>&-
done
exec "$@""#,
            "zdn-public-adapter",
        ]);
        command.arg(&self.setpriv);
        command.args(self.arguments(snapshot));
        Ok(command)
    }

    fn arguments(&self, snapshot: &Path) -> Vec<OsString> {
        // Drop the real host UID, supplementary groups and privilege gains
        // BEFORE executing bubblewrap. User-namespace root must never map to
        // host root or the node UID. Unsupported namespaces fail closed.
        let mut args: Vec<OsString> = [
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--no-new-privs",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--pdeathsig=KILL",
            "--",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        // setpriv arms this signal AFTER changing credentials (which would
        // otherwise clear it). Check the original caller after arming, so a
        // death before setpriv runs cannot silently bind to a new parent.
        // This trusted exec-only gate never starts the adapter on mismatch.
        args.push(self.shell.as_os_str().to_owned());
        args.extend(
            [
                "--noprofile",
                "--norc",
                "-c",
                r#"set -eu
test "$PPID" -eq "$1"
shift
exec "$@""#,
                "zdn-public-adapter-parent",
            ]
            .into_iter()
            .map(OsString::from),
        );
        args.push(std::process::id().to_string().into());
        args.push(self.bwrap.as_os_str().to_owned());
        args.extend(
            [
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--clearenv",
                "--setenv",
                "LANG",
                "C",
                "--setenv",
                "LC_ALL",
                "C",
                "--setenv",
                "HOME",
                "/nonexistent",
            ]
            .into_iter()
            .map(OsString::from),
        );
        for (source, destination) in &self.libraries {
            args.extend([
                "--ro-bind".into(),
                source.as_os_str().to_owned(),
                destination.as_os_str().to_owned(),
            ]);
        }
        args.extend([
            "--ro-bind".into(),
            snapshot.as_os_str().to_owned(),
            "/public".into(),
            "--dev".into(),
            "/dev".into(),
            "--dir".into(),
            "/tmp".into(),
            "--chdir".into(),
            "/public".into(),
            "--remount-ro".into(),
            "/".into(),
            "--".into(),
            "/public/adapter".into(),
        ]);
        args
    }
}

fn trusted(path: &Path, directory: bool) -> Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    let mut cursor = PathBuf::new();
    for component in resolved.components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "invalid sandbox tool path"
        );
        cursor.push(component.as_os_str());
        let info = fs::symlink_metadata(&cursor)?;
        ensure!(
            info.uid() == 0 && info.mode() & 0o022 == 0 && !info.file_type().is_symlink(),
            "untrusted sandbox tool path"
        );
    }
    let info = fs::metadata(&resolved)?;
    ensure!(
        if directory {
            info.is_dir()
        } else {
            info.is_file() && info.mode() & 0o111 != 0 && info.nlink() == 1
        },
        "invalid sandbox tool kind"
    );
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_policy_drops_host_identity_and_exposes_only_public_inputs_and_libraries() {
        // Inspect literal policy without executing setpriv, namespaces or a
        // container. This is not host isolation qualification.
        let sandbox = Sandbox {
            shell: "/usr/bin/bash".into(),
            setpriv: "/usr/bin/setpriv".into(),
            bwrap: "/usr/bin/bwrap".into(),
            libraries: vec![("/usr/lib".into(), "/lib".into())],
        };
        let args = sandbox.arguments(Path::new("/public-snapshot"));
        let args: Vec<_> = args.iter().map(|a| a.to_str().unwrap()).collect();
        for flag in [
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--no-new-privs",
            "--bounding-set=-all",
            "--pdeathsig=KILL",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(args.contains(&flag), "{flag}");
        }
        assert!(args
            .windows(3)
            .any(|w| w == ["--ro-bind", "/public-snapshot", "/public"]));
        assert!(!args.iter().any(|a| [
            "/etc",
            "/run",
            "/home",
            "/root",
            "/proc",
            "--share-net",
            "--bind"
        ]
        .contains(a)));
        assert_eq!(args.last(), Some(&"/public/adapter"));
    }
}
