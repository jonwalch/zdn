//! Write executable fixtures without exposing their writable descriptors to
//! sibling subprocesses in the parallel test harness.

use std::{io::Write, path::Path, process::Command};

pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    let mut source = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    source.write_all(contents.as_ref())?;
    // CLOEXEC is not enough: a concurrent spawn can copy a writable descriptor
    // before it is closed, retaining it until that child execs. Executing the
    // fixture in that window fails with ETXTBSY, even after fs::write returns.
    // Only this single-purpose child opens the executable for writing. Waiting
    // for its exit releases every writer; the parent only writes staging data
    // that is never executed. Keep the existing executable path and argv intact.
    let status = Command::new("/bin/cp")
        .arg(source.path())
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("executable fixture copy failed"));
    }
    Ok(())
}
