use crate::errors::Result;
use crate::slog;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IoCapability {
    pub platform: String,
    pub direct_io_supported: bool,
    pub direct_io_mode: String,
    pub fallback_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IoExecution {
    pub requested_direct_io: bool,
    pub direct_io_supported: bool,
    pub requested_mode: String,
    pub effective_mode: String,
    pub fallback_reason: Option<String>,
}

pub fn detect_io_capability() -> IoCapability {
    #[cfg(target_os = "linux")]
    let (supported, mode) = (true, "o_direct");
    #[cfg(target_os = "windows")]
    let (supported, mode) = (true, "file_flag_no_buffering");
    #[cfg(target_os = "macos")]
    let (supported, mode) = (true, "fcntl_f_nocache");
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let (supported, mode) = (false, "unsupported");

    IoCapability {
        platform: std::env::consts::OS.to_string(),
        direct_io_supported: supported,
        direct_io_mode: mode.to_string(),
        fallback_mode: "buffered_io".to_string(),
    }
}

pub fn resolve_io_execution(requested_direct_io: bool) -> IoExecution {
    let capability = detect_io_capability();
    let fallback_reason = if !requested_direct_io {
        None
    } else if !capability.direct_io_supported {
        Some("platform_not_supported".to_string())
    } else {
        None
    };
    let effective_mode = if requested_direct_io && fallback_reason.is_none() {
        capability.direct_io_mode.clone()
    } else {
        capability.fallback_mode.clone()
    };
    IoExecution {
        requested_direct_io,
        direct_io_supported: capability.direct_io_supported,
        requested_mode: if requested_direct_io {
            capability.direct_io_mode
        } else {
            capability.fallback_mode.clone()
        },
        effective_mode,
        fallback_reason,
    }
}

/// Write and sync file contents before returning, including buffered fallbacks.
/// On Unix, also sync the parent directory so a new file entry is durable.
pub fn write_file_with_policy(
    path: &Path,
    bytes: &[u8],
    requested_direct_io: bool,
) -> Result<IoExecution> {
    let mut execution = resolve_io_execution(requested_direct_io);
    if execution.requested_direct_io
        && execution.direct_io_supported
        && direct_io_write_compatible(bytes)
    {
        match open_direct_write(path) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    drop(file);
                    execution.effective_mode = "buffered_io".to_string();
                    execution.fallback_reason =
                        Some(format!("direct_write_failed: {error}").replace('\n', " "));
                    emit_fallback(path, &execution);
                    write_buffered_durable(path, bytes)?;
                }
            }
            Err(error) => {
                execution.effective_mode = "buffered_io".to_string();
                execution.fallback_reason =
                    Some(format!("direct_open_failed: {error}").replace('\n', " "));
                emit_fallback(path, &execution);
                write_buffered_durable(path, bytes)?;
            }
        }
    } else {
        if requested_direct_io && execution.fallback_reason.is_none() {
            execution.effective_mode = "buffered_io".to_string();
            execution.fallback_reason = Some("unaligned_payload".to_string());
            emit_fallback(path, &execution);
        }
        write_buffered_durable(path, bytes)?;
    }
    sync_parent_dir(path)?;
    Ok(execution)
}

fn write_buffered_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Persist every new directory entry from the deepest directory to its first
/// existing ancestor. Directory syncing remains unavailable on non-Unix hosts.
pub(crate) fn create_dir_all_durable(path: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = path;
    while !ancestor.as_os_str().is_empty() && !ancestor.try_exists()? {
        missing.push(ancestor.to_path_buf());
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
    fs::create_dir_all(path)?;
    for directory in missing {
        sync_parent_dir(&directory)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_dir(_path: &Path) -> Result<()> {
    // Rust has no portable directory-fsync operation on these platforms.
    Ok(())
}

pub fn read_file_with_policy(
    path: &Path,
    requested_direct_io: bool,
) -> Result<(Vec<u8>, IoExecution)> {
    let mut execution = resolve_io_execution(requested_direct_io);
    if requested_direct_io && execution.direct_io_supported {
        let len = fs::metadata(path)?.len();
        if !direct_io_length_compatible(len as usize) {
            execution.effective_mode = "buffered_io".to_string();
            execution.fallback_reason = Some("unaligned_file_length".to_string());
            emit_fallback(path, &execution);
            return Ok((fs::read(path)?, execution));
        }
        if let Ok(mut file) = open_direct_read(path) {
            let mut bytes = Vec::with_capacity(len as usize);
            match file.read_to_end(&mut bytes) {
                Ok(_) => return Ok((bytes, execution)),
                Err(error) => {
                    execution.effective_mode = "buffered_io".to_string();
                    execution.fallback_reason =
                        Some(format!("direct_read_failed: {error}").replace('\n', " "));
                    emit_fallback(path, &execution);
                }
            }
        } else {
            execution.effective_mode = "buffered_io".to_string();
            execution.fallback_reason = Some("direct_open_failed".to_string());
            emit_fallback(path, &execution);
        }
    }
    Ok((fs::read(path)?, execution))
}

fn emit_fallback(path: &Path, execution: &IoExecution) {
    slog::info(
        "direct_io_fallback",
        slog::context()
            .with_str("path", path.to_string_lossy().to_string())
            .with_str("requested_mode", execution.requested_mode.clone())
            .with_str("effective_mode", execution.effective_mode.clone())
            .with_str(
                "fallback_reason",
                execution
                    .fallback_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
    );
}

fn direct_io_write_compatible(bytes: &[u8]) -> bool {
    let alignment = direct_io_alignment();
    !bytes.is_empty() && bytes.len().is_multiple_of(alignment)
}

fn direct_io_length_compatible(len: usize) -> bool {
    len == 0 || len.is_multiple_of(direct_io_alignment())
}

const fn direct_io_alignment() -> usize {
    4096
}

#[cfg(target_os = "windows")]
fn open_direct_write(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .custom_flags(0x2000_0000)
        .open(path)
}

#[cfg(target_os = "linux")]
fn open_direct_write(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    const O_DIRECT: i32 = 0x4000;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .custom_flags(O_DIRECT)
        .open(path)
}

#[cfg(target_os = "macos")]
fn open_direct_write(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    set_macos_nocache(&file)?;
    Ok(file)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn open_direct_write(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

#[cfg(target_os = "windows")]
fn open_direct_read(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(0x2000_0000)
        .open(path)
}

#[cfg(target_os = "linux")]
fn open_direct_read(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    const O_DIRECT: i32 = 0x4000;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECT)
        .open(path)
}

#[cfg(target_os = "macos")]
fn open_direct_read(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new().read(true).open(path)?;
    set_macos_nocache(&file)?;
    Ok(file)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn open_direct_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(target_os = "macos")]
fn set_macos_nocache(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    }

    const F_NOCACHE: i32 = 48;
    let result = unsafe { fcntl(file.as_raw_fd(), F_NOCACHE, 1) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn durable_directory_creation_is_nested_and_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("new").join("nested").join("records");
        create_dir_all_durable(&path).unwrap();
        assert!(path.is_dir());
        let record = path.join("existing.bin");
        fs::write(&record, b"keep").unwrap();
        create_dir_all_durable(&path).unwrap();
        assert_eq!(fs::read(record).unwrap(), b"keep");
    }

    #[test]
    fn durable_directory_creation_rejects_a_file_ancestor() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"keep").unwrap();
        assert!(create_dir_all_durable(&file.join("records")).is_err());
        assert_eq!(fs::read(file).unwrap(), b"keep");
    }

    #[test]
    fn unaligned_direct_write_falls_back_explicitly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unaligned.bin");
        let execution = write_file_with_policy(&path, b"abc", true).unwrap();
        assert_eq!(execution.effective_mode, "buffered_io");
        assert_eq!(
            execution.fallback_reason.as_deref(),
            Some("unaligned_payload")
        );
        assert_eq!(fs::read(path).unwrap(), b"abc");
    }

    #[test]
    fn unaligned_direct_read_falls_back_explicitly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.bin");
        fs::write(&path, b"abc").unwrap();
        let (bytes, execution) = read_file_with_policy(&path, true).unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(execution.effective_mode, "buffered_io");
        assert_eq!(
            execution.fallback_reason.as_deref(),
            Some("unaligned_file_length")
        );
    }
}
