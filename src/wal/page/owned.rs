//! Mutations below the retained PageDatabase lease/mutex. Classification alone
//! does not authorize this module: the owner validates every collection first.
use super::{PageWalFileFormat, PageWalIncompleteKind, PageWalReplayReport, PageWalScanStop};
use crate::errors::{PraxisError, Result};
use crate::io::{create_dir_all_durable, sync_parent_dir};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecyclePhase {
    RepairOpen,
    RepairTruncate,
    RepairHeader,
    RepairSync,
    RepairRescan,
    HeaderWrite,
    HeaderSync,
    HeaderParentSync,
    StageCreate,
    StageWrite,
    StageSync,
    StageValidate,
    Replace,
    ParentSync,
    Reopen,
    InstalledValidate,
    InstalledFileSync,
    InstalledParentSync,
}

/// Per-operation faults are private and absent from production state. Never a
/// public constructor, process-wide switch, or alternative filesystem protocol.
#[derive(Default)]
pub(crate) struct WalLifecycle {
    #[cfg(test)]
    failure: Option<LifecyclePhase>,
}

impl WalLifecycle {
    fn check(&mut self, phase: LifecyclePhase) -> Result<()> {
        #[cfg(not(test))]
        let _ = phase;
        #[cfg(test)]
        if self.failure == Some(phase) {
            self.failure = None;
            return Err(std::io::Error::other(format!("injected page WAL {phase:?}")).into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn failing(phase: LifecyclePhase) -> Self {
        Self {
            failure: Some(phase),
        }
    }
}

fn corrupt<T>(path: &Path, reason: impl Into<String>) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    })
}

fn is_alias(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn check_leaf(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || is_alias(&meta) => {
            corrupt(path, "canonical page WAL must be a regular non-alias file")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn read_owner_report(path: &Path) -> Result<PageWalReplayReport> {
    check_leaf(path)?;
    let report = super::read_report(path)?;
    match &report.stop {
        PageWalScanStop::Clean | PageWalScanStop::ProvenV2Torn { .. } => Ok(report),
        _ => corrupt(
            path,
            format!("page WAL owner preflight refused: {:?}", report.stop),
        ),
    }
}

/// The caller has validated *all* collection directories and canonical semantic
/// facts against this complete prefix under the same retained writer lease.
pub(crate) fn repair_validated(
    path: &Path,
    report: &PageWalReplayReport,
    lifecycle: &mut WalLifecycle,
) -> Result<()> {
    let PageWalScanStop::ProvenV2Torn { kind, .. } = report.stop else {
        return if report.stop == PageWalScanStop::Clean {
            Ok(())
        } else {
            corrupt(path, "unvalidated page WAL repair request")
        };
    };
    if report.file_format != PageWalFileFormat::V2 || read_owner_report(path)? != *report {
        return corrupt(path, "page WAL changed after owner preflight");
    }
    lifecycle.check(LifecyclePhase::RepairOpen)?;
    let mut file = OpenOptions::new().write(true).open(path)?;
    lifecycle.check(LifecyclePhase::RepairTruncate)?;
    file.set_len(report.valid_len)?;
    if kind == PageWalIncompleteKind::FileHeader {
        // A proven partial file header has no complete records and valid_len=0.
        let header = super::framing::file_header_v2();
        file.write_all(&header[..5])?;
        lifecycle.check(LifecyclePhase::RepairHeader)?;
        file.write_all(&header[5..])?;
    }
    lifecycle.check(LifecyclePhase::RepairSync)?;
    file.sync_all()?;
    drop(file);
    lifecycle.check(LifecyclePhase::RepairRescan)?;
    let repaired = super::read_report(path)?;
    if repaired.stop != PageWalScanStop::Clean
        || repaired.file_format != PageWalFileFormat::V2
        || repaired.records != report.records
    {
        return corrupt(path, "page WAL repair did not produce its validated prefix");
    }
    crate::slog::storage(
        "page_wal_repair",
        crate::slog::context()
            .with_str("path", path.display().to_string())
            .with_str("outcome", "success")
            .with_str("stop", format!("{:?}", report.stop))
            .with_u64("physical_len_before", report.physical_len)
            .with_u64("valid_len_before", report.valid_len)
            .with_u64("physical_len_after", repaired.physical_len)
            .with_u64("validated_records", repaired.records.len() as u64),
    );
    Ok(())
}

/// A clean log only; owned-open repair cannot be bypassed at writer activation.
pub(super) fn writable_file(
    path: &Path,
    lifecycle: &mut WalLifecycle,
) -> Result<(File, PageWalReplayReport)> {
    check_leaf(path)?;
    let before = super::read_report(path)?;
    if before.stop != PageWalScanStop::Clean {
        return corrupt(
            path,
            format!("writable page WAL is not clean: {:?}", before.stop),
        );
    }
    match before.file_format {
        PageWalFileFormat::Missing | PageWalFileFormat::Empty => {
            if let Some(parent) = path.parent() {
                create_dir_all_durable(parent)?;
            }
            let mut options = OpenOptions::new();
            options.write(true);
            if before.file_format == PageWalFileFormat::Missing {
                options.create_new(true);
            }
            let mut file = options.open(path)?;
            let header = super::framing::file_header_v2();
            file.write_all(&header[..5])?;
            lifecycle.check(LifecyclePhase::HeaderWrite)?;
            file.write_all(&header[5..])?;
            lifecycle.check(LifecyclePhase::HeaderSync)?;
            file.sync_all()?;
            drop(file);
            lifecycle.check(LifecyclePhase::HeaderParentSync)?;
            sync_parent_dir(path)?;
        }
        PageWalFileFormat::LegacyV1 | PageWalFileFormat::HeaderlessV1 => {
            upgrade(path, &before, lifecycle)?;
        }
        PageWalFileFormat::V2 => {}
        PageWalFileFormat::Undetermined => {
            return corrupt(path, "undetermined writable WAL format");
        }
    }
    lifecycle.check(LifecyclePhase::Reopen)?;
    check_leaf(path)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    lifecycle.check(LifecyclePhase::InstalledValidate)?;
    let installed = super::read_report(path)?;
    if installed.stop != PageWalScanStop::Clean
        || installed.file_format != PageWalFileFormat::V2
        || installed.records != before.records
        || file.metadata()?.len() != installed.physical_len
    {
        return corrupt(path, "installed page WAL disagrees with validated history");
    }
    // Clean v2 bytes cannot prove a prior create/rename publication fence
    // completed. Re-establish both barriers on every new writable activation,
    // including a fresh owner retry and Never append policy.
    lifecycle.check(LifecyclePhase::InstalledFileSync)?;
    file.sync_all()?;
    lifecycle.check(LifecyclePhase::InstalledParentSync)?;
    sync_parent_dir(path)?;
    Ok((file, installed))
}

static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

fn create_stage(path: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..64 {
        let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        let stage = path.with_file_name(format!(
            "page.wal.upgrade-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Never expose payload through a broader umask-derived default,
            // even before restoring the original canonical mode below.
            options.mode(0o600);
        }
        match options.open(&stage) {
            Ok(file) => return Ok((stage, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PraxisError::PageRecoveryRequired {
        path: path.to_path_buf(),
        reason: "cannot create a unique page WAL upgrade sibling; inspect stale siblings offline"
            .into(),
    })
}

fn upgrade(path: &Path, before: &PageWalReplayReport, lifecycle: &mut WalLifecycle) -> Result<()> {
    // fs::read closes the canonical reader before any replacement attempt.
    let bytes = fs::read(path)?;
    if super::framing::scan(&bytes, path) != *before {
        return corrupt(path, "legacy page WAL changed before activation");
    }
    let offset = if before.file_format == PageWalFileFormat::LegacyV1 {
        16
    } else {
        0
    };
    #[cfg(unix)]
    let original_permissions = fs::metadata(path)?.permissions();
    lifecycle.check(LifecyclePhase::StageCreate)?;
    let (stage, mut file) = create_stage(path)?;
    let mut attempted_replace = false;
    let result = (|| {
        #[cfg(unix)]
        file.set_permissions(original_permissions)?;
        file.write_all(&super::framing::file_header_v2())?;
        lifecycle.check(LifecyclePhase::StageWrite)?;
        file.write_all(&bytes[offset..])?;
        lifecycle.check(LifecyclePhase::StageSync)?;
        file.sync_all()?;
        // Close staging and canonical handles before same-filesystem replacement.
        drop(file);
        lifecycle.check(LifecyclePhase::StageValidate)?;
        let staged = super::read_report(&stage)?;
        if staged.stop != PageWalScanStop::Clean
            || staged.file_format != PageWalFileFormat::V2
            || staged.records != before.records
        {
            return corrupt(
                &stage,
                "staged page WAL differs from validated legacy history",
            );
        }
        attempted_replace = true;
        lifecycle.check(LifecyclePhase::Replace)?;
        fs::rename(&stage, path).map_err(|error| PraxisError::PageRecoveryRequired {
            path: path.to_path_buf(),
            reason: format!("same-filesystem page WAL replacement failed ({error}); canonical was not unlinked; inspect the retained upgrade sibling offline"),
        })?;
        lifecycle.check(LifecyclePhase::ParentSync)?;
        sync_parent_dir(path)?;
        Ok(())
    })();
    if result.is_err()
        && !attempted_replace
        && let Ok(meta) = fs::symlink_metadata(&stage)
        && meta.is_file()
        && !is_alias(&meta)
    {
        // Only this exact create-new attempt, never an unrelated/stale sibling.
        let _ = fs::remove_file(&stage);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_legacy_activation_copies_wire_bytes_without_the_new_write_cap() {
        // The private wire mechanism preserves historical frames. Existing page
        // semantic admission still independently enforces its physical slot limit.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("page.wal");
        let mut payload = 1_u64.to_le_bytes().to_vec();
        payload.push(1);
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&2_u32.to_le_bytes());
        payload.extend_from_slice(&1_u64.to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.push(1);
        payload.extend_from_slice(&1_u32.to_le_bytes());
        let len = super::super::MAX_PAGE_WAL_PAYLOAD_BYTES;
        payload.extend_from_slice(&(len as u32).to_le_bytes());
        payload.resize(payload.len() + len, 0x87);
        let mut original = 0x5450_5752_u32.to_le_bytes().to_vec();
        original.push(1);
        original.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        original.extend_from_slice(&crate::io::crc32_ieee(&payload).to_le_bytes());
        original.extend_from_slice(&payload);
        drop(payload);
        fs::write(&path, &original).unwrap();
        let (file, report) = writable_file(&path, &mut WalLifecycle::default()).unwrap();
        assert_eq!(report.physical_len, (original.len() + 16) as u64);
        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].try_encode().is_err());
        drop(report);
        drop(file);
        let installed = fs::read(&path).unwrap();
        assert_eq!(&installed[..16], super::super::framing::file_header_v2());
        assert_eq!(&installed[16..], original);
    }
}
