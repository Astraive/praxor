//! Cooperative exclusive ownership of a durable writer root.
//!
//! The permanent lock file must never be unlinked, replaced or truncated:
//! opening a replacement inode would admit a second owner of the same path.
//! Internal nested stores receive an already acquired lease explicitly. A
//! second independent open never shares ownership merely because its PID matches.

use crate::errors::{PraxisError, Result};
use crate::io::create_dir_all_durable;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

pub(crate) const LOCK_FILE_NAME: &str = ".praxor.writer.lock";

pub(crate) struct WriterLease {
    root: PathBuf,
    // Keep the OS lock alive until the complete owner (including Arc clones)
    // drops. No explicit unlock on an individual facade's close operation.
    _file: File,
    // A standalone physical primary also owns its enclosing root. Release
    // that parent only after the child's file handle has closed.
    _parent: Option<Box<WriterLease>>,
}

impl WriterLease {
    pub(crate) fn acquire(root: impl AsRef<Path>) -> Result<Self> {
        Self::acquire_impl(root.as_ref(), None)
    }

    fn acquire_impl(root: &Path, parent: Option<&Path>) -> Result<Self> {
        // Avoid leaving permanent child artifacts for already-known invalid
        // layouts. This is only an early rejection; repeat after locking to
        // close the race with a parent that starts after this check.
        validate_ancestors(root, parent)?;
        create_dir_all_durable(root)?;
        let root = std::fs::canonicalize(root)?;
        lock_artifact_exists(&root.join(LOCK_FILE_NAME))?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join(LOCK_FILE_NAME))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(PraxisError::AlreadyOpen { path: root }),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        // Lock our artifact BEFORE checking ancestors. Parent copy operations
        // lock themselves before scanning descendants, closing the race with
        // a delayed independent child opener without recursively sharing locks.
        validate_ancestors(&root, parent)?;
        Ok(Self {
            root,
            _file: file,
            _parent: None,
        })
    }

    pub(crate) fn acquire_primary(&self) -> Result<Self> {
        let path = self.root.join("primary");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let actual = std::fs::canonicalize(&path)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || actual.parent() != Some(self.root())
                    || !is_primary_name(&actual)
                {
                    return Err(PraxisError::InvalidConfig(
                        "the reserved primary directory must not be a directory alias".to_string(),
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Self::acquire_impl(&path, Some(self.root()))
    }

    pub(crate) fn acquire_record_root(root: impl AsRef<Path>) -> Result<Self> {
        create_dir_all_durable(root.as_ref())?;
        let root = std::fs::canonicalize(root)?;
        if is_primary_name(&root)
            && let Some(parent) = root.parent()
        {
            let parent_lease = Self::acquire(parent)?;
            let mut child = parent_lease.acquire_primary()?;
            child._parent = Some(Box::new(parent_lease));
            Ok(child)
        } else {
            Self::acquire(root)
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

fn validate_ancestors(root: &Path, parent: Option<&Path>) -> Result<()> {
    let absolute = std::path::absolute(root)?;
    let mut existing = absolute.as_path();
    let canonical = loop {
        match std::fs::canonicalize(existing) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing.parent().ok_or(error)?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    let skip = usize::from(existing == absolute);
    for ancestor in canonical.ancestors().skip(skip) {
        if lock_artifact_exists(&ancestor.join(LOCK_FILE_NAME))? && Some(ancestor) != parent {
            return Err(PraxisError::InvalidConfig(
                "independent database roots cannot be nested inside an existing writer root"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn is_primary_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        #[cfg(windows)]
        {
            name.to_string_lossy().eq_ignore_ascii_case("primary")
        }
        #[cfg(not(windows))]
        {
            name == "primary"
        }
    })
}

pub(crate) fn lock_artifact_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(PraxisError::InvalidConfig(format!(
                "writer lock artifact must be a regular file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
