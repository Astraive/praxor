use crate::errors::Result;
use crate::kernel::{
    DurableArtifactDescriptor, DurableArtifactKind, DurableArtifactState, DurableFormatDescriptor,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::fs::File;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageManifest {
    pub version: u64,
    pub last_sequence: u64,
    pub primary_segments: Vec<String>,
    pub index_files: HashMap<String, Vec<String>>,
    pub plugin_namespaces: HashMap<String, String>,
    #[serde(default)]
    pub index_compaction_runs: HashMap<String, u64>,
    #[serde(default)]
    pub last_compacted_at_sequence: HashMap<String, u64>,
    #[serde(default)]
    pub maintenance_cycles_run: u64,
    #[serde(default)]
    pub last_maintenance_at_sequence: Option<u64>,
    #[serde(default)]
    pub durable_files: Vec<DurableFileRecord>,
    #[serde(default)]
    pub edits: Vec<ManifestEdit>,
}

impl Default for StorageManifest {
    fn default() -> Self {
        Self {
            version: 1,
            last_sequence: 0,
            primary_segments: Vec::new(),
            index_files: HashMap::new(),
            plugin_namespaces: HashMap::new(),
            index_compaction_runs: HashMap::new(),
            last_compacted_at_sequence: HashMap::new(),
            maintenance_cycles_run: 0,
            last_maintenance_at_sequence: None,
            durable_files: Vec::new(),
            edits: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DurableFileKind {
    WalSegment,
    Manifest,
    RecordDirectory,
    ValueSegment,
    IndexSegment,
    Sstable,
    BTreePageFile,
    Checkpoint,
    TieredObject,
    ReplicationLog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DurableFileState {
    Created,
    Installed,
    Replaced,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableFileRecord {
    pub logical_name: String,
    pub path: String,
    pub kind: DurableFileKind,
    pub state: DurableFileState,
    pub format_version: u16,
    pub checksum: String,
    pub independently_recoverable: bool,
    pub forward_compatible: bool,
}

impl DurableFileRecord {
    pub fn installed(
        logical_name: impl Into<String>,
        path: impl Into<String>,
        kind: DurableFileKind,
        format_version: u16,
        checksum: impl Into<String>,
    ) -> Self {
        Self {
            logical_name: logical_name.into(),
            path: path.into(),
            kind,
            state: DurableFileState::Installed,
            format_version,
            checksum: checksum.into(),
            independently_recoverable: true,
            forward_compatible: true,
        }
    }

    pub fn to_kernel_descriptor(&self) -> DurableArtifactDescriptor {
        DurableArtifactDescriptor {
            logical_name: self.logical_name.clone(),
            path: PathBuf::from(&self.path),
            kind: self.kind.into(),
            state: self.state.into(),
            format: DurableFormatDescriptor {
                structure: self.kind.structure_name(),
                format_version: self.format_version,
                checksum: Cow::Owned(self.checksum.clone()),
                forward_compatible: self.forward_compatible,
                independently_recoverable: self.independently_recoverable,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ManifestEdit {
    DurableFileCreated {
        logical_name: String,
        path: String,
    },
    DurableFileInstalled {
        logical_name: String,
        path: String,
    },
    CompactionStarted {
        job_id: String,
        old_segments: Vec<u32>,
    },
    CompactionInstalled {
        job_id: String,
        old_segments: Vec<u32>,
        new_segment: u32,
        records_retained: u64,
        bytes_written: u64,
    },
    CompactionCleanupComplete {
        job_id: String,
        cleaned_segments: Vec<u32>,
    },
    CompactionAborted {
        job_id: String,
        old_segments: Vec<u32>,
        reason: String,
    },
    TierMigrationStarted {
        object_id: String,
    },
    TierMigrationInstalled {
        object_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCompactionCleanup {
    pub job_id: String,
    pub old_segments: Vec<u32>,
    pub new_segment: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCompactionAbort {
    pub job_id: String,
    pub old_segments: Vec<u32>,
}

impl StorageManifest {
    pub fn set_durable_files(&mut self, files: Vec<DurableFileRecord>) {
        self.durable_files = files;
    }

    pub fn append_edit(&mut self, edit: ManifestEdit) {
        self.edits.push(edit);
    }

    pub fn kernel_artifacts(&self) -> Vec<DurableArtifactDescriptor> {
        self.durable_files
            .iter()
            .map(DurableFileRecord::to_kernel_descriptor)
            .collect()
    }

    pub fn pending_compaction_cleanups(&self) -> Vec<PendingCompactionCleanup> {
        let mut installed: HashMap<String, PendingCompactionCleanup> = HashMap::new();
        for edit in &self.edits {
            match edit {
                ManifestEdit::CompactionInstalled {
                    job_id,
                    old_segments,
                    new_segment,
                    ..
                } => {
                    installed.insert(
                        job_id.clone(),
                        PendingCompactionCleanup {
                            job_id: job_id.clone(),
                            old_segments: old_segments.clone(),
                            new_segment: *new_segment,
                        },
                    );
                }
                ManifestEdit::CompactionCleanupComplete {
                    cleaned_segments, ..
                } => {
                    let cleaned: std::collections::HashSet<u32> =
                        cleaned_segments.iter().copied().collect();
                    installed.retain(|_, pending| {
                        pending
                            .old_segments
                            .iter()
                            .any(|segment_id| !cleaned.contains(segment_id))
                    });
                }
                ManifestEdit::CompactionAborted { job_id, .. } => {
                    installed.remove(job_id);
                }
                _ => {}
            }
        }
        let mut pending: Vec<_> = installed.into_values().collect();
        pending.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        pending
    }

    pub fn pending_compaction_aborts(&self) -> Vec<PendingCompactionAbort> {
        let mut started: HashMap<String, PendingCompactionAbort> = HashMap::new();
        let mut installed = std::collections::HashSet::new();
        let mut terminal = std::collections::HashSet::new();
        for edit in &self.edits {
            match edit {
                ManifestEdit::CompactionStarted {
                    job_id,
                    old_segments,
                } => {
                    started.insert(
                        job_id.clone(),
                        PendingCompactionAbort {
                            job_id: job_id.clone(),
                            old_segments: old_segments.clone(),
                        },
                    );
                }
                ManifestEdit::CompactionInstalled { job_id, .. } => {
                    installed.insert(job_id.clone());
                }
                ManifestEdit::CompactionCleanupComplete { job_id, .. }
                | ManifestEdit::CompactionAborted { job_id, .. } => {
                    terminal.insert(job_id.clone());
                }
                _ => {}
            }
        }

        let mut pending: Vec<_> = started
            .into_values()
            .filter(|started| {
                !installed.contains(&started.job_id) && !terminal.contains(&started.job_id)
            })
            .collect();
        pending.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        pending
    }
}

impl DurableFileKind {
    fn structure_name(self) -> &'static str {
        match self {
            Self::WalSegment => "wal_segment",
            Self::Manifest => "manifest",
            Self::RecordDirectory => "record_directory",
            Self::ValueSegment => "value_segment",
            Self::IndexSegment => "index_segment",
            Self::Sstable => "sstable",
            Self::BTreePageFile => "btree_page_file",
            Self::Checkpoint => "checkpoint",
            Self::TieredObject => "tiered_object",
            Self::ReplicationLog => "replication_log",
        }
    }
}

impl From<DurableFileKind> for DurableArtifactKind {
    fn from(kind: DurableFileKind) -> Self {
        match kind {
            DurableFileKind::WalSegment => Self::WalSegment,
            DurableFileKind::Manifest => Self::Manifest,
            DurableFileKind::RecordDirectory => Self::RecordDirectory,
            DurableFileKind::ValueSegment => Self::ValueSegment,
            DurableFileKind::IndexSegment => Self::IndexSegment,
            DurableFileKind::Sstable => Self::Sstable,
            DurableFileKind::BTreePageFile => Self::BTreePageFile,
            DurableFileKind::Checkpoint => Self::Checkpoint,
            DurableFileKind::TieredObject => Self::TieredObject,
            DurableFileKind::ReplicationLog => Self::ReplicationLog,
        }
    }
}

impl From<DurableFileState> for DurableArtifactState {
    fn from(state: DurableFileState) -> Self {
        match state {
            DurableFileState::Created => Self::Created,
            DurableFileState::Installed => Self::Installed,
            DurableFileState::Replaced => Self::Replaced,
            DurableFileState::Deleted => Self::Deleted,
        }
    }
}

pub struct StorageManifestStore {
    path: PathBuf,
}

impl StorageManifestStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load_or_create(&self) -> Result<StorageManifest> {
        if self.path.exists() {
            let bytes = std::fs::read(&self.path)?;
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            let manifest = StorageManifest::default();
            self.save(&manifest)?;
            Ok(manifest)
        }
    }

    pub fn save(&self, manifest: &StorageManifest) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(manifest)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, &self.path)?;
        sync_parent_dir(&self.path)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}
