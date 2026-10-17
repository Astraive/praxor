use crate::errors::Result;
use crate::io::{file_digest, write_file_with_policy};
use crate::manifest::{CheckpointMetadata, ColumnFamilyGeneration, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointFile {
    pub format_version: u32,
    pub sequence: u64,
    pub segment_paths: Vec<String>,
    #[serde(default)]
    pub column_family_generations: BTreeMap<String, ColumnFamilyGeneration>,
    #[serde(default = "crate::manifest::model::default_next_column_family_generation")]
    pub next_column_family_generation: u64,
}

pub fn write_checkpoint(path: &Path, id: u64, manifest: &Manifest) -> Result<CheckpointMetadata> {
    write_checkpoint_with_policy(path, id, manifest, false)
}

pub fn write_checkpoint_with_policy(
    path: &Path,
    id: u64,
    manifest: &Manifest,
    requested_direct_io: bool,
) -> Result<CheckpointMetadata> {
    let checkpoint = CheckpointFile {
        format_version: manifest.format_version,
        sequence: manifest.last_sequence,
        column_family_generations: manifest.column_family_generations.clone(),
        next_column_family_generation: manifest.next_column_family_generation,
        segment_paths: manifest
            .segments
            .iter()
            .map(|segment| segment.path.clone())
            .collect(),
    };
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(&checkpoint)?;
    write_file_with_policy(&tmp, &bytes, requested_direct_io)?;
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    let digest = file_digest(path)?;
    Ok(CheckpointMetadata {
        id,
        path: path.to_string_lossy().to_string(),
        sequence: manifest.last_sequence,
        segment_count: manifest.segments.len() as u64,
        file_digest: digest.to_hex().to_string(),
    })
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
