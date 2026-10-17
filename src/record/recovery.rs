use super::RidDirectory;
use super::database::{CollectionState, EntityCursor};
use crate::errors::{PraxisError, Result};
use crate::identity::{Cid, Eid, Fid, Pid};
use crate::io::crc32c;
use crate::layout::PraxisLayout;
use crate::manifest::{PageLayoutManifest, PageManifestStore};
use crate::page::RecordPage;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn load_collection(layout: &PraxisLayout, cid: Cid) -> Result<CollectionState> {
    let map_path = layout.critical_map_path(cid, "rid_to_slot").path;
    let manifest_path = layout.page_manifest_path().path;
    let manifest = PageManifestStore::open(&manifest_path).load()?;
    let has_directory = map_path.exists() && map_path.metadata()?.len() > 0;
    let (directory, mut next_rid) = if has_directory {
        let bytes = std::fs::read(&map_path)?;
        validate_tracked(&manifest, &map_path, &bytes)?;
        let (directory, next_rid, _, _) = RidDirectory::load_binary(&map_path)?;
        (directory, next_rid)
    } else {
        (RidDirectory::default(), 1)
    };
    let mut cursors: BTreeMap<(Eid, Fid), EntityCursor> = BTreeMap::new();
    let mut occupied = BTreeSet::new();
    let mut tombstoned = BTreeSet::new();
    let mut has_pages = false;
    let entities = layout.collection_root(cid).join("entities");
    if entities.exists() {
        for entity in std::fs::read_dir(&entities)? {
            let entity = entity?;
            require_directory(&entity.path())?;
            let eid = Eid(hex_id(&entity.path())?);
            let frames = entity.path().join("pages").join("frames");
            if !frames.exists() {
                continue;
            }
            require_directory(&frames)?;
            for frame in std::fs::read_dir(frames)? {
                let frame = frame?;
                require_directory(&frame.path())?;
                let fid = Fid(hex_id(&frame.path())?);
                let pages = frame.path().join("pages");
                if !pages.exists() {
                    continue;
                }
                require_directory(&pages)?;
                for file in std::fs::read_dir(pages)? {
                    let path = file?.path();
                    if path.extension().is_none_or(|extension| extension != "page") {
                        continue;
                    }
                    let metadata = std::fs::symlink_metadata(&path)?;
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        return corrupt(&path, "canonical record page must be a regular file");
                    }
                    let pid = Pid(hex_stem(&path)?);
                    let bytes = std::fs::read(&path)?;
                    validate_tracked(&manifest, &path, &bytes)?;
                    let page = RecordPage::from_bytes(&bytes, &path)?;
                    has_pages = true;
                    let next_sid = page
                        .slots()
                        .iter()
                        .map(|slot| u32::from(slot.sid.0) + 1)
                        .max()
                        .unwrap_or(1);
                    for slot in page.slots() {
                        occupied.insert((eid, fid, pid, slot.sid));
                        if slot.tombstone {
                            tombstoned.insert((eid, fid, pid, slot.sid));
                        }
                    }
                    let cursor = cursors.entry((eid, fid)).or_default();
                    if pid.0 >= cursor.current_pid.0 {
                        *cursor = EntityCursor {
                            current_pid: pid,
                            next_sid,
                        };
                    }
                }
            }
        }
    }
    if !has_directory && has_pages {
        return Err(PraxisError::PageRecoveryRequired {
            path: map_path,
            reason: "record pages exist without their RID directory; explicit recovery is required"
                .to_string(),
        });
    }
    let mut deleted = BTreeSet::new();
    let mut mapped_slots = BTreeSet::new();
    for (rid, address) in &directory.mappings {
        if address.cid != cid {
            return corrupt(
                &map_path,
                "RID directory address belongs to a different collection",
            );
        }
        if !occupied.contains(&(address.eid, address.fid, address.pid, address.sid)) {
            return corrupt(
                &map_path,
                "RID directory points to a missing physical page or slot",
            );
        }
        if !mapped_slots.insert((
            address.cid,
            address.eid,
            address.fid,
            address.pid,
            address.sid,
        )) {
            return corrupt(&map_path, "multiple RIDs point to one physical slot");
        }
        // MAX is a nonallocatable exhaustion sentinel, never a RID to reissue.
        next_rid = next_rid.max(rid.0.saturating_add(1));
        if tombstoned.contains(&(address.eid, address.fid, address.pid, address.sid)) {
            deleted.insert(*rid);
        }
    }
    Ok(CollectionState {
        directory,
        deleted,
        next_rid,
        cursors,
    })
}

fn validate_tracked(manifest: &PageLayoutManifest, path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(tracked) = manifest
        .files
        .iter()
        .find(|tracked| Path::new(&tracked.path) == path)
        && tracked.checksum != format!("{:08x}", crc32c(bytes))
    {
        return corrupt(
            path,
            "page manifest checksum disagrees with the canonical file",
        );
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return corrupt(
            path,
            "canonical page directory must not be an alias or file",
        );
    }
    Ok(())
}

fn hex_id(path: &Path) -> Result<u32> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    parse_id(path, name)
}

pub(super) fn collection_id(path: &Path) -> Result<u32> {
    require_directory(path)?;
    hex_id(path)
}

fn hex_stem(path: &Path) -> Result<u32> {
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    parse_id(path, name)
}

fn parse_id(path: &Path, name: &str) -> Result<u32> {
    u32::from_str_radix(name, 16)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| PraxisError::Corrupt {
            path: path.to_path_buf(),
            reason: "invalid nonzero hexadecimal page identity".to_string(),
        })
}

fn corrupt<T>(path: &Path, reason: &str) -> Result<T> {
    Err(PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
