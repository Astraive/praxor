use crate::errors::{PraxisError, Result};
use crate::identity::{Cid, Eid, Fid, Pid};
use crate::layout::PraxisLayout;
use crate::manifest::PageLayoutManifest;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

/// V1 labels can outlive a move. They identify a known terminal writer role,
/// never an IO destination or an authenticated source/checksum after relocation.
#[derive(Debug, Eq, PartialEq)]
enum Role {
    Page(Cid, Eid, Fid, Pid),
    Slots(Cid, Eid, Fid, Pid),
    Rids(Cid),
}

impl Role {
    fn current_path(&self, layout: &PraxisLayout) -> PathBuf {
        match *self {
            Self::Page(cid, eid, fid, pid) => layout.page_path(cid, eid, fid, pid).path,
            Self::Slots(cid, eid, fid, pid) => layout.slot_directory_path(cid, eid, fid, pid).path,
            Self::Rids(cid) => layout.critical_map_path(cid, "rid_to_slot").path,
        }
    }
}

pub(super) fn require_inventory_presence(
    layout: &PraxisLayout,
    manifest: &PageLayoutManifest,
) -> Result<()> {
    for row in &manifest.files {
        if row.format_version != 1
            || !matches!(
                row.format.as_str(),
                "record-page" | "slot-directory" | "rid-directory"
            )
        {
            // Unknown annotations remain opaque and confer no file authority.
            continue;
        }
        let role = parse_role(&row.path, &row.format, '/')
            .or_else(|| parse_role(&row.path, &row.format, '\\'))
            .ok_or_else(|| {
                missing(
                    &layout.page_manifest_path().path,
                    "known v1 writer role has an unresolvable terminal path identity",
                )
            })?;
        // Both recoverable flag values require presence. Do not select, compare
        // or rewrite foreign-label checksums; existing exact-path checks remain.
        require_current_file(layout, &role.current_path(layout))?;
    }
    Ok(())
}

fn parse_role(label: &str, format: &str, separator: char) -> Option<Role> {
    match format {
        "record-page" => {
            let [
                ".praxis",
                "data",
                cid,
                "entities",
                eid,
                "pages",
                "frames",
                fid,
                "pages",
                page,
            ] = terminal(label, separator)?
            else {
                return None;
            };
            Some(Role::Page(
                Cid(id(cid)?),
                Eid(id(eid)?),
                Fid(id(fid)?),
                Pid(id(page.strip_suffix(".page")?)?),
            ))
        }
        "slot-directory" => {
            let [
                ".praxis",
                "data",
                cid,
                "entities",
                eid,
                "slots",
                fid,
                pid,
                "slot.directory",
            ] = terminal(label, separator)?
            else {
                return None;
            };
            Some(Role::Slots(
                Cid(id(cid)?),
                Eid(id(eid)?),
                Fid(id(fid)?),
                Pid(id(pid)?),
            ))
        }
        "rid-directory" => {
            let [".praxis", "data", cid, "kv", "critical", "rid_to_slot.kv"] =
                terminal(label, separator)?
            else {
                return None;
            };
            Some(Role::Rids(Cid(id(cid)?)))
        }
        _ => None,
    }
}

// Read a fixed number of terminal components without allocating from a label.
// All earlier source-root components are opaque and are never dereferenced.
fn terminal<const N: usize>(label: &str, separator: char) -> Option<[&str; N]> {
    let mut split = label.rsplit(separator);
    let mut parts = [""; N];
    for part in parts.iter_mut().rev() {
        *part = split.next()?;
    }
    Some(parts)
}

fn id(text: &str) -> Option<u32> {
    if !(4..=8).contains(&text.len()) {
        return None;
    }
    let value = u32::from_str_radix(text, 16).ok()?;
    (value != 0 && Cid(value).to_hex() == text).then_some(value)
}

fn require_current_file(layout: &PraxisLayout, path: &Path) -> Result<()> {
    // Only Layout-produced paths reach this function. Walk from the current
    // namespace so symlink_metadata never follows an unchecked ancestor.
    let relative = path
        .strip_prefix(layout.root())
        .expect("current layout path");
    let mut current = layout.root().to_path_buf();
    require_component(&current, false)?;
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        current.push(part);
        require_component(&current, parts.peek().is_none())?;
    }
    Ok(())
}

fn require_component(path: &Path, leaf: bool) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(missing(
                path,
                "surviving v1 inventory names a missing current writer role",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    if is_alias(&metadata)
        || if leaf {
            !metadata.is_file()
        } else {
            !metadata.is_dir()
        }
    {
        return Err(missing(
            path,
            "required writer role must have real directory ancestors and a regular non-alias leaf",
        ));
    }
    Ok(())
}

fn is_alias(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn missing(path: &Path, reason: &str) -> PraxisError {
    PraxisError::PageRecoveryRequired {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(label: &str, format: &str) -> Option<Role> {
        parse_role(label, format, '/').or_else(|| parse_role(label, format, '\\'))
    }

    #[test]
    fn literal_terminal_roles_preserve_each_u32_identity_and_opaque_source_prefix() {
        assert_eq!(
            parse(
                "/a/.praxis/b/.praxis/data/10001/entities/ffffffff/pages/frames/abcd/pages/ffffffff.page",
                "record-page"
            ),
            Some(Role::Page(
                Cid(0x10001),
                Eid(u32::MAX),
                Fid(0xabcd),
                Pid(u32::MAX)
            ))
        );
        assert_eq!(
            parse(
                r"\\?\UNC\server\share\.praxis\data\ffffffff\entities\10001\slots\ffffffff\10001\slot.directory",
                "slot-directory"
            ),
            Some(Role::Slots(
                Cid(u32::MAX),
                Eid(0x10001),
                Fid(u32::MAX),
                Pid(0x10001)
            ))
        );
        assert_eq!(
            parse(
                r"\\server\share\.praxis\data\ffff\kv\critical\rid_to_slot.kv",
                "rid-directory"
            ),
            Some(Role::Rids(Cid(0xffff)))
        );
    }

    #[test]
    fn every_identity_position_requires_exact_nonzero_to_hex_spelling() {
        for invalid in [
            "0000",
            "0",
            "001",
            "00001",
            "FFFF",
            "100000000",
            "+001",
            "0x01",
            "..",
            "%31",
        ] {
            for position in [2, 4, 7, 9] {
                let mut parts = [
                    ".praxis", "data", "0001", "entities", "0002", "pages", "frames", "0003",
                    "pages", "0004",
                ];
                parts[position] = invalid;
                let label = format!("/source/{}.page", parts.join("/"));
                assert_eq!(parse(&label, "record-page"), None, "{label}");
            }
        }
    }

    #[test]
    fn suffixes_do_not_normalize_separators_or_traversal_or_extra_components() {
        for label in [
            "/source/.praxis/data/0001/entities/0002/pages/frames/0003/pages/0004.page/extra",
            "/source/.praxis/data/0001/entities/0002/pages/frames/0003/../pages/0004.page",
            r"/source/.praxis/data/0001/entities/0002/pages\frames/0003/pages/0004.page",
            "/source/.praxis/data/0001/entities/0002/pages/frames/0003/pages//0004.page",
            "/source/not.praxis/data/0001/entities/0002/pages/frames/0003/pages/0004.page",
        ] {
            assert_eq!(parse(label, "record-page"), None, "{label}");
        }
        assert_eq!(
            parse(
                "/source/.praxis/data/0001/kv/critical/rid_to_slot.kv",
                "record-page"
            ),
            None
        );
    }
}
