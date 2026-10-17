use praxis::catalog::{CatalogSnapshot, CatalogStore};
use praxis::record::PageDatabase;
use praxis::store::{RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine, PraxisError};
use std::any::Any;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn incompatible_owner(root: &Path, kind: u8) -> Box<dyn Any> {
    match kind {
        0 => Box::new(PraxisEngine::open(PraxisConfig::new(root)).unwrap()),
        1 => Box::new(StorageEngine::open(root, 1024).unwrap()),
        _ => Box::new(RecordStore::open(root).unwrap()),
    }
}

pub fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, at: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(base).unwrap().to_path_buf();
            if matches!(
                relative.to_str(),
                Some(
                    ".praxor.writer.lock"
                        | "primary/.praxor.writer.lock"
                        | "primary\\.praxor.writer.lock"
                )
            ) && path.is_file()
            {
                continue;
            }
            output.insert(
                relative,
                if path.is_dir() {
                    None
                } else {
                    Some(std::fs::read(&path).unwrap())
                },
            );
            if path.is_dir() {
                visit(base, &path, output);
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn catalog_must_not_initialize_an_incompatible_root(kind: u8, live: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let mut owner = Some(incompatible_owner(root, kind));
    if !live {
        drop(owner.take());
    }
    let before = tree(root);
    let result = CatalogStore::open(root);
    let refused = if live {
        matches!(result, Err(PraxisError::AlreadyOpen { .. }))
    } else {
        matches!(
            result,
            Err(PraxisError::StorageFormatMismatch { .. }
                | PraxisError::StorageFormatAmbiguous { .. }
                | PraxisError::StorageFormatIncomplete { .. }
                | PraxisError::StorageFormatUnsupported { .. })
        )
    };
    assert!(
        refused && tree(root) == before,
        "catalog bypassed ownership/admission: live={live}, kind={kind}, result={result:?}, namespace_created={}",
        root.join(".praxis").exists()
    );
}

#[test]
fn catalog_refuses_live_core() {
    catalog_must_not_initialize_an_incompatible_root(0, true);
}
#[test]
fn catalog_refuses_closed_core() {
    catalog_must_not_initialize_an_incompatible_root(0, false);
}
#[test]
fn catalog_refuses_live_pointer() {
    catalog_must_not_initialize_an_incompatible_root(1, true);
}
#[test]
fn catalog_refuses_closed_pointer() {
    catalog_must_not_initialize_an_incompatible_root(1, false);
}
#[test]
fn catalog_refuses_live_record() {
    catalog_must_not_initialize_an_incompatible_root(2, true);
}
#[test]
fn catalog_refuses_closed_record() {
    catalog_must_not_initialize_an_incompatible_root(2, false);
}
#[test]
fn fresh_catalog_control() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    assert_eq!(catalog.load().unwrap(), CatalogSnapshot::default());
}
#[test]
fn independent_catalog_owners_are_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let _first = CatalogStore::open(dir.path()).unwrap();
    assert!(matches!(
        CatalogStore::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
}
#[test]
fn catalog_and_page_independent_owners_exclude_each_other() {
    for catalog_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        if catalog_first {
            let _catalog = CatalogStore::open(dir.path()).unwrap();
            assert!(matches!(
                PageDatabase::open(dir.path()),
                Err(PraxisError::AlreadyOpen { .. })
            ));
        } else {
            let _page = PageDatabase::open(dir.path()).unwrap();
            assert!(matches!(
                CatalogStore::open(dir.path()),
                Err(PraxisError::AlreadyOpen { .. })
            ));
        }
    }
}
#[test]
fn catalog_clone_retains_ownership_until_final_drop() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let clone = catalog.clone();
    drop(catalog);
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(clone.load().unwrap(), CatalogSnapshot::default());
    drop(clone);
    PageDatabase::open(dir.path()).unwrap();
}
#[test]
fn loading_a_missing_optional_catalog_does_not_repair_it() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let path = catalog.layout().catalog_root().join("users.cat");
    std::fs::remove_file(&path).unwrap();
    let before = tree(dir.path());
    assert_eq!(catalog.load().unwrap(), CatalogSnapshot::default());
    assert_eq!(tree(dir.path()), before);
    assert!(!path.exists());
}

#[test]
fn explicit_catalog_and_page_views_share_one_owner_and_final_catalog_clone_retains_it() {
    use praxis::config::WalSyncPolicy;
    use praxis::identity::{Aid, Cid, Eid, FieldId};
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let retained = catalog.clone();
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    catalog.save(&CatalogSnapshot::default()).unwrap();
    let rid = page
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"shared")])
        .unwrap();
    assert_eq!(page.get(rid).unwrap(), b"shared");
    assert_eq!(retained.load().unwrap(), CatalogSnapshot::default());
    drop(catalog);
    drop(page);
    drop(wal);
    drop(database);
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    assert_eq!(retained.load().unwrap(), CatalogSnapshot::default());
    drop(retained);
    let reopened = PageDatabase::open(dir.path()).unwrap();
    assert_eq!(
        reopened.entity(Cid(1), Eid(2)).unwrap().get(rid).unwrap(),
        b"shared"
    );
}

#[test]
fn catalog_open_preserves_unrelated_application_siblings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), b"application").unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    let before = tree(dir.path());
    let catalog = CatalogStore::open(dir.path()).unwrap();
    catalog.save(&CatalogSnapshot::default()).unwrap();
    let after = tree(dir.path());
    for (path, value) in before {
        assert_eq!(after.get(&path), Some(&value));
    }
}

#[cfg(any(unix, windows))]
#[test]
fn catalog_open_refuses_a_namespace_alias_without_touching_the_target() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let outside = tempfile::tempdir().unwrap();
    drop(CatalogStore::open(outside.path()).unwrap());
    let before = tree(outside.path());
    let dir = tempfile::tempdir().unwrap();
    let alias = dir.path().join(".praxis");
    symlink_dir(outside.path().join(".praxis"), &alias).unwrap();
    let target = std::fs::read_link(&alias).unwrap();
    assert!(matches!(
        CatalogStore::open(dir.path()),
        Err(PraxisError::StorageFormatAmbiguous { .. })
    ));
    assert_eq!(std::fs::read_link(alias).unwrap(), target);
    assert_eq!(tree(outside.path()), before);
}
