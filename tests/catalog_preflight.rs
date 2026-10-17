use praxis::catalog::{CatalogSnapshot, CatalogStore, CollectionCatalogEntry, UserCatalogEntry};
use praxis::identity::Cid;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, at: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(base).unwrap().to_path_buf();
            if relative == Path::new(".praxor.writer.lock") && path.is_file() {
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

fn snapshot(name: &str) -> CatalogSnapshot {
    CatalogSnapshot {
        collections: vec![CollectionCatalogEntry {
            cid: Cid(1),
            name: name.to_string(),
            retention_policy: None,
        }],
        users: vec![UserCatalogEntry {
            user_id: 1,
            name: name.to_string(),
            role: "owner".to_string(),
        }],
        ..CatalogSnapshot::default()
    }
}

#[test]
fn last_catalog_destination_preflight_does_not_change_earlier_catalogs() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let original = snapshot("original");
    catalog.save(&original).unwrap();
    let obstruction = catalog.layout().catalog_root().join("users.cat");
    let old_users = std::fs::read(&obstruction).unwrap();
    std::fs::remove_file(&obstruction).unwrap();
    std::fs::create_dir(&obstruction).unwrap();
    let before = tree(dir.path());
    let result = catalog.save(&snapshot("updated"));
    assert!(
        result.is_err() && tree(dir.path()) == before,
        "late destination error changed earlier catalogs: {result:?}"
    );
    std::fs::remove_dir(&obstruction).unwrap();
    std::fs::write(&obstruction, old_users).unwrap();
    assert_eq!(catalog.load().unwrap(), original);
}

#[test]
fn late_temporary_destination_preflight_keeps_shared_page_and_catalog_views_healthy() {
    use praxis::identity::{Aid, Eid, FieldId};
    use praxis::record::PageDatabase;
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = page
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    let original = snapshot("original");
    catalog.save(&original).unwrap();
    let obstruction = catalog.layout().catalog_root().join("users.tmp");
    std::fs::create_dir(&obstruction).unwrap();
    let before = tree(dir.path());
    let result = catalog.save(&snapshot("updated"));
    assert!(matches!(result, Err(praxis::PraxisError::Corrupt { .. })));
    assert_eq!(tree(dir.path()), before);
    assert_eq!(catalog.load().unwrap(), original);
    assert_eq!(page.get(rid).unwrap(), b"acknowledged");
    std::fs::remove_dir(obstruction).unwrap();
    catalog.save(&snapshot("updated")).unwrap();
}

#[test]
fn catalog_checksum_read_error_does_not_create_repair_or_poison_shared_page_data() {
    use praxis::identity::{Aid, Eid, FieldId};
    use praxis::record::PageDatabase;
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = page
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    let original = snapshot("original");
    catalog.save(&original).unwrap();
    let path = catalog.layout().catalog_root().join("users.cat");
    let good = std::fs::read(&path).unwrap();
    let mut damaged = good.clone();
    *damaged.last_mut().unwrap() ^= 1;
    std::fs::write(&path, damaged).unwrap();
    let before = tree(dir.path());
    assert!(matches!(
        catalog.load(),
        Err(praxis::PraxisError::Corrupt { .. })
    ));
    assert_eq!(tree(dir.path()), before);
    assert_eq!(page.get(rid).unwrap(), b"acknowledged");
    std::fs::write(&path, good).unwrap();
    assert_eq!(catalog.load().unwrap(), original);
}
