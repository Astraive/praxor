use super::*;
use crate::api::service::{GetPageRecordRequest, PagePrimitiveStorageService, RequestContext};
use crate::config::WalSyncPolicy;
use crate::identity::{FieldId, Rid};
use crate::sdk::LocalPagepraxisClient;
use std::collections::BTreeMap;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::Duration;

fn snapshot(name: &str) -> CatalogSnapshot {
    CatalogSnapshot {
        collections: vec![CollectionCatalogEntry {
            cid: Cid(1),
            name: name.into(),
            retention_policy: None,
        }],
        entities: vec![EntityCatalogEntry {
            cid: Cid(1),
            eid: Eid(2),
            name: name.into(),
            storage_model: EntityStorageModel::Sql,
            primary_key: None,
            compression: Compression::None,
        }],
        users: vec![UserCatalogEntry {
            user_id: 1,
            name: name.into(),
            role: name.into(),
        }],
        ..CatalogSnapshot::default()
    }
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, at: &Path, files: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(at).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(base).unwrap().to_path_buf();
            if relative == Path::new(".praxor.writer.lock") && path.is_file() {
                continue;
            }
            files.insert(
                relative,
                if path.is_dir() {
                    None
                } else {
                    Some(std::fs::read(&path).unwrap())
                },
            );
            if path.is_dir() {
                visit(base, &path, files);
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn late_publication_io_error_poison_is_shared_by_every_view_and_retains_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let retained = catalog.clone();
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let rid = page
        .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let service = PagePrimitiveStorageService::new(database.clone());
    let sdk = LocalPagepraxisClient::new(service.clone());
    let original = snapshot("original");
    catalog.save(&original).unwrap();
    let users_before = std::fs::read(catalog.layout().catalog_root().join("users.cat")).unwrap();
    let obstruction = catalog.layout().catalog_root().join("users.tmp");
    let result = catalog.save_prepared(&snapshot("updated"), |prepared| {
        prepared.publish_with_hook(|index| {
            if index == 0 {
                std::fs::create_dir(&obstruction)?;
            }
            Ok(())
        })
    });
    assert!(matches!(result, Err(PraxisError::Io(_))));
    // Actual publication occurred before the late IO error, but it is not an
    // acknowledged complete snapshot and no ten-file rollback is promised.
    assert_ne!(
        decode::read_optional(
            &catalog.layout().catalog_root().join("collections.cat"),
            decode::decode_collections
        )
        .unwrap(),
        original.collections
    );
    assert_eq!(
        std::fs::read(catalog.layout().catalog_root().join("users.cat")).unwrap(),
        users_before
    );
    let after_failure = tree(dir.path());
    assert!(matches!(
        catalog.load(),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        retained.save(&original),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        page.get(rid),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        page.put(&[(FieldId::Fixed(Aid(1)), b"retry")]),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        page.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"retry")]),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        service.get_page_record(GetPageRecordRequest {
            context: RequestContext::new("catalog-fault"),
            cid: Cid(1),
            eid: Eid(2),
            rid
        }),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        sdk.get_page_record(RequestContext::new("catalog-fault"), Cid(1), Eid(2), rid),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        wal.sync(),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        wal.bytes_written(),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        database.entity(Cid(2), Eid(2)),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert_eq!(tree(dir.path()), after_failure);
    drop(sdk);
    drop(service);
    drop(wal);
    drop(page);
    drop(catalog);
    drop(database);
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
    drop(retained);
    assert!(!matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::AlreadyOpen { .. })
    ));
}

#[test]
fn page_publication_error_poison_reaches_existing_catalog_clones() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let clone = catalog.clone();
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    page.put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
        .unwrap();
    catalog.save(&snapshot("original")).unwrap();
    let obstruction = catalog
        .layout()
        .critical_map_path(Cid(1), "rid_to_entity")
        .path;
    std::fs::remove_file(&obstruction).unwrap();
    std::fs::create_dir(&obstruction).unwrap();
    assert!(matches!(
        page.put(&[(FieldId::Fixed(Aid(1)), b"uncertain")]),
        Err(PraxisError::Io(_))
    ));
    assert!(matches!(
        catalog.load(),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
    assert!(matches!(
        clone.save(&snapshot("retry")),
        Err(PraxisError::PageRecoveryRequired { .. })
    ));
}

struct ResumeOnDrop(Sender<()>);
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[test]
fn paused_catalog_publication_hides_split_epochs_from_load_page_and_wal_operations() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let original = snapshot("original");
    let updated = snapshot("updated");
    catalog.save(&original).unwrap();
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let (published_tx, published_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let resume = ResumeOnDrop(resume_tx);
    let writer = catalog.clone();
    let expected = updated.clone();
    let writer = std::thread::spawn(move || {
        writer.save_prepared(&updated, |prepared| {
            prepared.publish_with_hook(|index| {
                if index == 0 {
                    published_tx.send(()).unwrap();
                    resume_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(std::io::Error::other)?;
                }
                Ok(())
            })
        })
    });
    published_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // This is a real split-file window, independently inspected via private raw
    // codecs while the supported root owner is paused under its guard.
    assert_eq!(
        decode::read_optional(
            &catalog.layout().catalog_root().join("collections.cat"),
            decode::decode_collections
        )
        .unwrap(),
        expected.collections
    );
    assert_eq!(
        decode::read_optional(
            &catalog.layout().catalog_root().join("entities.cat"),
            decode::decode_entities
        )
        .unwrap(),
        original.entities
    );
    let (started_tx, started_rx) = mpsc::channel();
    let (read_tx, read_rx) = mpsc::channel();
    let reader = catalog.clone();
    let started = started_tx.clone();
    let reader = std::thread::spawn(move || {
        started.send(()).unwrap();
        read_tx.send(reader.load()).unwrap();
    });
    let (page_tx, page_rx) = mpsc::channel();
    let started = started_tx.clone();
    let page_writer = std::thread::spawn(move || {
        started.send(()).unwrap();
        page_tx
            .send(page.put(&[(FieldId::Fixed(Aid(1)), b"after catalog")]))
            .unwrap();
    });
    let (wal_tx, wal_rx) = mpsc::channel();
    let syncer = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        wal_tx.send(wal.sync()).unwrap();
    });
    for _ in 0..3 {
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    assert!(matches!(
        read_rx.recv_timeout(Duration::from_millis(50)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(matches!(page_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(matches!(wal_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(resume);
    writer.join().unwrap().unwrap();
    assert_eq!(
        read_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(
        page_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        Rid(1)
    );
    wal_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    reader.join().unwrap();
    page_writer.join().unwrap();
    syncer.join().unwrap();
}
