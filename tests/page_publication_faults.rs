use praxis::PraxisError;
use praxis::api::service::{GetPageRecordRequest, PagePrimitiveStorageService, RequestContext};
use praxis::config::WalSyncPolicy;
use praxis::identity::{Aid, Cid, Eid, Fid, FieldId, Pid, Rid};
use praxis::record::{PageDatabase, RidDirectory};
use praxis::sdk::LocalPagepraxisClient;
use praxis::wal::PageWal;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(base: &Path, at: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            // Windows denies reads of the live OS-locked portion. Its permanent
            // caller-base lease is not part of the mutable page publication set.
            if path.strip_prefix(base).unwrap() == Path::new(".praxor.writer.lock") {
                continue;
            }
            output.insert(
                path.strip_prefix(base).unwrap().to_path_buf(),
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

#[test]
fn io_failures_across_publication_stages_poison_all_facades_and_prevent_retries() {
    for stage in [
        "page-temp",
        "slot-directory",
        "page-header",
        "rid-directory",
        "first-sidecar",
        "last-sidecar",
        "manifest",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let database = PageDatabase::open(dir.path()).unwrap();
        let mut old = database.entity(Cid(1), Eid(2)).unwrap();
        let rid = old
            .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
            .unwrap();
        let reader = old.clone();
        let mut pending = database.entity(Cid(1), Eid(3)).unwrap();
        let service = PagePrimitiveStorageService::new(database.clone());
        let client = LocalPagepraxisClient::new(service.clone());
        let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        let layout = old.layout();
        let page = layout.page_path(Cid(1), Eid(3), Fid(1), Pid(1)).path;
        let slots = layout.slot_directory_root(Cid(1), Eid(3), Fid(1), Pid(1));
        let directory = layout.critical_map_path(Cid(1), "rid_to_slot").path;
        let obstruction = match stage {
            "page-temp" => page.with_extension("tmp"),
            "slot-directory" => slots.join("slot.directory"),
            "page-header" => slots.join("page.header"),
            "rid-directory" => directory.with_extension("tmp"),
            "first-sidecar" => layout.critical_map_path(Cid(1), "rid_to_page").path,
            "last-sidecar" => layout.critical_map_path(Cid(1), "sequence").path,
            _ => layout.page_manifest_path().path.with_extension("tmp"),
        };
        if obstruction.is_file() {
            std::fs::remove_file(&obstruction).unwrap();
        }
        std::fs::create_dir_all(&obstruction).unwrap();
        let result = pending.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"uncertain")]);
        assert!(
            matches!(result, Err(PraxisError::Io(_))),
            "{stage}: {result:?}"
        );
        assert_eq!(
            PageWal::replay(wal.path()).unwrap().len(),
            1,
            "{stage}: WAL must precede failing page IO"
        );
        assert_eq!(
            page.exists(),
            stage != "page-temp",
            "{stage}: physical phase was not reached"
        );
        let (physical_map, _, _, _) = RidDirectory::load_binary(&directory).unwrap();
        assert_eq!(
            physical_map.resolve(Rid(2)).is_ok(),
            matches!(stage, "first-sidecar" | "last-sidecar"),
            "{stage}: directory publication phase"
        );
        let after_failure = tree(dir.path());
        assert!(
            matches!(
                reader.get(rid),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(
                old.directory(),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(
                old.put(&[(FieldId::Fixed(Aid(1)), b"retry")]),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(
                pending.delete(Rid(2)),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(
                service.get_page_record(GetPageRecordRequest {
                    context: RequestContext::new("failed-service"),
                    cid: Cid(1),
                    eid: Eid(2),
                    rid
                }),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(
                client.get_page_record(RequestContext::new("failed-sdk"), Cid(1), Eid(2), rid),
                Err(PraxisError::PageRecoveryRequired { .. })
            ),
            "{stage}"
        );
        assert!(
            matches!(wal.sync(), Err(PraxisError::PageRecoveryRequired { .. })),
            "{stage}"
        );
        assert!(
            matches!(
                PageDatabase::open(dir.path()),
                Err(PraxisError::AlreadyOpen { .. })
            ),
            "{stage}"
        );
        assert_eq!(
            tree(dir.path()),
            after_failure,
            "{stage}: poisoned retries performed IO"
        );
    }
}

#[test]
fn failed_manifest_publication_cannot_reopen_with_a_stale_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let mut store = database.entity(Cid(1), Eid(2)).unwrap();
    store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let obstruction = store
        .layout()
        .page_manifest_path()
        .path
        .with_extension("tmp");
    std::fs::create_dir(&obstruction).unwrap();
    let result = store.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"uncertain")]);
    assert!(matches!(result, Err(PraxisError::Io(_))));
    drop(wal);
    drop(store);
    drop(database);
    // Remove only our empty fault directory. The overwritten page and old
    // manifest remain real evidence of the separately tracked atomicity gap.
    std::fs::remove_dir(obstruction).unwrap();
    let before = tree(dir.path());
    assert!(matches!(
        PageDatabase::open(dir.path()),
        Err(PraxisError::Corrupt { .. })
    ));
    assert!(matches!(
        PageDatabase::recover_from_page_wal(dir.path()),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(tree(dir.path()), before);
}
