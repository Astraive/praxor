use praxis::PraxisError;
use praxis::catalog::*;
use praxis::config::Compression;
use praxis::identity::{Aid, Cid, Did, Eid, FieldId, Rid};
use praxis::io::crc32_ieee;
use praxis::record::{PageDatabase, PageRecordStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TABLES: [(&str, usize); 10] = [
    ("collections.cat", 12),
    ("entities.cat", 18),
    ("fixed_attrs.cat", 14),
    ("dynamic_attrs.cat", 14),
    ("indexes.cat", 20),
    ("vector_models.cat", 16),
    ("fulltext.cat", 12),
    ("graph.cat", 9),
    ("shards.cat", 16),
    ("users.cat", 12),
];

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = 0x5443_4154_u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn minimal_payload(name: &str, minimum: usize) -> Vec<u8> {
    let mut payload = vec![0; 4 + minimum];
    payload[..4].copy_from_slice(&1_u32.to_le_bytes());
    if name == "entities.cat" {
        payload[16] = 1;
    }
    payload
}

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Alias(PathBuf),
    Other,
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for item in std::fs::read_dir(path).unwrap() {
            let path = item.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if relative == Path::new(".praxor.writer.lock") && metadata.is_file() {
                continue;
            }
            let entry = if metadata.file_type().is_symlink() {
                Entry::Alias(std::fs::read_link(&path).unwrap())
            } else if metadata.is_dir() {
                visit(root, &path, out);
                Entry::Directory
            } else if metadata.is_file() {
                Entry::File(std::fs::read(&path).unwrap())
            } else {
                Entry::Other
            };
            out.insert(relative, entry);
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

struct Fixture {
    dir: tempfile::TempDir,
    catalog: CatalogStore,
    page: PageRecordStore,
    rid: Rid,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let database = PageDatabase::open(dir.path()).unwrap();
        let mut page = database.entity(Cid(1), Eid(2)).unwrap();
        let rid = page
            .put(&[(FieldId::Fixed(Aid(1)), b"acknowledged")])
            .unwrap();
        let catalog = CatalogStore::new(database);
        catalog.save(&CatalogSnapshot::default()).unwrap();
        Self {
            dir,
            catalog,
            page,
            rid,
        }
    }

    fn reject(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.catalog.layout().catalog_root().join(name), bytes).unwrap();
        let before = tree(self.dir.path());
        let result = self.catalog.load();
        assert!(
            matches!(result, Err(PraxisError::Corrupt { .. })),
            "{name}: {result:?}"
        );
        assert_eq!(tree(self.dir.path()), before);
        assert_eq!(self.page.get(self.rid).unwrap(), b"acknowledged");
    }
}

#[test]
fn every_table_rejects_trailing_rows_and_all_truncated_payload_prefixes() {
    for (name, minimum) in TABLES {
        let fixture = Fixture::new();
        let payload = minimal_payload(name, minimum);
        std::fs::write(
            fixture.catalog.layout().catalog_root().join(name),
            envelope(&payload),
        )
        .unwrap();
        fixture.catalog.load().unwrap();
        for end in 0..payload.len() {
            fixture.reject(name, &envelope(&payload[..end]));
        }
        let mut trailing = payload;
        trailing.push(0xff);
        fixture.reject(name, &envelope(&trailing));
    }
}

#[test]
fn envelope_requires_exact_checked_length_magic_version_and_checksum() {
    let fixture = Fixture::new();
    let valid = envelope(&0_u32.to_le_bytes());
    for end in 0..valid.len() {
        // A zero-length regular optional file intentionally means empty.
        if end != 0 {
            fixture.reject("users.cat", &valid[..end]);
        }
    }
    for offset in [0, 4, 9, 13] {
        let mut bytes = valid.clone();
        bytes[offset] ^= 0x80;
        fixture.reject("users.cat", &bytes);
    }
    for length in [0_u32, 3, 5, u32::MAX] {
        let mut bytes = valid.clone();
        bytes[5..9].copy_from_slice(&length.to_le_bytes());
        fixture.reject("users.cat", &bytes);
    }
    let mut trailing = valid;
    trailing.extend_from_slice(b"ignored?");
    fixture.reject("users.cat", &trailing);
}

#[test]
fn every_string_field_checks_actual_length_and_strict_utf8() {
    for (name, minimum, offsets) in [
        ("collections.cat", 12, &[8, 12][..]),
        ("entities.cat", 18, &[12, 17][..]),
        ("fixed_attrs.cat", 14, &[12][..]),
        ("dynamic_attrs.cat", 14, &[12][..]),
        ("indexes.cat", 20, &[12, 16, 20][..]),
        ("vector_models.cat", 16, &[8, 16][..]),
        ("fulltext.cat", 12, &[8, 12][..]),
        ("graph.cat", 9, &[8][..]),
        ("shards.cat", 16, &[12, 16][..]),
        ("users.cat", 12, &[8, 12][..]),
    ] {
        let fixture = Fixture::new();
        for &offset in offsets {
            let mut payload = minimal_payload(name, minimum);
            payload[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            fixture.reject(name, &envelope(&payload));
            let mut payload = minimal_payload(name, minimum);
            payload[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
            payload.insert(offset + 4, 0xff);
            fixture.reject(name, &envelope(&payload));
        }
    }
}

#[test]
fn flags_and_closed_tags_reject_unknown_wire_values() {
    for (name, minimum, offset, invalid) in [
        ("fixed_attrs.cat", 14, 17, &[2, 255][..]),
        ("dynamic_attrs.cat", 14, 16, &[2, 255][..]),
        ("graph.cat", 9, 12, &[2, 255][..]),
        ("entities.cat", 18, 16, &[0, 7, 255][..]),
        ("entities.cat", 18, 21, &[3, 255][..]),
    ] {
        let fixture = Fixture::new();
        for &value in invalid {
            let mut payload = minimal_payload(name, minimum);
            payload[offset] = value;
            fixture.reject(name, &envelope(&payload));
        }
    }
}

#[test]
fn full_id_ranges_utf8_empty_and_opaque_fields_preserve_v1_meaning() {
    let fixture = Fixture::new();
    let mut expected = CatalogSnapshot::default();
    for (i, storage_model) in [
        EntityStorageModel::Sql,
        EntityStorageModel::NoSql,
        EntityStorageModel::Graph,
        EntityStorageModel::Vector,
        EntityStorageModel::FullText,
        EntityStorageModel::Hybrid,
    ]
    .into_iter()
    .enumerate()
    {
        expected.entities.push(EntityCatalogEntry {
            cid: Cid(u32::MAX),
            eid: Eid(u32::MAX),
            name: "é猫🦀".into(),
            storage_model,
            primary_key: Some("鍵".into()),
            compression: [Compression::None, Compression::Lz4, Compression::Zstd][i % 3],
        });
    }
    for id in [0, 1, u16::MAX] {
        expected.fixed_attributes.push(FixedAttributeCatalogEntry {
            eid: Eid(0),
            aid: Aid(id),
            name: String::new(),
            type_code: 255,
            nullable: id != 0,
        });
        for inferred_type_code in [None, Some(0), Some(255)] {
            expected
                .dynamic_attributes
                .push(DynamicAttributeCatalogEntry {
                    eid: Eid(0),
                    did: Did(id),
                    name: "属性".into(),
                    inferred_type_code,
                });
        }
    }
    expected.collections = vec![
        CollectionCatalogEntry {
            cid: Cid(0),
            name: String::new(),
            retention_policy: Some("保管".into())
        };
        2
    ];
    expected.indexes.push(IndexCatalogEntry {
        eid: Eid(0),
        index_id: 0,
        name: "索引".into(),
        kind: "user-defined".into(),
        pointer_target: "../opaque:🦀".into(),
    });
    expected.vector_models.push(VectorModelCatalogEntry {
        model_id: 0,
        name: String::new(),
        dimensions: 0,
        metric: "unknown-but-opaque".into(),
    });
    expected.fulltext.push(FullTextCatalogEntry {
        eid: Eid(0),
        analyzer: "自由".into(),
        language: String::new(),
    });
    expected.graph.push(GraphCatalogEntry {
        eid: Eid(0),
        edge_label: String::new(),
        directed: true,
    });
    expected.shards.push(ShardCatalogEntry {
        shard_id: u32::MAX,
        cid: Cid(0),
        range_start: String::new(),
        range_end: "∞".into(),
    });
    expected.users.push(UserCatalogEntry {
        user_id: 0,
        name: "利用者".into(),
        role: String::new(),
    });
    fixture.catalog.save(&expected).unwrap();
    assert_eq!(fixture.catalog.load().unwrap(), expected);
}

#[test]
fn absent_optional_type_ignores_the_existing_unused_value_byte() {
    let fixture = Fixture::new();
    let mut payload = minimal_payload("dynamic_attrs.cat", 14);
    payload[17] = 255;
    std::fs::write(
        fixture
            .catalog
            .layout()
            .catalog_root()
            .join("dynamic_attrs.cat"),
        envelope(&payload),
    )
    .unwrap();
    let snapshot = fixture.catalog.load().unwrap();
    assert_eq!(snapshot.dynamic_attributes[0].inferred_type_code, None);
}

#[test]
fn rejected_load_keeps_catalog_clones_page_writes_and_managed_wal_healthy() {
    use praxis::config::WalSyncPolicy;
    let dir = tempfile::tempdir().unwrap();
    let database = PageDatabase::open(dir.path()).unwrap();
    let catalog = CatalogStore::new(database.clone());
    let clone = catalog.clone();
    let mut page = database.entity(Cid(1), Eid(2)).unwrap();
    let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
    let old = page
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"before")])
        .unwrap();
    catalog.save(&CatalogSnapshot::default()).unwrap();
    std::fs::write(
        catalog.layout().catalog_root().join("users.cat"),
        envelope(&[0, 0, 0, 0, 0xff]),
    )
    .unwrap();
    let before = tree(dir.path());
    assert!(matches!(clone.load(), Err(PraxisError::Corrupt { .. })));
    assert_eq!(tree(dir.path()), before);
    assert_eq!(page.get(old).unwrap(), b"before");
    let new = page
        .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"after")])
        .unwrap();
    wal.sync().unwrap();
    assert_eq!(page.get(new).unwrap(), b"after");
    let updated = CatalogSnapshot {
        users: vec![UserCatalogEntry {
            user_id: 1,
            name: "healthy".into(),
            role: String::new(),
        }],
        ..CatalogSnapshot::default()
    };
    clone.save(&updated).unwrap();
    assert_eq!(catalog.load().unwrap(), updated);
}

#[test]
fn missing_and_zero_length_regular_catalogs_stay_optional_without_repair() {
    let fixture = Fixture::new();
    for (name, _) in TABLES {
        let path = fixture.catalog.layout().catalog_root().join(name);
        std::fs::remove_file(&path).unwrap();
        let before = tree(fixture.dir.path());
        assert_eq!(fixture.catalog.load().unwrap(), CatalogSnapshot::default());
        assert_eq!(tree(fixture.dir.path()), before);
        std::fs::write(&path, []).unwrap();
        let before = tree(fixture.dir.path());
        assert_eq!(fixture.catalog.load().unwrap(), CatalogSnapshot::default());
        assert_eq!(tree(fixture.dir.path()), before);
    }
    assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
}

#[test]
fn directory_leaf_and_non_directory_parent_are_errors_without_poison_or_repair() {
    let fixture = Fixture::new();
    let path = fixture.catalog.layout().catalog_root().join("users.cat");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = tree(fixture.dir.path());
    assert!(fixture.catalog.load().is_err());
    assert_eq!(tree(fixture.dir.path()), before);
    assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
    std::fs::remove_dir(&path).unwrap();
    fixture.catalog.save(&CatalogSnapshot::default()).unwrap();
    let parent = fixture.catalog.layout().catalog_root();
    let backup = parent.with_extension("backup");
    std::fs::rename(&parent, &backup).unwrap();
    std::fs::write(&parent, []).unwrap();
    let before = tree(fixture.dir.path());
    assert!(fixture.catalog.load().is_err());
    assert_eq!(tree(fixture.dir.path()), before);
    assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
}

#[cfg(any(unix, windows))]
#[test]
fn regular_and_dangling_leaf_aliases_are_errors_without_touching_targets() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_file;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_file;
    let fixture = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("external.cat");
    std::fs::write(&target, envelope(&0_u32.to_le_bytes())).unwrap();
    let path = fixture.catalog.layout().catalog_root().join("users.cat");
    std::fs::remove_file(&path).unwrap();
    for target in [target, outside.path().join("missing.cat")] {
        symlink_file(&target, &path).unwrap();
        let before = tree(fixture.dir.path());
        let outside_before = tree(outside.path());
        assert!(fixture.catalog.load().is_err());
        assert_eq!(tree(fixture.dir.path()), before);
        assert_eq!(tree(outside.path()), outside_before);
        assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
        std::fs::remove_file(&path).unwrap();
    }
}

#[cfg(any(unix, windows))]
#[test]
fn aliased_catalog_parent_is_rejected_without_following_it() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    let fixture = Fixture::new();
    let parent = fixture.catalog.layout().catalog_root();
    let backup = parent.with_extension("backup");
    std::fs::rename(&parent, &backup).unwrap();
    symlink_dir(&backup, &parent).unwrap();
    let before = tree(fixture.dir.path());
    assert!(matches!(
        fixture.catalog.load(),
        Err(PraxisError::Corrupt { .. })
    ));
    assert_eq!(tree(fixture.dir.path()), before);
    assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
}

#[cfg(windows)]
#[test]
fn non_not_found_read_error_is_not_an_absent_optional_catalog() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let path = fixture.catalog.layout().catalog_root().join("users.cat");
    let before = tree(fixture.dir.path());
    let exclusive = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    assert!(matches!(fixture.catalog.load(), Err(PraxisError::Io(_))));
    assert_eq!(fixture.page.get(fixture.rid).unwrap(), b"acknowledged");
    drop(exclusive);
    assert_eq!(tree(fixture.dir.path()), before);
    assert_eq!(fixture.catalog.load().unwrap(), CatalogSnapshot::default());
}
