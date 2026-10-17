use praxis::catalog::{
    CatalogSnapshot, CatalogStore, CollectionCatalogEntry, DynamicAttributeCatalogEntry,
    EntityCatalogEntry, EntityStorageModel, FixedAttributeCatalogEntry, FullTextCatalogEntry,
    GraphCatalogEntry, IndexCatalogEntry, ShardCatalogEntry, UserCatalogEntry,
    VectorModelCatalogEntry,
};
use praxis::config::Compression;
use praxis::identity::{Aid, Cid, Did, Eid};
use tempfile::tempdir;

#[test]
fn catalog_store_loads_empty_doc_shape_catalog_files() {
    let dir = tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();

    assert_eq!(store.load().unwrap(), CatalogSnapshot::default());
    assert!(store.layout().catalog_root().join("indexes.cat").exists());
    assert!(
        store
            .layout()
            .catalog_root()
            .join("vector_models.cat")
            .exists()
    );
    assert!(store.layout().catalog_root().join("fulltext.cat").exists());
    assert!(store.layout().catalog_root().join("graph.cat").exists());
}

#[test]
fn catalog_store_persists_collection_entity_and_attribute_catalogs() {
    let dir = tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();
    let snapshot = CatalogSnapshot {
        collections: vec![CollectionCatalogEntry {
            cid: Cid(1),
            name: "users".into(),
            retention_policy: Some("hot-30d".into()),
        }],
        entities: vec![EntityCatalogEntry {
            cid: Cid(1),
            eid: Eid(2),
            name: "students".into(),
            storage_model: EntityStorageModel::Hybrid,
            primary_key: Some("id".into()),
            compression: Compression::Lz4,
        }],
        fixed_attributes: vec![FixedAttributeCatalogEntry {
            eid: Eid(2),
            aid: Aid(3),
            name: "marks".into(),
            type_code: 0x02,
            nullable: false,
        }],
        dynamic_attributes: vec![DynamicAttributeCatalogEntry {
            eid: Eid(2),
            did: Did(0x00af),
            name: "teacher".into(),
            inferred_type_code: Some(0x30),
        }],
        indexes: vec![IndexCatalogEntry {
            eid: Eid(2),
            index_id: 1,
            name: "students_by_marks".into(),
            kind: "btree".into(),
            pointer_target: "RID".into(),
        }],
        vector_models: vec![VectorModelCatalogEntry {
            model_id: 1,
            name: "student_embedding".into(),
            dimensions: 384,
            metric: "cosine".into(),
        }],
        fulltext: vec![FullTextCatalogEntry {
            eid: Eid(2),
            analyzer: "standard".into(),
            language: "en".into(),
        }],
        graph: vec![GraphCatalogEntry {
            eid: Eid(2),
            edge_label: "knows".into(),
            directed: true,
        }],
        shards: vec![ShardCatalogEntry {
            shard_id: 1,
            cid: Cid(1),
            range_start: "0000000000000001".into(),
            range_end: "00000000ffffffff".into(),
        }],
        users: vec![UserCatalogEntry {
            user_id: 1,
            name: "root".into(),
            role: "owner".into(),
        }],
    };

    store.save(&snapshot).unwrap();
    drop(store);
    let store = CatalogStore::open(dir.path()).unwrap();
    let loaded = store.load().unwrap();

    assert_eq!(loaded, snapshot);
    assert!(
        store
            .layout()
            .catalog_root()
            .join("collections.cat")
            .exists()
    );
    assert!(store.layout().catalog_root().join("entities.cat").exists());
    assert!(
        store
            .layout()
            .catalog_root()
            .join("indexes.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        store
            .layout()
            .catalog_root()
            .join("vector_models.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        store
            .layout()
            .catalog_root()
            .join("fulltext.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        store
            .layout()
            .catalog_root()
            .join("graph.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        store
            .layout()
            .catalog_root()
            .join("shards.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        store
            .layout()
            .catalog_root()
            .join("users.cat")
            .metadata()
            .unwrap()
            .len()
            > 0
    );
}

#[test]
fn catalog_store_rejects_corrupted_catalog_payload() {
    let dir = tempdir().unwrap();
    let store = CatalogStore::open(dir.path()).unwrap();
    store
        .save(&CatalogSnapshot {
            collections: vec![CollectionCatalogEntry {
                cid: Cid(1),
                name: "users".into(),
                retention_policy: None,
            }],
            ..CatalogSnapshot::default()
        })
        .unwrap();

    let path = store.layout().catalog_root().join("collections.cat");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();

    assert!(store.load().is_err());
}
