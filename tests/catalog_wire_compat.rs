use praxis::catalog::*;
use praxis::config::Compression;
use praxis::identity::{Aid, Cid, Did, Eid};

fn fixture() -> CatalogSnapshot {
    CatalogSnapshot {
        collections: vec![CollectionCatalogEntry {
            cid: Cid(0),
            name: "c".into(),
            retention_policy: None,
        }],
        entities: vec![EntityCatalogEntry {
            cid: Cid(0),
            eid: Eid(0),
            name: "e".into(),
            storage_model: EntityStorageModel::Sql,
            primary_key: None,
            compression: Compression::None,
        }],
        fixed_attributes: vec![FixedAttributeCatalogEntry {
            eid: Eid(0),
            aid: Aid(0),
            name: "f".into(),
            type_code: 255,
            nullable: true,
        }],
        dynamic_attributes: vec![DynamicAttributeCatalogEntry {
            eid: Eid(0),
            did: Did(0),
            name: "d".into(),
            inferred_type_code: Some(255),
        }],
        indexes: vec![IndexCatalogEntry {
            eid: Eid(0),
            index_id: 0,
            name: "i".into(),
            kind: "custom".into(),
            pointer_target: "opaque".into(),
        }],
        vector_models: vec![VectorModelCatalogEntry {
            model_id: 0,
            name: "v".into(),
            dimensions: 0,
            metric: "custom".into(),
        }],
        fulltext: vec![FullTextCatalogEntry {
            eid: Eid(0),
            analyzer: "f".into(),
            language: "l".into(),
        }],
        graph: vec![GraphCatalogEntry {
            eid: Eid(0),
            edge_label: "g".into(),
            directed: false,
        }],
        shards: vec![ShardCatalogEntry {
            shard_id: 0,
            cid: Cid(0),
            range_start: "".into(),
            range_end: "".into(),
        }],
        users: vec![UserCatalogEntry {
            user_id: 0,
            name: "u".into(),
            role: "r".into(),
        }],
    }
}

#[test]
fn all_ten_v1_catalog_files_keep_their_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let original = fixture();
    catalog.save(&original).unwrap();
    assert_eq!(catalog.load().unwrap(), original);
    for (name, expected) in [
        (
            "collections.cat",
            "5441435401110000002023a0870100000000000000010000006300000000",
        ),
        (
            "entities.cat",
            "544143540117000000b7a18f3a0100000000000000000000000100000065010000000000",
        ),
        (
            "fixed_attrs.cat",
            "544143540113000000f538e4030100000000000000000000000100000066ff01",
        ),
        (
            "dynamic_attrs.cat",
            "544143540113000000b3ff5ad0010000000000000000000000010000006401ff",
        ),
        (
            "indexes.cat",
            "5441435401250000009bd548e0010000000000000000000000010000006906000000637573746f6d060000006f7061717565",
        ),
        (
            "vector_models.cat",
            "54414354011b0000008b00eace010000000000000001000000760000000006000000637573746f6d",
        ),
        (
            "fulltext.cat",
            "54414354011200000016fa42c001000000000000000100000066010000006c",
        ),
        (
            "graph.cat",
            "54414354010e00000074b654ad0100000000000000010000006700",
        ),
        (
            "shards.cat",
            "544143540114000000cba0b26a0100000000000000000000000000000000000000",
        ),
        (
            "users.cat",
            "54414354011200000040b70fbf010000000000000001000000750100000072",
        ),
    ] {
        let bytes = std::fs::read(catalog.layout().catalog_root().join(name)).unwrap();
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(hex, expected, "v1 bytes changed for {name}");
    }
}

#[test]
fn zero_and_duplicate_catalog_ids_keep_existing_optional_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let mut original = fixture();
    original.collections.push(original.collections[0].clone());
    original.entities.push(original.entities[0].clone());
    original
        .fixed_attributes
        .push(original.fixed_attributes[0].clone());
    original
        .dynamic_attributes
        .push(original.dynamic_attributes[0].clone());
    original.indexes.push(original.indexes[0].clone());
    original
        .vector_models
        .push(original.vector_models[0].clone());
    original.fulltext.push(original.fulltext[0].clone());
    original.graph.push(original.graph[0].clone());
    original.shards.push(original.shards[0].clone());
    original.users.push(original.users[0].clone());
    catalog.save(&original).unwrap();
    drop(catalog);
    let catalog = CatalogStore::open(dir.path()).unwrap();
    assert_eq!(catalog.load().unwrap(), original);
}

#[test]
fn optional_empty_strings_keep_the_existing_v1_none_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = CatalogStore::open(dir.path()).unwrap();
    let mut original = fixture();
    original.collections[0].retention_policy = Some(String::new());
    original.entities[0].primary_key = Some(String::new());
    catalog.save(&original).unwrap();
    let decoded = catalog.load().unwrap();
    assert_eq!(decoded.collections[0].retention_policy, None);
    assert_eq!(decoded.entities[0].primary_key, None);
}
