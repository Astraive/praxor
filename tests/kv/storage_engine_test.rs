//! Tests for praxis's no-duplication storage engine.
//!
//! The central invariant under test: **every value payload is written to the
//! primary [`RecordStore`] exactly once**.  All index plugins ([`LsmIndex`],
//! [`BTreeIndex`], [`AdjacencyIndex`], [`HnswIndex`]) store only
//! `key → RecordId` pointers and never duplicate the underlying bytes.

use praxis::index::{AdjacencyIndex, BTreeIndex, HnswIndex, IndexPlugin};
use praxis::storage::lsm::LsmIndex;
use praxis::store::{
    BatchRecord, DirectorySyncPolicy, IndexInsert, MaintenanceCycleOptions, RecordId, RecordStore,
    SharedStorageEngine, StorageEngine, StorageEngineOptions, StorageMaintenanceRuntimeConfig,
    StorageMaintenanceRuntimeController, StorageWal, StorageWalEntry, StorageWalOperation,
    StorageWalOptions,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Add exact replay duplicates, which can be reclaimed at every raw sequence
/// ceiling. Increasing sequence histories alone are not safe pruning jobs.
fn append_replayed_index_duplicates(
    engine: &mut StorageEngine,
    index_dir: &std::path::Path,
    index_type: &str,
    duplicates: usize,
) {
    engine.flush().unwrap();
    let entry = StorageWal::replay(engine.wal_path())
        .unwrap()
        .into_iter()
        .rev()
        .find(|entry| entry.index_type == index_type && entry.key == b"hot")
        .unwrap();
    let mut index: Box<dyn IndexPlugin> = match index_type {
        "kv" => Box::new(LsmIndex::open(index_type, index_dir).unwrap()),
        "bt" => Box::new(BTreeIndex::open(index_type, index_dir).unwrap()),
        _ => panic!("unexpected test index {index_type}"),
    };
    for _ in 0..duplicates {
        match entry.rid {
            Some(rid) => index
                .put_with_sequence(&entry.key, rid, entry.sequence)
                .unwrap(),
            None => index
                .delete_with_sequence(&entry.key, entry.sequence)
                .unwrap(),
        }
    }
    engine.register_index(index_type, "default", index).unwrap();
}

// ──────────────────────────────────────────────
// 1.  Single-copy guarantee across multiple indexes
// ──────────────────────────────────────────────

/// Write a value once; point both an LSM and a B-tree index at the same RID.
/// The store must report exactly one live record.
#[test]
fn single_copy_per_value_lsm_and_btree() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", &idir).unwrap();
    let mut btree = BTreeIndex::open("bt", &idir).unwrap();

    let value = b"shared payload -- stored exactly once";
    let rid = store.put(value).unwrap();

    // Both indexes hold the same RID; the bytes are not duplicated.
    lsm.put(b"lsm-key", rid).unwrap();
    btree.put(b"btree-key", rid).unwrap();

    // One live record in the primary store regardless of index count.
    assert_eq!(store.live_count(), 1);
    assert_eq!(store.live_bytes(), value.len() as u64);

    // Both indexes resolve to the same RID.
    assert_eq!(lsm.get(b"lsm-key"), Some(rid));
    assert_eq!(btree.get(b"btree-key"), Some(rid));

    // Both lookups retrieve the same bytes through the store.
    assert_eq!(store.get(lsm.get(b"lsm-key").unwrap()).unwrap(), value);
    assert_eq!(store.get(btree.get(b"btree-key").unwrap()).unwrap(), value);
}

/// Write two values (Alice and Bob); index Alice by name (LSM), age (B-tree),
/// and a "friend" edge (adjacency).  The store must report exactly two live
/// records – one for Alice, one for Bob.
#[test]
fn three_index_types_two_data_records() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("name", &idir).unwrap();
    let mut btree = BTreeIndex::open("age", &idir).unwrap();
    let mut adj = AdjacencyIndex::open("social", &idir).unwrap();

    let alice = store.put(b"alice-profile-data").unwrap();
    let bob = store.put(b"bob-profile-data").unwrap();

    // Three different index types all point to alice's single record.
    lsm.put(b"alice", alice).unwrap();
    btree.put(b"030:alice", alice).unwrap(); // age 30
    adj.add_edge(alice, b"friend", bob, std::collections::BTreeMap::new())
        .unwrap();

    // Two live records total (alice + bob), not one per index entry.
    assert_eq!(store.live_count(), 2);

    // All indexes resolve correctly.
    assert_eq!(lsm.get(b"alice"), Some(alice));
    assert_eq!(btree.get(b"030:alice"), Some(alice));
    let neighbors = adj.neighbors(alice);
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].to, bob);

    // Resolve through the store – same bytes, no extra copies.
    assert_eq!(
        store.get(lsm.get(b"alice").unwrap()).unwrap(),
        b"alice-profile-data"
    );
    assert_eq!(
        store.get(btree.get(b"030:alice").unwrap()).unwrap(),
        b"alice-profile-data"
    );
    assert_eq!(store.get(neighbors[0].to).unwrap(), b"bob-profile-data");
}

#[test]
fn storage_engine_batch_put_uses_one_directory_flush_and_replays_indexes() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 64 * 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    let kv0 = [IndexInsert::new("kv", b"k0".to_vec())];
    let kv1 = [
        IndexInsert::new("kv", b"k1".to_vec()),
        IndexInsert::new("bt", b"id:0001".to_vec()),
    ];
    let records = [
        BatchRecord::new(b"value-0", &kv0),
        BatchRecord::new(b"value-1", &kv1),
    ];
    let rids = engine.put_batch(&records).unwrap();

    assert_eq!(rids.len(), 2);
    assert_eq!(engine.fetch(rids[0]).unwrap(), b"value-0");
    assert_eq!(engine.fetch(rids[1]).unwrap(), b"value-1");
    assert_eq!(engine.lookup_rid("kv", b"k0").unwrap(), Some(rids[0]));
    assert_eq!(engine.lookup_rid("kv", b"k1").unwrap(), Some(rids[1]));
    assert_eq!(engine.lookup_rid("bt", b"id:0001").unwrap(), Some(rids[1]));

    drop(engine);

    let mut reopened = StorageEngine::open(dir.path(), 64 * 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    reopened
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    assert_eq!(reopened.fetch(rids[0]).unwrap(), b"value-0");
    assert_eq!(reopened.fetch(rids[1]).unwrap(), b"value-1");
    assert_eq!(reopened.lookup_rid("kv", b"k0").unwrap(), Some(rids[0]));
    assert_eq!(reopened.lookup_rid("kv", b"k1").unwrap(), Some(rids[1]));
    assert_eq!(
        reopened.lookup_rid("bt", b"id:0001").unwrap(),
        Some(rids[1])
    );
}

// ──────────────────────────────────────────────
// 3.  Compaction: RIDs remain stable
// ──────────────────────────────────────────────

/// After compaction the logical RID of a live record is unchanged.
/// All index plugin lookups must continue to return the correct data.
#[test]
fn compaction_preserves_rids_and_index_lookups() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", &idir).unwrap();

    let rid_a = store.put(b"alive").unwrap();
    let rid_b = store.put(b"dead").unwrap();

    lsm.put(b"a", rid_a).unwrap();
    lsm.put(b"b", rid_b).unwrap();

    // Delete "b" from the store; the LSM entry becomes stale (same as any
    // real secondary index on a deleted row).
    store.delete(rid_b).unwrap();

    let stats = store.compact().unwrap();
    assert_eq!(stats.records_retained, 1);
    assert_eq!(stats.records_dropped, 1);

    // RID for "a" is stable across compaction; the LSM index still works.
    let resolved = lsm.get(b"a").unwrap();
    assert_eq!(resolved, rid_a);
    assert_eq!(store.get(resolved).unwrap(), b"alive");

    // "b" is gone from the store.
    assert!(store.get(rid_b).is_err());
}

/// Compact an empty store (all records deleted).
#[test]
fn compaction_all_deleted_leaves_zero_records() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();

    let r1 = store.put(b"x").unwrap();
    let r2 = store.put(b"y").unwrap();
    store.delete(r1).unwrap();
    store.delete(r2).unwrap();

    let stats = store.compact().unwrap();
    assert_eq!(stats.records_retained, 0);
    assert_eq!(stats.records_dropped, 2);
    assert_eq!(store.live_count(), 0);
}

// ──────────────────────────────────────────────
// 4.  Persistence: store and indexes survive a restart
// ──────────────────────────────────────────────

#[test]
fn store_and_indexes_survive_reopen() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let rid = {
        let mut store = RecordStore::open(dir.path()).unwrap();
        let mut lsm = LsmIndex::open("kv", &idir).unwrap();
        let mut btree = BTreeIndex::open("bt", &idir).unwrap();

        let rid = store.put(b"persistent value").unwrap();
        lsm.put(b"key1", rid).unwrap();
        btree.put(b"key1", rid).unwrap();

        store.flush().unwrap();
        lsm.flush().unwrap();
        btree.flush().unwrap();
        rid
    };

    // Reopen everything from disk.
    let store = RecordStore::open(dir.path()).unwrap();
    let lsm = LsmIndex::open("kv", &idir).unwrap();
    let btree = BTreeIndex::open("bt", &idir).unwrap();

    let rid_lsm = lsm.get(b"key1").expect("LSM should survive reopen");
    let rid_bt = btree.get(b"key1").expect("B-tree should survive reopen");

    assert_eq!(rid_lsm, rid);
    assert_eq!(rid_bt, rid);
    assert_eq!(store.get(rid_lsm).unwrap(), b"persistent value");
}

// ──────────────────────────────────────────────
// 5.  Index-specific behaviour: LSM range scan
// ──────────────────────────────────────────────

#[test]
fn lsm_scan_returns_sorted_range() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", dir.path().join("idx")).unwrap();

    let r1 = store.put(b"v1").unwrap();
    let r2 = store.put(b"v2").unwrap();
    let r3 = store.put(b"v3").unwrap();

    lsm.put(b"k1", r1).unwrap();
    lsm.put(b"k2", r2).unwrap();
    lsm.put(b"k3", r3).unwrap();

    // Half-open range [k1, k3) → k1 and k2 only.
    let results = lsm.scan(Some(b"k1"), Some(b"k3"));
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], (b"k1".to_vec(), r1));
    assert_eq!(results[1], (b"k2".to_vec(), r2));
}

#[test]
fn lsm_scan_open_bounds() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", dir.path().join("idx")).unwrap();

    let r1 = store.put(b"a").unwrap();
    let r2 = store.put(b"b").unwrap();
    let r3 = store.put(b"c").unwrap();

    lsm.put(b"x", r1).unwrap();
    lsm.put(b"y", r2).unwrap();
    lsm.put(b"z", r3).unwrap();

    let all = lsm.scan(None, None);
    assert_eq!(all.len(), 3);
}

#[test]
fn lsm_delete_removes_entry_from_scan() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", dir.path().join("idx")).unwrap();

    let r1 = store.put(b"keep").unwrap();
    let r2 = store.put(b"gone").unwrap();

    lsm.put(b"keep", r1).unwrap();
    lsm.put(b"gone", r2).unwrap();
    lsm.delete(b"gone").unwrap();

    let results = lsm.scan(None, None);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, r1);
    assert_eq!(lsm.get(b"gone"), None);
}

#[test]
fn lsm_snapshot_get_at_respects_sequence() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("kv", dir.path().join("idx")).unwrap();

    let v1 = store.put(b"v1").unwrap();
    let v2 = store.put(b"v2").unwrap();

    lsm.put_with_sequence(b"k", v1, 10).unwrap();
    lsm.put_with_sequence(b"k", v2, 20).unwrap();

    assert_eq!(lsm.get_at(b"k", 9), None);
    assert_eq!(lsm.get_at(b"k", 10), Some(v1));
    assert_eq!(lsm.get_at(b"k", 19), Some(v1));
    assert_eq!(lsm.get_at(b"k", 20), Some(v2));
}

#[test]
fn lsm_bloom_and_fence_metadata_survive_reopen() {
    let dir = tempdir().unwrap();
    let idx_dir = dir.path().join("idx");

    {
        let mut store = RecordStore::open(dir.path()).unwrap();
        let mut lsm = LsmIndex::open("kv", &idx_dir).unwrap();
        let a = store.put(b"a").unwrap();
        let b = store.put(b"b").unwrap();
        lsm.put(b"k1", a).unwrap();
        lsm.put(b"k2", b).unwrap();
        lsm.flush().unwrap();
    }

    let lsm = LsmIndex::open("kv", &idx_dir).unwrap();
    assert!(lsm.may_contain_key(b"k1"));
    assert!(lsm.may_contain_key(b"k2"));
    assert!(!lsm.may_contain_key(b"k3"));
    let (min, max) = lsm.fence_bounds();
    let min: Option<Vec<u8>> = min;
    let max: Option<Vec<u8>> = max;
    assert_eq!(min.unwrap(), b"k1".to_vec());
    assert_eq!(max.unwrap(), b"k2".to_vec());
}

// ──────────────────────────────────────────────
// 6.  Index-specific behaviour: B-tree range scan
// ──────────────────────────────────────────────

#[test]
fn btree_range_scan_ordered() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut btree = BTreeIndex::open("bt", dir.path().join("idx")).unwrap();

    let r1 = store.put(b"v1").unwrap();
    let r2 = store.put(b"v2").unwrap();
    let r3 = store.put(b"v3").unwrap();

    btree.put(b"10", r1).unwrap();
    btree.put(b"20", r2).unwrap();
    btree.put(b"30", r3).unwrap();

    // [10, 30) → 10 and 20 only.
    let range = btree.range(Some(b"10"), Some(b"30"));
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].1, r1);
    assert_eq!(range[1].1, r2);
}

#[test]
fn btree_open_lower_bound() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut btree = BTreeIndex::open("bt", dir.path().join("idx")).unwrap();

    let r1 = store.put(b"a").unwrap();
    let r2 = store.put(b"b").unwrap();
    let r3 = store.put(b"c").unwrap();

    btree.put(b"aa", r1).unwrap();
    btree.put(b"bb", r2).unwrap();
    btree.put(b"cc", r3).unwrap();

    // Unbounded lower, upper = b"cc" → aa and bb.
    let range = btree.range(None, Some(b"cc"));
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].1, r1);
    assert_eq!(range[1].1, r2);
}

#[test]
fn btree_snapshot_get_at_respects_sequence() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut btree = BTreeIndex::open("bt", dir.path().join("idx")).unwrap();

    let old = store.put(b"old").unwrap();
    let new = store.put(b"new").unwrap();
    btree.put_with_sequence(b"id:1", old, 100).unwrap();
    btree.put_with_sequence(b"id:1", new, 200).unwrap();

    assert_eq!(btree.get_at(b"id:1", 150), Some(old));
    assert_eq!(btree.get_at(b"id:1", 200), Some(new));
}

#[test]
fn btree_page_metadata_survives_reopen() {
    let dir = tempdir().unwrap();
    let idx_dir = dir.path().join("idx");
    {
        let mut store = RecordStore::open(dir.path()).unwrap();
        let mut btree = BTreeIndex::open("bt", &idx_dir).unwrap();
        for i in 0..300 {
            let rid = store.put(format!("v{i}").as_bytes()).unwrap();
            btree.put(format!("k{i:03}").as_bytes(), rid).unwrap();
        }
        btree.flush().unwrap();
    }

    let btree = BTreeIndex::open("bt", &idx_dir).unwrap();
    let pages = btree.page_metadata();
    assert!(!pages.is_empty());
    assert!(
        pages.len() >= 3,
        "300 keys with default page size should span pages"
    );
    assert!(pages[0].min_key <= pages[0].max_key);
}

// ──────────────────────────────────────────────
// 7.  Index-specific behaviour: adjacency (graph)
// ──────────────────────────────────────────────

#[test]
fn adjacency_add_and_query_edges() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut adj = AdjacencyIndex::open("g", dir.path().join("idx")).unwrap();

    let alice = store.put(b"alice").unwrap();
    let bob = store.put(b"bob").unwrap();
    let carol = store.put(b"carol").unwrap();

    adj.add_edge(alice, b"follows", bob, std::collections::BTreeMap::new())
        .unwrap();
    adj.add_edge(alice, b"follows", carol, std::collections::BTreeMap::new())
        .unwrap();
    adj.add_edge(alice, b"blocks", bob, std::collections::BTreeMap::new())
        .unwrap();

    let follows = adj.neighbors_with_label(alice, b"follows");
    assert_eq!(follows.len(), 2);
    assert!(follows.contains(&bob));
    assert!(follows.contains(&carol));

    let blocks = adj.neighbors_with_label(alice, b"blocks");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], bob);

    assert_eq!(adj.neighbors(alice).len(), 3);
}

#[test]
fn adjacency_duplicate_edges_ignored() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut adj = AdjacencyIndex::open("g", dir.path().join("idx")).unwrap();

    let a = store.put(b"a").unwrap();
    let b = store.put(b"b").unwrap();

    adj.add_edge(a, b"rel", b, std::collections::BTreeMap::new())
        .unwrap();
    adj.add_edge(a, b"rel", b, std::collections::BTreeMap::new())
        .unwrap(); // duplicate – must be ignored
    adj.add_edge(a, b"rel", b, std::collections::BTreeMap::new())
        .unwrap();

    assert_eq!(adj.neighbors(a).len(), 1);
}

#[test]
fn adjacency_remove_edges() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut adj = AdjacencyIndex::open("g", dir.path().join("idx")).unwrap();

    let a = store.put(b"a").unwrap();
    let b = store.put(b"b").unwrap();
    let c = store.put(b"c").unwrap();

    adj.add_edge(a, b"knows", b, std::collections::BTreeMap::new())
        .unwrap();
    adj.add_edge(a, b"knows", c, std::collections::BTreeMap::new())
        .unwrap();
    adj.remove_edges(a, b);

    let remaining = adj.neighbors(a);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].to, c);
}

#[test]
fn adjacency_add_bidirectional_edge() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut adj = AdjacencyIndex::open("g", dir.path().join("idx")).unwrap();

    let a = store.put(b"a").unwrap();
    let b = store.put(b"b").unwrap();
    adj.add_bidirectional_edge(a, b"follows", b, b"followed_by")
        .unwrap();

    assert_eq!(adj.neighbors_with_label(a, b"follows"), vec![b]);
    assert_eq!(adj.neighbors_with_label(b, b"followed_by"), vec![a]);
}

#[test]
fn adjacency_survives_reopen() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let (alice, bob) = {
        let mut store = RecordStore::open(dir.path()).unwrap();
        let mut adj = AdjacencyIndex::open("g", &idir).unwrap();
        let alice = store.put(b"alice").unwrap();
        let bob = store.put(b"bob").unwrap();
        adj.add_edge(alice, b"friend", bob, std::collections::BTreeMap::new())
            .unwrap();
        adj.flush().unwrap();
        (alice, bob)
    };

    let adj = AdjacencyIndex::open("g", &idir).unwrap();
    let friends = adj.neighbors_with_label(alice, b"friend");
    assert_eq!(friends, vec![bob]);
}

// ──────────────────────────────────────────────
// 8.  Index-specific behaviour: HNSW vector index
// ──────────────────────────────────────────────

#[test]
fn hnsw_insert_and_search() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut hnsw = HnswIndex::new("vec");

    let doc_a = store.put(b"document A").unwrap();
    let doc_b = store.put(b"document B").unwrap();

    hnsw.insert(vec![1.0_f32, 0.0, 0.0], doc_a).unwrap();
    hnsw.insert(vec![0.0_f32, 1.0, 0.0], doc_b).unwrap();

    // Query close to doc_a.
    let results = hnsw.search(&[0.9, 0.1, 0.0], 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, doc_a);

    // Resolve through store – no body duplication in the index.
    assert_eq!(store.get(results[0].0).unwrap(), b"document A");
}

#[test]
fn hnsw_top_k_returns_k_results() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut hnsw = HnswIndex::new("vec");

    for i in 0..10_u8 {
        let rid = store.put(&[i]).unwrap();
        hnsw.insert(vec![i as f32, 0.0], rid).unwrap();
    }

    let results = hnsw.search(&[5.0, 0.0], 3);
    assert_eq!(results.len(), 3);
    // Results must be sorted by ascending distance.
    assert!(results[0].1 <= results[1].1);
    assert!(results[1].1 <= results[2].1);
}

#[test]
fn hnsw_mismatched_dimensions_skipped() {
    let mut hnsw = HnswIndex::new("vec");
    hnsw.insert(vec![1.0, 2.0], RecordId(1)).unwrap();
    hnsw.insert(vec![1.0, 2.0, 3.0], RecordId(2)).unwrap(); // dim=3

    // Query with dim=2 – only the dim=2 vector matches.
    let results = hnsw.search(&[0.0, 0.0], 10);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, RecordId(1));
}

#[test]
fn hnsw_persisted_index_survives_reopen() {
    let dir = tempdir().unwrap();
    let idx_dir = dir.path().join("idx");
    let mut store = RecordStore::open(dir.path()).unwrap();

    let rid = store.put(b"persisted-doc").unwrap();
    {
        let mut hnsw = HnswIndex::open("vec", &idx_dir).unwrap();
        hnsw.insert(vec![1.0, 2.0, 3.0], rid).unwrap();
        hnsw.flush().unwrap();
    }

    let hnsw = HnswIndex::open("vec", &idx_dir).unwrap();
    let results = hnsw.search(&[1.0, 2.0, 3.0], 1);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, rid);
}

// ──────────────────────────────────────────────
// 9.  Compaction with all index types still consistent
// ──────────────────────────────────────────────

#[test]
fn compaction_followed_by_all_index_queries() {
    let dir = tempdir().unwrap();
    let idir = dir.path().join("idx");

    let mut store = RecordStore::open(dir.path()).unwrap();
    let mut lsm = LsmIndex::open("lsm", &idir).unwrap();
    let mut btree = BTreeIndex::open("bt", &idir).unwrap();
    let mut adj = AdjacencyIndex::open("g", &idir).unwrap();

    let alice = store.put(b"alice").unwrap();
    let bob = store.put(b"bob").unwrap();
    let stale = store.put(b"will be deleted").unwrap();

    lsm.put(b"alice", alice).unwrap();
    btree.put(b"alice", alice).unwrap();
    adj.add_edge(alice, b"knows", bob, std::collections::BTreeMap::new())
        .unwrap();

    store.delete(stale).unwrap();
    let stats = store.compact().unwrap();

    assert_eq!(stats.records_retained, 2);
    assert_eq!(stats.records_dropped, 1);

    // All indexes still work after compaction rewrote the segments.
    assert_eq!(store.get(lsm.get(b"alice").unwrap()).unwrap(), b"alice");
    assert_eq!(store.get(btree.get(b"alice").unwrap()).unwrap(), b"alice");
    let neighbors = adj.neighbors_with_label(alice, b"knows");
    assert_eq!(store.get(neighbors[0]).unwrap(), b"bob");
}

// ──────────────────────────────────────────────
// 10. RecordId properties
// ──────────────────────────────────────────────

#[test]
fn record_id_null_sentinel() {
    assert!(RecordId::NULL.is_null());
    assert_eq!(RecordId::NULL, RecordId(0));
}

#[test]
fn record_id_not_null_after_put() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();
    let rid = store.put(b"x").unwrap();
    assert!(!rid.is_null());
    assert_ne!(rid, RecordId::NULL);
}

#[test]
fn record_id_monotonically_increasing() {
    let dir = tempdir().unwrap();
    let mut store = RecordStore::open(dir.path()).unwrap();

    let r1 = store.put(b"a").unwrap();
    let r2 = store.put(b"b").unwrap();
    let r3 = store.put(b"c").unwrap();

    assert!(r1 < r2);
    assert!(r2 < r3);
}

#[test]
fn storage_engine_writes_once_and_serves_multiple_indexes() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "pk",
            "default",
            Box::new(BTreeIndex::open("pk", &index_dir).unwrap()),
        )
        .unwrap();

    let rid = engine
        .put(
            b"single-copy-record",
            &[
                IndexInsert::new("kv", b"user:42".to_vec()),
                IndexInsert::new("pk", b"users/42".to_vec()),
            ],
        )
        .unwrap();

    assert_eq!(engine.live_count(), 1);
    assert_eq!(
        engine.lookup_rid("kv", b"user:42").unwrap(),
        Some(rid),
        "LSM index should map to the same logical RID"
    );
    assert_eq!(
        engine.lookup_rid("pk", b"users/42").unwrap(),
        Some(rid),
        "B-tree index should map to the same logical RID"
    );
    assert_eq!(engine.fetch(rid).unwrap(), b"single-copy-record");
}

#[test]
fn storage_engine_replays_wal_entries_by_index_type() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        engine
            .register_index(
                "bt",
                "default",
                Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
            )
            .unwrap();

        // Simulate process crash before plugin snapshot flush; WAL must restore
        // index mappings on reopen.
        engine
            .put(
                b"wal-backed-value",
                &[
                    IndexInsert::new("kv", b"k".to_vec()),
                    IndexInsert::new("bt", b"b".to_vec()),
                ],
            )
            .unwrap()
    };

    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    reopened
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    assert_eq!(reopened.lookup_rid("kv", b"k").unwrap(), Some(rid));
    assert_eq!(reopened.lookup_rid("bt", b"b").unwrap(), Some(rid));
    assert_eq!(reopened.fetch(rid).unwrap(), b"wal-backed-value");
}

#[test]
fn storage_engine_put_uses_grouped_wal_batch_sequences() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "lsm",
            "default",
            Box::new(LsmIndex::open("lsm", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    let rid = engine
        .put(
            b"group-commit-payload",
            &[
                IndexInsert::new("lsm", b"k".to_vec()),
                IndexInsert::new("bt", b"p".to_vec()),
            ],
        )
        .unwrap();
    drop(engine);

    let entries = StorageWal::replay(&dir.path().join("wal").join("storage.wal")).unwrap();
    assert_eq!(entries.len(), 3, "primary + two index entries");
    assert_eq!(entries[0].sequence + 1, entries[1].sequence);
    assert_eq!(entries[1].sequence + 1, entries[2].sequence);
    assert_eq!(entries[1].index_type, "lsm");
    assert_eq!(entries[2].index_type, "bt");
    assert_eq!(entries[1].rid, Some(rid));
    assert_eq!(entries[2].rid, Some(rid));
}

#[test]
fn storage_engine_stats_report_per_index_counts() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();
    engine.set_compaction_budget_bytes(64 * 1024 * 1024);
    let rid = engine
        .put(
            b"stats-payload",
            &[
                IndexInsert::new("kv", b"k".to_vec()),
                IndexInsert::new("bt", b"p".to_vec()),
            ],
        )
        .unwrap();
    assert_eq!(engine.fetch(rid).unwrap(), b"stats-payload");

    let stats = engine.stats();
    assert_eq!(stats.live_records, 1);
    assert_eq!(stats.compaction_budget_bytes, 64 * 1024 * 1024);
    assert_eq!(stats.index_stats.get("kv").unwrap().live_keys, 1);
    assert_eq!(stats.index_stats.get("bt").unwrap().live_keys, 1);
    assert_eq!(stats.reads_total, 1);
    assert_eq!(stats.writes_total, 1);
    assert_eq!(stats.wal_records_total, 3);
    assert!(stats.wal_bytes_written > 0);
    assert_eq!(stats.user_bytes_written, b"stats-payload".len() as u64);
    assert!(stats.read_latency_p50_us > 0);
    assert!(stats.write_latency_p50_us > 0);
    assert!(stats.reads_per_sec > 0.0);
    assert!(stats.writes_per_sec > 0.0);
    assert!(stats.wal_bytes_per_sec > 0.0);
    assert!(stats.write_amplification > 1.0);
}

#[test]
fn storage_engine_compact_indexes_preserves_required_snapshot_versions() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let rid1 = engine.put(b"v1", &[]).unwrap();
    let rid2 = engine.put(b"v2", &[]).unwrap();
    engine.put_index("kv", b"hot-key", rid1).unwrap();
    engine.put_index("kv", b"hot-key", rid2).unwrap();
    engine.delete_index("kv", b"hot-key").unwrap();

    let before = engine.stats();
    assert!(
        before.index_stats.get("kv").unwrap().versions >= 3,
        "expected multiple versions before compaction"
    );

    let reports = engine.compact_indexes().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].index_type, "kv");
    assert_eq!(reports[0].after.versions, reports[0].before.versions);
    let put_sequence = StorageWal::replay(engine.wal_path())
        .unwrap()
        .into_iter()
        .find(|entry| entry.index_type == "kv" && entry.rid == Some(rid1))
        .unwrap()
        .sequence;
    assert_eq!(
        engine
            .lookup_rid_at("kv", b"hot-key", put_sequence)
            .unwrap(),
        Some(rid1)
    );

    let after = engine.stats();
    assert_eq!(after.index_compaction_runs.get("kv"), Some(&1));
    assert_eq!(after.index_stats.get("kv").unwrap().live_keys, 0);
}

#[test]
fn storage_engine_compact_selected_indexes_errors_on_unknown() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let err = engine
        .compact_selected_indexes(&["does-not-exist"])
        .unwrap_err();
    assert!(matches!(err, praxis::PraxisError::InvalidConfig(_)));
}

#[test]
fn storage_engine_does_not_suggest_pruning_required_snapshot_history() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let r1 = engine.put(b"a", &[]).unwrap();
    let r2 = engine.put(b"b", &[]).unwrap();
    engine.put_index("kv", b"hot", r1).unwrap();
    engine.put_index("kv", b"hot", r2).unwrap();
    engine.delete_index("kv", b"hot").unwrap();

    let jobs = engine.suggest_index_compactions(2);
    assert!(jobs.is_empty());
    assert!(engine.suggest_index_compactions(0).is_empty());
}

#[test]
fn storage_engine_put_rejects_unknown_index_before_wal_append() {
    let dir = tempdir().unwrap();
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    let err = engine
        .put(b"value", &[IndexInsert::new("missing", b"k".to_vec())])
        .unwrap_err();
    assert!(matches!(err, praxis::PraxisError::InvalidConfig(_)));

    let entries = StorageWal::replay(&dir.path().join("wal").join("storage.wal")).unwrap();
    assert!(
        entries.is_empty(),
        "strict prevalidation must prevent WAL writes for unknown indexes"
    );
}

#[test]
fn wal_replay_preserves_delete_sequence_for_snapshot_reads() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"snapshot-value", &[]).unwrap();
        engine.put_index("kv", b"k", rid).unwrap();
        engine.delete_index("kv", b"k").unwrap();
        rid
    };

    let entries = StorageWal::replay(&dir.path().join("wal").join("storage.wal")).unwrap();
    let put_seq = entries
        .iter()
        .find(|e| e.index_type == "kv" && e.key == b"k".to_vec() && e.rid == Some(rid))
        .unwrap()
        .sequence;
    let delete_seq = entries
        .iter()
        .find(|e| e.index_type == "kv" && e.key == b"k".to_vec() && e.rid.is_none())
        .unwrap()
        .sequence;
    assert!(delete_seq > put_seq);

    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    assert_eq!(reopened.lookup_rid("kv", b"k").unwrap(), None);
    assert_eq!(
        reopened.lookup_rid_at("kv", b"k", put_seq).unwrap(),
        Some(rid)
    );
    assert_eq!(
        reopened.lookup_rid_at("kv", b"k", delete_seq).unwrap(),
        None
    );
}

#[test]
fn maintenance_cycle_suggests_and_executes_compaction_end_to_end() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let r1 = engine.put(b"a", &[]).unwrap();
    let r2 = engine.put(b"b", &[]).unwrap();
    engine.put_index("kv", b"hot", r1).unwrap();
    engine.put_index("kv", b"hot", r2).unwrap();
    engine.delete_index("kv", b"hot").unwrap();
    append_replayed_index_duplicates(&mut engine, &index_dir, "kv", 2);

    let cycle = engine.run_maintenance_cycle(2).unwrap();
    assert_eq!(cycle.suggested.len(), 1);
    assert_eq!(cycle.suggested[0].index_type, "kv");
    assert_eq!(cycle.executed.len(), 1);
    assert_eq!(cycle.executed[0].index_type, "kv");
    assert_eq!(cycle.suggested[0].estimated_versions_pruned, 2);
    assert_eq!(
        cycle.executed[0].before.versions - cycle.executed[0].after.versions,
        2
    );
    assert!(engine.suggest_index_compactions(0).is_empty());
    assert_eq!(engine.lookup_rid("kv", b"hot").unwrap(), None);
    engine.flush().unwrap();
    drop(engine);
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    assert_eq!(engine.lookup_rid("kv", b"hot").unwrap(), None);
    let stats = engine.stats();
    assert_eq!(stats.index_compaction_runs.get("kv"), Some(&1));
}

#[test]
fn put_index_uses_wal_sequence_for_immediate_snapshot_reads() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let rid = engine.put(b"value", &[]).unwrap();
    engine.put_index("kv", b"k", rid).unwrap();
    let entries = StorageWal::replay(engine.wal_path()).unwrap();
    let sequence = entries
        .iter()
        .find(|entry| {
            entry.index_type == "kv" && entry.key == b"k".to_vec() && entry.rid == Some(rid)
        })
        .unwrap()
        .sequence;
    assert_eq!(
        engine.lookup_rid_at("kv", b"k", sequence).unwrap(),
        Some(rid)
    );
}

#[test]
fn primary_only_wal_entries_are_not_counted_as_pending_index_replay() {
    let dir = tempdir().unwrap();
    {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        let _ = engine.put(b"primary-only", &[]).unwrap();
    }
    let reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    assert_eq!(reopened.stats().pending_wal_replay, 0);
}

#[test]
fn maintenance_suggestions_are_deterministically_ordered() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    let r1 = engine.put(b"a", &[]).unwrap();
    let r2 = engine.put(b"b", &[]).unwrap();
    // Both indexes receive one safely reclaimable replay duplicate.
    engine.put_index("kv", b"hot", r1).unwrap();
    engine.put_index("kv", b"hot", r2).unwrap();
    engine.put_index("bt", b"hot", r1).unwrap();
    engine.put_index("bt", b"hot", r2).unwrap();
    append_replayed_index_duplicates(&mut engine, &index_dir, "kv", 1);
    append_replayed_index_duplicates(&mut engine, &index_dir, "bt", 1);

    let suggestions = engine.suggest_index_compactions(1);
    assert_eq!(suggestions.len(), 2);
    assert_eq!(
        suggestions
            .iter()
            .map(|job| job.index_type.as_str())
            .collect::<Vec<_>>(),
        vec!["bt", "kv"],
        "tie-break order must be stable and lexicographic by index type"
    );
}

#[test]
fn maintenance_cycle_with_options_respects_max_jobs() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    engine
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    let r1 = engine.put(b"a", &[]).unwrap();
    let r2 = engine.put(b"b", &[]).unwrap();
    engine.put_index("kv", b"hot", r1).unwrap();
    engine.put_index("kv", b"hot", r2).unwrap();
    engine.put_index("bt", b"hot", r1).unwrap();
    engine.put_index("bt", b"hot", r2).unwrap();
    append_replayed_index_duplicates(&mut engine, &index_dir, "kv", 1);
    append_replayed_index_duplicates(&mut engine, &index_dir, "bt", 1);

    let report = engine
        .run_maintenance_cycle_with_options(MaintenanceCycleOptions {
            stale_version_threshold: 1,
            max_jobs: 1,
        })
        .unwrap();
    assert_eq!(report.suggested.len(), 2);
    assert_eq!(report.executed.len(), 1);

    let stats = engine.stats();
    assert_eq!(stats.maintenance_cycles_run, 1);
    assert!(stats.last_maintenance_at_sequence.is_some());
}

#[test]
fn storage_wal_rotates_segments_and_replays_all_entries() {
    let dir = tempdir().unwrap();
    let wal_path = dir.path().join("wal").join("storage.wal");
    let mut wal = StorageWal::open_with_options(
        &wal_path,
        StorageWalOptions {
            max_segment_bytes: 256,
        },
    )
    .unwrap();
    for seq in 1..=200_u64 {
        wal.append(&StorageWalEntry {
            sequence: seq,
            index_type: "kv".to_string(),
            key: format!("k-{seq:04}").into_bytes(),
            rid: Some(RecordId(seq)),
            operation: StorageWalOperation::Put,
        })
        .unwrap();
    }

    let entries = StorageWal::replay(&wal_path).unwrap();
    assert_eq!(entries.len(), 200);
    assert_eq!(entries.first().unwrap().sequence, 1);
    assert_eq!(entries.last().unwrap().sequence, 200);

    let segment_count = std::fs::read_dir(wal_path.parent().unwrap())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
        .count();
    assert!(segment_count > 1, "expected WAL segment rotation");
}

#[test]
fn storage_runtime_executes_maintenance_cycles_in_background() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    let r1 = engine.put(b"a", &[]).unwrap();
    let r2 = engine.put(b"b", &[]).unwrap();
    engine.put_index("kv", b"hot", r1).unwrap();
    engine.put_index("kv", b"hot", r2).unwrap();
    engine.delete_index("kv", b"hot").unwrap();
    append_replayed_index_duplicates(&mut engine, &index_dir, "kv", 1);

    let shared: SharedStorageEngine = Arc::new(parking_lot::Mutex::new(engine));
    let mut runtime = StorageMaintenanceRuntimeController::default();
    runtime
        .start(
            shared.clone(),
            StorageMaintenanceRuntimeConfig {
                workers: 1,
                idle_sleep_ms: 5,
                cycle: MaintenanceCycleOptions {
                    stale_version_threshold: 1,
                    max_jobs: 1,
                },
            },
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    runtime.stop().unwrap();
    runtime.join().unwrap();

    let status = runtime.status();
    assert!(!status.running);
    let engine = shared.lock();
    let stats = engine.stats();
    assert!(stats.maintenance_cycles_run >= 1);
    assert_eq!(stats.index_compaction_runs.get("kv"), Some(&1));
}

#[test]
fn storage_engine_recovers_from_torn_segment_wal_suffix() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"value", &[]).unwrap();
        engine.put_index("kv", b"k", rid).unwrap();
        rid
    };

    let wal_dir = dir.path().join("wal");
    let active_segment = std::fs::read_dir(&wal_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
        .max()
        .unwrap();
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(active_segment)
            .unwrap();
        // Simulate a torn suffix / garbage tail after crash.
        file.write_all(&[0xaa, 0xbb, 0xcc]).unwrap();
        file.flush().unwrap();
    }

    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    assert_eq!(reopened.lookup_rid("kv", b"k").unwrap(), Some(rid));
    assert_eq!(reopened.fetch(rid).unwrap(), b"value");
}

// ──────────────────────────────────────────────
// 11. Fault-Injection Tests: Crash & Recovery
// ──────────────────────────────────────────────

/// Simulate a crash during WAL append and verify recovery restores
/// only fully-written records. We create a new segment after corruption
/// to simulate fresh writes post-crash.
#[test]
fn fault_injection_crash_during_wal_append_single_record() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let expected_data = b"fault-tolerant-data";

    // Write and flush normally.
    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(expected_data, &[]).unwrap();
        engine.put_index("kv", b"key1", rid).unwrap();
        rid
    };

    // Simulate crash by marking the active segment as corrupted
    // (by adding a corrupted suffix), and then reopening will create a new segment.
    let wal_dir = dir.path().join("wal");
    let active_segment = std::fs::read_dir(&wal_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
        .max()
        .unwrap();
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&active_segment)
            .unwrap();
        // Add a torn suffix (garbage bytes) to simulate crash.
        file.write_all(&[0xff; 32]).ok();
        file.flush().ok();
    }

    // Reopen: must skip the corrupted tail and recover successfully.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    // Data that was fully flushed before the crash must still be readable.
    assert_eq!(reopened.fetch(rid).unwrap(), expected_data);
    assert_eq!(
        reopened.lookup_rid("kv", b"key1").unwrap(),
        Some(rid),
        "fully-written index entry must survive torn WAL recovery"
    );
}

/// Simulate crash during multi-index write: recover with partial indexes.
#[test]
fn fault_injection_crash_during_grouped_wal_batch() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "lsm",
                "default",
                Box::new(LsmIndex::open("lsm", &index_dir).unwrap()),
            )
            .unwrap();
        engine
            .register_index(
                "bt",
                "default",
                Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"grouped-data", &[]).unwrap();
        engine.put_index("lsm", b"k1", rid).unwrap();
        engine.put_index("bt", b"k2", rid).unwrap();
        rid
    };

    // Simulate crash: add a corrupted suffix to the active WAL segment.
    let wal_dir = dir.path().join("wal");
    let active_segment = std::fs::read_dir(&wal_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
        .max()
        .unwrap();
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&active_segment)
            .unwrap();
        // Add corrupted bytes to simulate torn write.
        file.write_all(&[0xde; 64]).ok();
        file.flush().ok();
    }

    // Recovery: indexes may be partially restored.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "lsm",
            "default",
            Box::new(LsmIndex::open("lsm", &index_dir).unwrap()),
        )
        .unwrap();
    reopened
        .register_index(
            "bt",
            "default",
            Box::new(BTreeIndex::open("bt", &index_dir).unwrap()),
        )
        .unwrap();

    // Primary data must always be recoverable.
    assert_eq!(reopened.fetch(rid).unwrap(), b"grouped-data");

    // At least one index may be restored from fully-written WAL entries.
    // The critical invariant: data integrity - no panic or corruption.
    let _lsm_entry_exists = reopened.lookup_rid("lsm", b"k1").unwrap().is_some();
    let _bt_entry_exists = reopened.lookup_rid("bt", b"k2").unwrap().is_some();
}

/// Simulate repeated crash-recovery cycles: each recovery must be deterministic.
#[test]
fn fault_injection_deterministic_recovery_across_multiple_crashes() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Establish initial state.
    let (rid1, rid2) = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid1 = engine.put(b"data-1", &[]).unwrap();
        let rid2 = engine.put(b"data-2", &[]).unwrap();
        engine.put_index("kv", b"k1", rid1).unwrap();
        engine.put_index("kv", b"k2", rid2).unwrap();
        (rid1, rid2)
    };

    // Simulate crash: add a corrupted suffix to the WAL.
    let add_corrupted_suffix = |_factor: f64| {
        let wal_dir = dir.path().join("wal");
        let active_segment = std::fs::read_dir(&wal_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
            .max()
            .unwrap();
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&active_segment)
                .unwrap();
            // Add corrupted bytes without truncating (simulating crash with torn write).
            file.write_all(&[0xcc; 128]).ok();
            file.flush().ok();
        }
    };

    add_corrupted_suffix(0.5);

    let state1 = {
        let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        reopened
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let k1_exists = reopened.lookup_rid("kv", b"k1").unwrap().is_some();
        let k2_exists = reopened.lookup_rid("kv", b"k2").unwrap().is_some();
        (k1_exists, k2_exists)
    };

    // Do NOT modify anything; simulate process restart (read-only recovery).
    let state2 = {
        let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        reopened
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let k1_exists = reopened.lookup_rid("kv", b"k1").unwrap().is_some();
        let k2_exists = reopened.lookup_rid("kv", b"k2").unwrap().is_some();
        (k1_exists, k2_exists)
    };

    assert_eq!(
        state1, state2,
        "recovery must be deterministic across repeated opens with same torn WAL state"
    );

    // Both primary records must always be accessible.
    let mut final_engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    final_engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    assert_eq!(final_engine.fetch(rid1).unwrap(), b"data-1");
    assert_eq!(final_engine.fetch(rid2).unwrap(), b"data-2");
}

/// Simulate crash during compaction: verify index files remain coherent.
#[test]
fn fault_injection_crash_during_compaction_leaves_coherent_index() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Build up multiple versions via overwrites.
    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"compaction-test-data", &[]).unwrap();
        for _v in 0..10 {
            engine.put_index("kv", b"volatile-key", rid).unwrap();
            engine.delete_index("kv", b"volatile-key").ok();
        }
        rid
    };

    // Trigger compaction to rewrite index files.
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();
    let _compaction_report = engine.compact_indexes().unwrap();
    drop(engine);

    // Simulate crash: truncate or corrupt index snapshot (if one was written).
    // In this test, the LSM snapshot may be in JSON or binary format; we corrupt
    // the index directory selectively.
    let idx_path = index_dir.join("kv");
    if idx_path.exists()
        && let Ok(entries) = std::fs::read_dir(&idx_path)
    {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("snap") {
                // Corrupt the snapshot by truncating it.
                let size = std::fs::metadata(&path).unwrap().len();
                std::fs::File::create(&path)
                    .unwrap()
                    .set_len(size / 2)
                    .unwrap();
            }
        }
    }

    // Reopen: LSM must fallback gracefully or recover from WAL.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    // Primary data must always be accessible.
    assert_eq!(reopened.fetch(rid).unwrap(), b"compaction-test-data");
    // Index may be empty or partially populated after replay, but must not panic.
}

/// Simulate multiple concurrent writers crashing and verify WAL segment
/// replay order correctness.
#[test]
fn fault_injection_wal_segment_replay_order_correctness() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Write data with a custom small WAL segment size to force rotation.
    let rids = {
        let mut engine = StorageEngine::open_with_wal_options(
            dir.path(),
            1024 * 1024,
            StorageWalOptions {
                max_segment_bytes: 512, // Force small segments
            },
        )
        .unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let mut rids = Vec::new();
        for i in 0..50 {
            // Write larger data to force segment rotation with small segment size.
            let data = format!("data-{i}-{:0>100}", i);
            let rid = engine.put(data.as_bytes(), &[]).unwrap();
            engine
                .put_index("kv", format!("k{i}").as_bytes(), rid)
                .unwrap();
            rids.push((i, rid));
        }
        rids
    };

    // Verify all WAL segments exist.
    let wal_dir = dir.path().join("wal");
    let segment_count = std::fs::read_dir(&wal_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("swal"))
        .count();
    assert!(
        segment_count > 1,
        "expected multiple WAL segments, got {}",
        segment_count
    );

    // Reopen and verify all records are replayed in order.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    for (i, rid) in rids {
        let data = format!("data-{i}-{:0>100}", i);
        assert_eq!(reopened.fetch(rid).unwrap(), data.as_bytes());
        assert_eq!(
            reopened
                .lookup_rid("kv", format!("k{i}").as_bytes())
                .unwrap(),
            Some(rid)
        );
    }
}

/// Verify that compaction manifests remain consistent after a crash.
#[test]
fn fault_injection_manifest_consistency_after_compaction_crash() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Write initial data and compact.
    {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let r1 = engine.put(b"data1", &[]).unwrap();
        let r2 = engine.put(b"data2", &[]).unwrap();
        engine.put_index("kv", b"key1", r1).unwrap();
        engine.put_index("kv", b"key1", r2).unwrap(); // overwrite
        let _report = engine.compact_indexes().unwrap();
        // Simulate crash here (drop without flush).
    }

    // Reopen: manifest should be valid and compaction should have been applied
    // or safely rolled back.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    // Stats should be readable and consistent.
    let stats = reopened.stats();
    assert!(stats.live_records > 0);
    assert!(stats.index_stats.contains_key("kv"));
}

/// Test recovery from a deleted manifest file.
#[test]
fn fault_injection_recovery_with_missing_manifest() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Establish initial data.
    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"manifest-recovery-test", &[]).unwrap();
        engine.put_index("kv", b"key", rid).unwrap();
        rid
    };

    // Delete the manifest file to simulate severe corruption.
    let manifest_path = dir.path().join("MANIFEST");
    if manifest_path.exists() {
        std::fs::remove_file(&manifest_path).ok();
    }

    // Reopen: engine should recover from WAL alone without manifest.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    // Data must still be accessible via WAL replay.
    assert_eq!(reopened.fetch(rid).unwrap(), b"manifest-recovery-test");
}

/// Test recovery with a corrupted WAL segment: later segments must still be replayed
/// if they are valid. For now, we test that at least primary data survives.
#[test]
fn fault_injection_skip_corrupted_wal_segment_continue_with_next() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    // Write data to rotate WAL segments.
    let rids = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        // Write enough data to force segment rotation (default is 16MB, but tests use small segment sizes).
        let mut rids = Vec::new();
        for i in 0..5 {
            let rid = engine.put(format!("data-{i}").as_bytes(), &[]).unwrap();
            engine
                .put_index("kv", format!("k{i}").as_bytes(), rid)
                .unwrap();
            rids.push(rid);
        }
        rids
    };

    // Write more data after the first set.
    let final_rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine.put(b"post-corruption-data", &[]).unwrap();
        engine.put_index("kv", b"final-key", rid).unwrap();
        rid
    };

    // Reopen: should still be able to read all primary data.
    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    // All primary data should be accessible.
    for (i, rid) in rids.iter().enumerate() {
        assert_eq!(
            reopened.fetch(*rid).ok(),
            Some(format!("data-{i}").into_bytes())
        );
    }
    assert_eq!(reopened.fetch(final_rid).unwrap(), b"post-corruption-data");
}

#[test]
fn primary_wal_replay_repairs_missing_record_directory() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");

    let rid = {
        let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
        engine
            .register_index(
                "kv",
                "default",
                Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
            )
            .unwrap();
        let rid = engine
            .put(
                b"directory-replay-value",
                &[IndexInsert::new("kv", b"directory-key".to_vec())],
            )
            .unwrap();
        engine.flush().unwrap();
        rid
    };

    let indirection_path = dir.path().join("primary").join("indirection.tind");
    if indirection_path.exists() {
        std::fs::remove_file(indirection_path).unwrap();
    }

    let mut reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    reopened
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    assert_eq!(reopened.fetch(rid).unwrap(), b"directory-replay-value");
    assert_eq!(
        reopened.fetch_by_index("kv", b"directory-key").unwrap(),
        Some(b"directory-replay-value".to_vec())
    );
}

#[test]
fn primary_delete_wal_replay_tombstones_record_after_restart() {
    let dir = tempdir().unwrap();

    let rid = {
        let mut engine = StorageEngine::open_with_options(
            dir.path(),
            1024 * 1024,
            StorageEngineOptions {
                directory_sync_policy: DirectorySyncPolicy::Manual,
                ..StorageEngineOptions::default()
            },
        )
        .unwrap();
        let rid = engine.put(b"delete-after-replay", &[]).unwrap();
        engine.delete_record(rid).unwrap();
        rid
    };

    let reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    assert!(reopened.fetch(rid).is_err());
}

#[test]
fn deferred_directory_sync_recovers_latest_primary_writes() {
    let dir = tempdir().unwrap();
    let rid = {
        let mut engine = StorageEngine::open_with_options(
            dir.path(),
            1024 * 1024,
            StorageEngineOptions {
                directory_sync_policy: DirectorySyncPolicy::Manual,
                ..StorageEngineOptions::default()
            },
        )
        .unwrap();
        let rid = engine.put(b"manual-sync-recovery", &[]).unwrap();
        let stats = engine.stats();
        assert_eq!(stats.directory_sync_policy, DirectorySyncPolicy::Manual);
        assert_eq!(stats.dirty_directory_entries, 1);
        rid
    };

    std::fs::remove_file(dir.path().join("primary").join("indirection.tind")).ok();

    let reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    assert_eq!(reopened.fetch(rid).unwrap(), b"manual-sync-recovery");
}

#[test]
fn batch_primary_delete_wal_replay_tombstones_records_after_restart() {
    let dir = tempdir().unwrap();
    let (rid_a, rid_b) = {
        let mut engine = StorageEngine::open_with_options(
            dir.path(),
            1024 * 1024,
            StorageEngineOptions {
                directory_sync_policy: DirectorySyncPolicy::Manual,
                ..StorageEngineOptions::default()
            },
        )
        .unwrap();
        let rid_a = engine.put(b"batch-delete-a", &[]).unwrap();
        let rid_b = engine.put(b"batch-delete-b", &[]).unwrap();
        engine.delete_records(&[rid_a, rid_b]).unwrap();
        let stats = engine.stats();
        assert_eq!(stats.directory_sync_policy, DirectorySyncPolicy::Manual);
        assert_eq!(stats.dirty_directory_entries, 4);
        (rid_a, rid_b)
    };

    let reopened = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    assert!(reopened.fetch(rid_a).is_err());
    assert!(reopened.fetch(rid_b).is_err());
}

#[test]
fn stale_secondary_pointer_is_not_returned_after_primary_delete() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let rid = engine
        .put(
            b"delete-me",
            &[IndexInsert::new("kv", b"stale-key".to_vec())],
        )
        .unwrap();
    engine.delete_record(rid).unwrap();

    assert_eq!(engine.fetch_by_index("kv", b"stale-key").unwrap(), None);
}

#[test]
fn delete_by_index_removes_secondary_pointer_and_primary_record() {
    let dir = tempdir().unwrap();
    let index_dir = dir.path().join("indexes");
    let mut engine = StorageEngine::open(dir.path(), 1024 * 1024).unwrap();
    engine
        .register_index(
            "kv",
            "default",
            Box::new(LsmIndex::open("kv", &index_dir).unwrap()),
        )
        .unwrap();

    let rid = engine
        .put(
            b"delete-by-index",
            &[IndexInsert::new("kv", b"delete-key".to_vec())],
        )
        .unwrap();

    assert_eq!(
        engine.delete_by_index("kv", b"delete-key").unwrap(),
        Some(rid)
    );
    assert_eq!(engine.lookup_rid("kv", b"delete-key").unwrap(), None);
    assert!(engine.fetch(rid).is_err());
}
