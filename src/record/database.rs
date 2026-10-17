use super::recovery::load_collection;
use super::{PageOperation, PageRecordStore, RidDirectory};
use crate::config::WalSyncPolicy;
use crate::errors::{PraxisError, Result};
use crate::identity::{Cid, Eid, Fid, Pid, Rid};
use crate::layout::PraxisLayout;
use crate::storage::root_format::{InspectionOptions, require_page_base_compatible};
use crate::wal::{PageWal, PageWalMutation, PageWalRecord, PageWalWriter, read_page_wal_strict};
use crate::writer_lease::WriterLease;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

/// Explicit owner of one page database root and its collection state.
#[derive(Clone)]
pub struct PageDatabase {
    pub(super) inner: Arc<PageDatabaseInner>,
}

pub(super) struct PageDatabaseInner {
    pub(super) layout: PraxisLayout,
    pub(super) state: Mutex<PageDatabaseState>,
    _writer_lease: WriterLease,
}

#[derive(Default)]
pub(super) struct PageDatabaseState {
    pub(super) collections: BTreeMap<Cid, CollectionState>,
    initialized_entities: BTreeSet<(Cid, Eid)>,
    recovery_required: Option<String>,
    wal: Option<PageWalWriter>,
}

pub(super) struct CollectionState {
    pub(super) directory: RidDirectory,
    pub(super) deleted: BTreeSet<Rid>,
    // u64::MAX is an exhausted sentinel, also representable in directory v1.
    pub(super) next_rid: u64,
    pub(super) cursors: BTreeMap<(Eid, Fid), EntityCursor>,
}

#[derive(Clone, Copy)]
pub(super) struct EntityCursor {
    pub(super) current_pid: Pid,
    // 65536 means this page has exhausted its SID space; the next put rolls over.
    pub(super) next_sid: u32,
}

impl Default for EntityCursor {
    fn default() -> Self {
        Self {
            current_pid: Pid(1),
            next_sid: 1,
        }
    }
}

impl fmt::Debug for PageDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageDatabase")
            .field("layout", &self.inner.layout)
            .finish_non_exhaustive()
    }
}

impl PageDatabase {
    pub(crate) fn layout(&self) -> &PraxisLayout {
        &self.inner.layout
    }

    /// Hold the existing root guard through a read-only, non-reentrant action.
    pub(crate) fn with_root_read<T>(
        &self,
        read: impl FnOnce(&PraxisLayout) -> Result<T>,
    ) -> Result<T> {
        let _state = self.lock()?;
        read(&self.inner.layout)
    }

    /// Preparation may read but must not mutate or reenter a locking API.
    /// Publication crosses the uncertain-IO boundary while retaining the guard.
    pub(crate) fn with_root_mutation<P, T>(
        &self,
        prepare: impl FnOnce(&PraxisLayout) -> Result<P>,
        publish: impl FnOnce(&PraxisLayout, P) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.lock()?;
        let prepared = prepare(&self.inner.layout)?;
        let result = publish(&self.inner.layout, prepared);
        if let Err(error) = &result {
            state.recovery_required = Some(error.to_string());
        }
        result
    }

    pub fn open(base: impl Into<PathBuf>) -> Result<Self> {
        let writer_lease = WriterLease::acquire(base.into())?;
        require_page_base_compatible(writer_lease.root(), InspectionOptions::for_admission())?;
        let layout = PraxisLayout::new(writer_lease.root());
        let records = read_page_wal_strict(&layout.logs_root().join("page.wal"))?;
        let mut high_water = BTreeMap::new();
        for record in &records {
            let (cid, rid) = match &record.mutation {
                PageWalMutation::Put { cid, rid, .. }
                | PageWalMutation::Delete { cid, rid, .. } => (*cid, *rid),
            };
            high_water
                .entry(cid)
                .and_modify(|next: &mut u64| *next = (*next).max(rid.0.saturating_add(1)))
                .or_insert(rid.0.saturating_add(1));
        }
        let mut collections = BTreeMap::new();
        let mut existing = BTreeSet::new();
        if layout.data_root().exists() {
            for entry in std::fs::read_dir(layout.data_root())? {
                let entry = entry?;
                let cid = Cid(super::recovery::collection_id(&entry.path())?);
                existing.insert(cid);
            }
        }
        existing.extend(high_water.keys().copied());
        for cid in existing {
            let path = layout.critical_map_path(cid, "rid_to_slot").path;
            if high_water.contains_key(&cid) && (!path.exists() || path.metadata()?.len() == 0) {
                return Err(PraxisError::PageRecoveryRequired {
                    path,
                    reason: "WAL history exists without the canonical RID directory/high-water; v1 cannot prove complete allocation history (see issue #41)".to_string(),
                });
            }
            let mut collection = load_collection(&layout, cid)?;
            collection.next_rid = collection
                .next_rid
                .max(high_water.get(&cid).copied().unwrap_or(1));
            collections.insert(cid, collection);
        }
        validate_canonical_log(&layout, &collections, &records)?;
        layout.create_all()?;
        Ok(Self {
            inner: Arc::new(PageDatabaseInner {
                layout,
                state: Mutex::new(PageDatabaseState {
                    collections,
                    ..PageDatabaseState::default()
                }),
                _writer_lease: writer_lease,
            }),
        })
    }

    pub fn page_wal(&self, policy: WalSyncPolicy) -> Result<PageWal> {
        let mut state = self.lock()?;
        let path = self.inner.layout.logs_root().join("page.wal");
        if let Some(writer) = &state.wal {
            if writer.policy() != policy {
                return Err(PraxisError::InvalidConfig(
                    "one page root cannot use conflicting WAL sync policies".to_string(),
                ));
            }
        } else {
            match PageWalWriter::open(&path, policy) {
                Ok(writer) => state.wal = Some(writer),
                Err(error) => {
                    // Opening may create/sync a header. Retain ownership and fail
                    // closed rather than retry a possibly partial writer.
                    state.recovery_required = Some(error.to_string());
                    return Err(error);
                }
            }
        }
        Ok(PageWal::from_owner(self.clone(), path))
    }

    /// Apply an intact canonical log against its validated directory. V1
    /// directory loss is ambiguous and is refused by `open`, never guessed.
    pub fn recover_from_page_wal(base: impl Into<PathBuf>) -> Result<Self> {
        let database = Self::open(base)?;
        let records = read_page_wal_strict(&database.inner.layout.logs_root().join("page.wal"))?;
        {
            let state = database.lock()?;
            validate_canonical_log(&database.inner.layout, &state.collections, &records)?;
        }
        let mut views: BTreeMap<(Cid, Eid), Vec<PageWalRecord>> = BTreeMap::new();
        for record in records {
            let (cid, eid) = match &record.mutation {
                PageWalMutation::Put { cid, eid, .. }
                | PageWalMutation::Delete { cid, eid, .. } => (*cid, *eid),
            };
            views.entry((cid, eid)).or_default().push(record);
        }
        for ((cid, eid), records) in views {
            database.entity(cid, eid)?.replay_page_wal(&records)?;
        }
        Ok(database)
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn page_wal_bytes(&self) -> Result<u64> {
        let state = self.lock()?;
        state
            .wal
            .as_ref()
            .map(PageWalWriter::bytes_written)
            .ok_or_else(|| PraxisError::InvalidConfig("page WAL is not open".to_string()))
    }

    pub(crate) fn sync_page_wal(&self) -> Result<()> {
        let mut state = self.lock()?;
        let result = state
            .wal
            .as_mut()
            .ok_or_else(|| PraxisError::InvalidConfig("page WAL is not open".to_string()))?
            .sync();
        if let Err(error) = &result {
            state.recovery_required = Some(error.to_string());
        }
        result
    }

    pub fn entity(&self, cid: Cid, eid: Eid) -> Result<PageRecordStore> {
        if cid.is_null() || eid.is_null() {
            return Err(PraxisError::InvalidConfig(
                "page collection and entity IDs must be nonzero".to_string(),
            ));
        }
        let mut state = self.lock()?;
        if state.initialized_entities.contains(&(cid, eid)) {
            return Ok(PageRecordStore {
                database: self.clone(),
                cid,
                eid,
                fid: Fid(1),
            });
        }
        let collection = if state.collections.contains_key(&cid) {
            None
        } else {
            Some(load_collection(&self.inner.layout, cid)?)
        };
        // Layout creation can partially publish files. Do not leave any live
        // facade usable if initialization fails after starting that work.
        if let Err(error) = self.inner.layout.ensure_entity_tree(cid, eid) {
            state.recovery_required = Some(error.to_string());
            return Err(error);
        }
        if let Some(collection) = collection {
            state.collections.insert(cid, collection);
        }
        state.initialized_entities.insert((cid, eid));
        Ok(PageRecordStore {
            database: self.clone(),
            cid,
            eid,
            fid: Fid(1),
        })
    }

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, PageDatabaseState>> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| self.recovery_error("page state mutex was poisoned"))?;
        if let Some(reason) = &state.recovery_required {
            return Err(self.recovery_error(reason.clone()));
        }
        Ok(state)
    }

    fn recovery_error(&self, reason: impl Into<String>) -> PraxisError {
        PraxisError::PageRecoveryRequired {
            path: self.inner.layout.root().to_path_buf(),
            reason: reason.into(),
        }
    }
}

fn validate_canonical_log(
    layout: &PraxisLayout,
    collections: &BTreeMap<Cid, CollectionState>,
    records: &[PageWalRecord],
) -> Result<()> {
    let path = layout.logs_root().join("page.wal");
    let mut bindings = BTreeMap::new();
    let mut views: BTreeMap<(Cid, Eid), Vec<&PageWalRecord>> = BTreeMap::new();
    for record in records {
        let (cid, eid, rid) = match &record.mutation {
            PageWalMutation::Put { cid, eid, rid, .. }
            | PageWalMutation::Delete { cid, eid, rid } => (*cid, *eid, *rid),
        };
        if let Some(previous) = bindings.insert((cid, rid), eid)
            && previous != eid
        {
            return Err(PraxisError::Corrupt {
                path,
                reason: "canonical WAL binds one RID to multiple entities".to_string(),
            });
        }
        views.entry((cid, eid)).or_default().push(record);
    }
    // Every view is checked before any apply/layout writes. Borrow records so
    // admission does not duplicate an entire log's field payloads.
    for ((cid, eid), records) in views {
        let collection =
            collections
                .get(&cid)
                .ok_or_else(|| PraxisError::PageRecoveryRequired {
                    path: layout.critical_map_path(cid, "rid_to_slot").path,
                    reason: "canonical WAL collection has no validated directory".to_string(),
                })?;
        PageOperation::borrowed(layout, cid, eid, Fid(1), collection).validate_replay(records)?;
    }
    Ok(())
}

impl PageRecordStore {
    pub(super) fn with_read<T>(
        &self,
        action: impl FnOnce(&PageOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        let state = self.database.lock()?;
        let collection = state.collections.get(&self.cid).ok_or_else(|| {
            PraxisError::InvalidConfig("page entity has no collection owner".to_string())
        })?;
        let operation = PageOperation::borrowed(
            &self.database.inner.layout,
            self.cid,
            self.eid,
            self.fid,
            collection,
        );
        action(&operation)
    }

    pub(super) fn with_mutation<T>(
        &self,
        action: impl FnOnce(&mut PageOperation<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_candidate(|operation, _| action(operation))
    }

    pub(super) fn with_wal_mutation<T>(
        &self,
        wal: &PageWal,
        action: impl FnOnce(&mut PageOperation<'_>, &mut PageWalWriter) -> Result<T>,
    ) -> Result<T> {
        if !self.database.same_owner(&wal.database) {
            return Err(PraxisError::InvalidConfig(
                "page WAL belongs to a different explicit root owner".to_string(),
            ));
        }
        self.with_candidate(|operation, state| {
            let writer = state
                .wal
                .as_mut()
                .ok_or_else(|| PraxisError::InvalidConfig("page WAL is not open".to_string()))?;
            action(operation, writer)
        })
    }

    fn with_candidate<T>(
        &self,
        action: impl FnOnce(&mut PageOperation<'_>, &mut PageDatabaseState) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.database.lock()?;
        let collection = state.collections.get(&self.cid).ok_or_else(|| {
            PraxisError::InvalidConfig("page entity has no collection owner".to_string())
        })?;
        let mut operation = PageOperation::candidate(
            &self.database.inner.layout,
            self.cid,
            self.eid,
            self.fid,
            collection,
        );
        match action(&mut operation, &mut state) {
            Ok(result) => {
                let collection = state.collections.get_mut(&self.cid).ok_or_else(|| {
                    PraxisError::InvalidConfig("page collection owner disappeared".to_string())
                })?;
                collection.next_rid = operation.next_rid;
                collection.cursors.insert(
                    (self.eid, self.fid),
                    EntityCursor {
                        current_pid: operation.current_pid,
                        next_sid: operation.next_sid,
                    },
                );
                collection.directory = operation.directory.into_owned();
                collection.deleted = operation.deleted.into_owned();
                Ok(result)
            }
            Err(error) => {
                if operation.side_effects.get() {
                    state.recovery_required = Some(error.to_string());
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Aid, FieldId};
    use crate::wal::page::PageWalFailure;
    use std::path::Path;

    fn assert_failed_closed(
        database: &PageDatabase,
        store: &mut PageRecordStore,
        wal: &mut PageWal,
    ) {
        let clone = store.clone();
        let mut other = store.clone();
        assert!(matches!(
            store.get(Rid(1)),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            clone.directory(),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            other.put(&[(FieldId::Fixed(Aid(1)), b"retry")]),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            store.put_durable(wal, &[(FieldId::Fixed(Aid(1)), b"retry")]),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            database.entity(Cid(2), Eid(2)),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            database.page_wal(WalSyncPolicy::EveryBatch),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            wal.bytes_written(),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            wal.sync(),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            PageDatabase::open(database.inner._writer_lease.root()),
            Err(PraxisError::AlreadyOpen { .. })
        ));
        // Inspect the guarded state without using the poisoned public access path:
        // an errored candidate must not publish a receipt/allocator update.
        let state = database.inner.state.lock().unwrap();
        let collection = &state.collections[&Cid(1)];
        assert_eq!(collection.next_rid, 2);
        assert!(collection.directory.resolve(Rid(2)).is_err());
        assert_eq!(collection.cursors[&(Eid(2), Fid(1))].next_sid, 2);
    }

    fn initialized(root: &Path, policy: WalSyncPolicy) -> (PageDatabase, PageRecordStore, PageWal) {
        let database = PageDatabase::open(root).unwrap();
        let mut store = database.entity(Cid(1), Eid(2)).unwrap();
        assert_eq!(
            store.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap(),
            Rid(1)
        );
        let wal = database.page_wal(policy).unwrap();
        (database, store, wal)
    }

    #[test]
    fn partial_wal_append_poison_is_shared_and_torn_reopen_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (database, mut store, mut wal) = initialized(dir.path(), WalSyncPolicy::EveryBatch);
        let before = std::fs::read(wal.path()).unwrap();
        database
            .inner
            .state
            .lock()
            .unwrap()
            .wal
            .as_mut()
            .unwrap()
            .fail_next(PageWalFailure::AppendAfterPrefix(7));
        let result = store.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"unacknowledged")]);
        assert!(matches!(result, Err(PraxisError::Io(_))));
        let torn = std::fs::read(wal.path()).unwrap();
        assert_eq!(torn.len(), before.len() + 7);
        assert_eq!(&torn[..before.len()], before);
        assert_failed_closed(&database, &mut store, &mut wal);
        assert_eq!(std::fs::read(wal.path()).unwrap(), torn);
        drop(store);
        drop(database);
        assert!(matches!(
            PageDatabase::open(dir.path()),
            Err(PraxisError::AlreadyOpen { .. })
        ));
        let path = wal.path().to_owned();
        drop(wal);
        assert!(PageDatabase::open(dir.path()).is_err());
        assert_eq!(std::fs::read(path).unwrap(), torn);
    }

    #[test]
    fn every_batch_and_group_commit_sync_failures_poison_before_page_publication() {
        for policy in [WalSyncPolicy::EveryBatch, WalSyncPolicy::GroupCommit] {
            let dir = tempfile::tempdir().unwrap();
            let (database, mut store, mut wal) = initialized(dir.path(), policy);
            let page = store
                .layout()
                .page_path(Cid(1), Eid(2), Fid(1), Pid(1))
                .path;
            let before_page = std::fs::read(&page).unwrap();
            database
                .inner
                .state
                .lock()
                .unwrap()
                .wal
                .as_mut()
                .unwrap()
                .fail_next(PageWalFailure::Sync);
            let result =
                store.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"unacknowledged")]);
            assert!(matches!(result, Err(PraxisError::Io(_))));
            assert_eq!(std::fs::read(&page).unwrap(), before_page);
            assert_eq!(PageWal::replay(wal.path()).unwrap().len(), 1);
            assert_failed_closed(&database, &mut store, &mut wal);
            drop(wal);
            drop(store);
            drop(database);
            // A complete log is still not automatically applied on normal open.
            let reopened = PageDatabase::open(dir.path()).unwrap();
            assert!(matches!(
                reopened.entity(Cid(1), Eid(2)).unwrap().get(Rid(2)),
                Err(PraxisError::KeyNotFound)
            ));
            drop(reopened);
            let recovered = PageDatabase::recover_from_page_wal(dir.path()).unwrap();
            assert_eq!(
                recovered
                    .entity(Cid(1), Eid(2))
                    .unwrap()
                    .get(Rid(2))
                    .unwrap(),
                b"unacknowledged"
            );
        }
    }

    #[test]
    fn never_policy_defers_sync_and_an_explicit_sync_error_poison_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let (database, mut store, mut wal) = initialized(dir.path(), WalSyncPolicy::Never);
        database
            .inner
            .state
            .lock()
            .unwrap()
            .wal
            .as_mut()
            .unwrap()
            .fail_next(PageWalFailure::Sync);
        let rid = store
            .put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"unsynced")])
            .unwrap();
        assert_eq!(rid, Rid(2));
        assert_eq!(store.get(rid).unwrap(), b"unsynced");
        assert!(matches!(wal.sync(), Err(PraxisError::Io(_))));
        assert!(matches!(
            store.get(rid),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            wal.sync(),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
    }
}

#[cfg(test)]
mod catalog_health_tests {
    use super::*;
    use crate::catalog::{CatalogSnapshot, CatalogStore};
    use crate::identity::{Aid, FieldId};
    use crate::wal::page::PageWalFailure;

    #[test]
    fn wal_sync_uncertainty_poison_reaches_existing_catalog_views() {
        let dir = tempfile::tempdir().unwrap();
        let database = PageDatabase::open(dir.path()).unwrap();
        let catalog = CatalogStore::new(database.clone());
        let clone = catalog.clone();
        let mut page = database.entity(Cid(1), Eid(2)).unwrap();
        page.put(&[(FieldId::Fixed(Aid(1)), b"old")]).unwrap();
        catalog.save(&CatalogSnapshot::default()).unwrap();
        let mut wal = database.page_wal(WalSyncPolicy::EveryBatch).unwrap();
        database
            .inner
            .state
            .lock()
            .unwrap()
            .wal
            .as_mut()
            .unwrap()
            .fail_next(PageWalFailure::Sync);
        assert!(matches!(
            page.put_durable(&mut wal, &[(FieldId::Fixed(Aid(1)), b"uncertain")]),
            Err(PraxisError::Io(_))
        ));
        assert!(matches!(
            catalog.load(),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
        assert!(matches!(
            clone.save(&CatalogSnapshot::default()),
            Err(PraxisError::PageRecoveryRequired { .. })
        ));
    }
}
