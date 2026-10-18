//! Process-local record capability over one existing core pin and live owner.
use super::schema::{RecordAuthority, corrupt};
use crate::memory::PinnedSnapshot;
use crate::{PraxisEngine, PraxisError, Result};
use std::sync::Arc;

/// An opaque, cloneable registration of one published core view.
///
/// Clones retain the same pin and writer owner until the last clone drops.
/// This handle is neither serializable nor transferable to a reopened/backup
/// owner, even when that owner's persisted database identity is identical.
#[derive(Clone)]
pub struct CoreRecordSnapshot {
    inner: Arc<SnapshotInner>,
}

struct SnapshotInner {
    // Drop the pin before the owner, which retains the underlying writer lease.
    pin: PinnedSnapshot,
    authority: RecordAuthority,
    engine: PraxisEngine,
}

impl CoreRecordSnapshot {
    pub(super) fn new(engine: PraxisEngine, pin: PinnedSnapshot) -> Result<Self> {
        let authority = {
            let manifest = engine.inner.manifest.lock();
            let source = engine.inner.layout.manifest_path();
            let authority = manifest.record_authority.as_ref().ok_or_else(|| {
                corrupt(&source, "record snapshot requires a validated authority")
            })?;
            // CoreRecordStore is created only from an admitted CoreDatabase;
            // public CF operations cannot mutate its protected bindings.
            authority.validate_binding(&source)?;
            authority.clone()
        };
        Ok(Self {
            inner: Arc::new(SnapshotInner {
                pin,
                authority,
                engine,
            }),
        })
    }

    /// Diagnostic commit endpoint only; this number cannot register another view.
    pub fn core_sequence(&self) -> u64 {
        self.inner.pin.sequence()
    }

    pub(super) fn pin_for(&self, engine: &PraxisEngine) -> Result<&PinnedSnapshot> {
        if !Arc::ptr_eq(&self.inner.engine.inner, &engine.inner) {
            return Err(PraxisError::ForeignRecordSnapshot {
                reason: "live owner differs",
            });
        }
        if engine.inner.manifest.lock().record_authority.as_ref() != Some(&self.inner.authority) {
            return Err(PraxisError::ForeignRecordSnapshot {
                reason: "authority binding differs",
            });
        }
        engine.inner.group_commit.ensure_writable()?;
        Ok(&self.inner.pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreDatabase, PraxisConfig, RecordAuthorityOptions};

    #[test]
    fn checked_reads_reject_changed_identity_epoch_or_role_binding_without_new_pins() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoreDatabase::create_fresh(
            PraxisConfig::new(dir.path()),
            RecordAuthorityOptions::default(),
        )
        .unwrap();
        let records = db.records();
        let rid = records.put(b"v", &[]).unwrap();
        for changed in 0..3 {
            let mut token = records.pin_snapshot().unwrap();
            let inner = Arc::get_mut(&mut token.inner).unwrap();
            match changed {
                0 => inner.authority.database_id = "00".repeat(16),
                1 => inner.authority.epoch += 1,
                _ => inner.authority.roles[0].generation += 1,
            }
            macro_rules! foreign {
                ($call:expr) => {
                    assert!(matches!(
                        $call,
                        Err(PraxisError::ForeignRecordSnapshot {
                            reason: "authority binding differs"
                        })
                    ));
                };
            }
            foreign!(records.fetch_at_snapshot(rid, &token));
            foreign!(records.lookup_rid_at_snapshot("unknown", b"k", &token));
            foreign!(records.fetch_by_index_at_snapshot("unknown", b"k", &token));
            assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
            assert_eq!(records.fetch(rid).unwrap(), b"v");
        }
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
    }

    #[test]
    fn invalid_owner_binding_cannot_create_a_token_or_leak_its_pin() {
        let dir = tempfile::tempdir().unwrap();
        let db = CoreDatabase::create_fresh(
            PraxisConfig::new(dir.path()),
            RecordAuthorityOptions::default(),
        )
        .unwrap();
        let engine = db.kv();
        engine
            .inner
            .manifest
            .lock()
            .record_authority
            .as_mut()
            .unwrap()
            .epoch = 2;
        assert!(matches!(
            db.records().pin_snapshot(),
            Err(PraxisError::Corrupt { .. })
        ));
        assert_eq!(engine.inner.snapshots.pinned_count(), 0);
    }
}
