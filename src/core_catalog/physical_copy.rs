//! Private physical-copy admission seam for protected installed rows.
//!
//! The bounded segment visitor and its witnesses precede this ledger. Until
//! equality proof exists, this entrypoint never grants copy admission.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue};
use super::segment_witness::{
    ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass, ProtectedRole,
    ProtectedSegmentCandidate, SegmentFileWitness, SegmentSource,
    collect_protected_segment_candidate,
};
use super::value_witness::{ValueFileScanProbe, ValueWitnessCandidate, collect_value_witness};
use crate::core_records::codec::{Key as RecordKey, Role as RecordRole, Row as RecordRow};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::wal::catalog_witness::{PhysicalWitnessBudget, vector_charge};
use std::cmp::Ordering;
use std::path::Path;

const MAX_PROTECTED_COPY_ROWS: usize = 65_536;
const MAX_PROTECTED_COPY_TRIPLES: usize = 65_536;
const MAX_COPY_LEDGER_RETAINED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
struct CopyProofLimits {
    max_rows: usize,
    max_triples: usize,
    max_metadata_bytes: usize,
}

const COPY_PROOF_LIMITS: CopyProofLimits = CopyProofLimits {
    max_rows: MAX_PROTECTED_COPY_ROWS,
    max_triples: MAX_PROTECTED_COPY_TRIPLES,
    max_metadata_bytes: MAX_COPY_LEDGER_RETAINED_BYTES,
};

fn corrupt(root: &Path, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: root.to_path_buf(),
        reason: reason.into(),
    }
}

fn metadata_limit() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "protected physical-copy metadata exceeds the private proof profile",
    }
}

fn pending_replay() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "protected physical-copy bytes await authenticated replay",
    }
}

#[allow(dead_code)] // Compared only after authenticated replay lands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyWireOperation {
    Put { len: u64 },
    Delete,
    Pointer { len: u64 },
}

/// The descriptor retains physical order, not a selected current version.
#[allow(dead_code)] // Retained for the later authenticated group comparison.
#[derive(Debug)]
struct CopyDescriptor {
    cf: String,
    key: Vec<u8>,
    sequence: u64,
    source: SegmentSource,
    block_offset: u64,
    row_ordinal: u32,
    operation: CopyWireOperation,
}

#[allow(dead_code)] // Group boundaries remain private until byte replay lands.
#[derive(Debug)]
struct CopyTripleGroup {
    start: usize,
    end: usize,
}

/// All three receipts remain live until an eventual owner composer discards
/// this private candidate. No field grants a current-version or owner claim.
#[allow(dead_code)] // Equality replay is the next #82 implementation slice.
#[derive(Debug)]
pub(crate) struct ProtectedCopyLedgerCandidate {
    segment: ProtectedSegmentCandidate,
    value: Option<ValueWitnessCandidate>,
    descriptors: Vec<CopyDescriptor>,
    groups: Vec<CopyTripleGroup>,
    metadata_charge: usize,
}

#[allow(dead_code)] // Used once authenticated replay can complete admission.
impl ProtectedCopyLedgerCandidate {
    pub(crate) fn discard(self, root: &Path, budget: &mut PhysicalWitnessBudget) -> Result<()> {
        let Self {
            segment,
            value,
            descriptors,
            groups,
            metadata_charge,
        } = self;
        drop(groups);
        drop(descriptors);
        budget.release(root, metadata_charge)?;
        if let Some(value) = value {
            value.discard(root, budget)?;
        }
        segment.discard(root, budget)
    }
}

/// Owns each child receipt as soon as it is acquired. Drop is the unwind
/// fallback; the normal error path uses `fail` to return refund errors.
struct CopyAttempt<'a> {
    root: &'a Path,
    budget: &'a mut PhysicalWitnessBudget,
    limits: CopyProofLimits,
    segment: Option<ProtectedSegmentCandidate>,
    value: Option<ValueWitnessCandidate>,
    descriptors: Vec<CopyDescriptor>,
    groups: Vec<CopyTripleGroup>,
    metadata_charge: usize,
}

impl<'a> CopyAttempt<'a> {
    fn new(root: &'a Path, budget: &'a mut PhysicalWitnessBudget, limits: CopyProofLimits) -> Self {
        Self {
            root,
            budget,
            limits,
            segment: None,
            value: None,
            descriptors: Vec::new(),
            groups: Vec::new(),
            metadata_charge: 0,
        }
    }

    fn charge_metadata(&mut self, bytes: usize) -> Result<()> {
        let next = self
            .metadata_charge
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.max_metadata_bytes)
            .ok_or_else(metadata_limit)?;
        if bytes > self.budget.remaining_bytes() {
            return Err(metadata_limit());
        }
        self.budget.charge(self.root, bytes)?;
        self.metadata_charge = next;
        Ok(())
    }

    fn reserve_descriptors(&mut self, rows: usize) -> Result<()> {
        if rows > self.limits.max_rows {
            return Err(metadata_limit());
        }
        let charge = vector_charge::<CopyDescriptor>(self.root, rows)?;
        self.charge_metadata(charge)?;
        self.descriptors
            .try_reserve_exact(rows)
            .map_err(|_| metadata_limit())?;
        let actual = self
            .descriptors
            .capacity()
            .checked_mul(std::mem::size_of::<CopyDescriptor>())
            .ok_or_else(metadata_limit)?;
        if actual > charge {
            return Err(metadata_limit());
        }
        Ok(())
    }

    fn push_descriptor(&mut self, row: &ObservedSegmentRow) -> Result<()> {
        if self.descriptors.len() == self.descriptors.capacity() {
            return Err(metadata_limit());
        }
        let copied_bytes = row
            .cf
            .len()
            .checked_add(row.key.len())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(128))
            .ok_or_else(metadata_limit)?;
        self.charge_metadata(copied_bytes)?;
        let mut cf = String::new();
        cf.try_reserve_exact(row.cf.len())
            .map_err(|_| metadata_limit())?;
        cf.push_str(&row.cf);
        let mut key = Vec::new();
        key.try_reserve_exact(row.key.len())
            .map_err(|_| metadata_limit())?;
        key.extend_from_slice(&row.key);
        if cf
            .capacity()
            .checked_add(key.capacity())
            .ok_or_else(metadata_limit)?
            > copied_bytes
        {
            return Err(metadata_limit());
        }
        let operation = match &row.value {
            ObservedSegmentValue::Put(bytes) => CopyWireOperation::Put {
                len: bytes.len() as u64,
            },
            ObservedSegmentValue::Delete => CopyWireOperation::Delete,
            ObservedSegmentValue::Pointer { pointer, .. } => {
                CopyWireOperation::Pointer { len: pointer.len }
            }
            ObservedSegmentValue::PutWithExpiry { .. } | ObservedSegmentValue::Merge(_) => {
                return Err(corrupt(
                    self.root,
                    "protected copy has an invalid wire operation",
                ));
            }
        };
        self.descriptors.push(CopyDescriptor {
            cf,
            key,
            sequence: row.sequence,
            source: row.source,
            block_offset: row.block_offset,
            row_ordinal: row.row_ordinal,
            operation,
        });
        Ok(())
    }

    fn build_groups(&mut self, manifest: &Manifest) -> Result<()> {
        // The first in-place ordering exposes reused physical locators without
        // allocating an unbounded hash table.
        self.descriptors.sort_unstable_by(|a, b| {
            source_order(a.source, b.source)
                .then(a.block_offset.cmp(&b.block_offset))
                .then(a.row_ordinal.cmp(&b.row_ordinal))
        });
        let witnesses = &self
            .segment
            .as_ref()
            .expect("copy attempt owns its segment receipt")
            .witnesses;
        for (index, descriptor) in self.descriptors.iter().enumerate() {
            if index > 0 {
                let previous = &self.descriptors[index - 1];
                if source_order(previous.source, descriptor.source) == Ordering::Equal
                    && previous.block_offset == descriptor.block_offset
                    && previous.row_ordinal == descriptor.row_ordinal
                {
                    return Err(corrupt(self.root, "protected physical locator is reused"));
                }
            }
            if index == 0
                || source_order(self.descriptors[index - 1].source, descriptor.source)
                    != Ordering::Equal
            {
                let listed = manifest
                    .segments
                    .get(descriptor.source.manifest_ordinal)
                    .ok_or_else(|| corrupt(self.root, "protected row has no MANIFEST source"))?;
                if listed.level != descriptor.source.level || listed.id != descriptor.source.id {
                    return Err(corrupt(
                        self.root,
                        "protected row source differs from MANIFEST",
                    ));
                }
                if witnesses
                    .iter()
                    .filter(|witness| witness.source == descriptor.source)
                    .count()
                    != 1
                {
                    return Err(corrupt(self.root, "protected row source lacks one witness"));
                }
            }
        }
        self.descriptors.sort_unstable_by(|a, b| {
            a.cf.cmp(&b.cf)
                .then(a.key.cmp(&b.key))
                .then(a.sequence.cmp(&b.sequence))
                .then(source_order(a.source, b.source))
                .then(a.block_offset.cmp(&b.block_offset))
                .then(a.row_ordinal.cmp(&b.row_ordinal))
        });
        let mut triples = 0usize;
        for index in 0..self.descriptors.len() {
            if index == 0 || !same_triple(&self.descriptors[index - 1], &self.descriptors[index]) {
                triples = triples.checked_add(1).ok_or_else(metadata_limit)?;
                if triples > self.limits.max_triples {
                    return Err(metadata_limit());
                }
            }
        }
        let charge = vector_charge::<CopyTripleGroup>(self.root, triples)?;
        self.charge_metadata(charge)?;
        self.groups
            .try_reserve_exact(triples)
            .map_err(|_| metadata_limit())?;
        let actual = self
            .groups
            .capacity()
            .checked_mul(std::mem::size_of::<CopyTripleGroup>())
            .ok_or_else(metadata_limit)?;
        if actual > charge {
            return Err(metadata_limit());
        }
        for index in 0..self.descriptors.len() {
            if index == 0 || !same_triple(&self.descriptors[index - 1], &self.descriptors[index]) {
                self.groups.push(CopyTripleGroup {
                    start: index,
                    end: index + 1,
                });
            } else {
                self.groups
                    .last_mut()
                    .expect("the first descriptor opened a group")
                    .end = index + 1;
            }
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        drop(std::mem::take(&mut self.groups));
        drop(std::mem::take(&mut self.descriptors));
        let metadata_charge = std::mem::take(&mut self.metadata_charge);
        self.budget.release(self.root, metadata_charge)?;
        if let Some(value) = self.value.take() {
            value.discard(self.root, self.budget)?;
        }
        if let Some(segment) = self.segment.take() {
            segment.discard(self.root, self.budget)?;
        }
        Ok(())
    }

    fn fail<T>(mut self, error: PraxisError) -> Result<T> {
        self.cleanup()?;
        Err(error)
    }

    #[allow(dead_code)] // Transfer is gated on the next authenticated-byte slice.
    fn finish(mut self) -> ProtectedCopyLedgerCandidate {
        ProtectedCopyLedgerCandidate {
            segment: self.segment.take().expect("segment receipt is present"),
            value: self.value.take(),
            descriptors: std::mem::take(&mut self.descriptors),
            groups: std::mem::take(&mut self.groups),
            metadata_charge: std::mem::take(&mut self.metadata_charge),
        }
    }
}

impl Drop for CopyAttempt<'_> {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            std::process::abort();
        }
    }
}

fn source_order(a: SegmentSource, b: SegmentSource) -> Ordering {
    (a.level, a.id, a.manifest_ordinal).cmp(&(b.level, b.id, b.manifest_ordinal))
}

fn same_triple(a: &CopyDescriptor, b: &CopyDescriptor) -> bool {
    a.cf == b.cf && a.key == b.key && a.sequence == b.sequence
}

fn preflight_row(root: &Path, manifest: &Manifest, row: &ObservedSegmentRow) -> Result<bool> {
    if row.sequence == 0 || row.sequence > manifest.flushed_sequence {
        return Err(corrupt(
            root,
            "protected copy sequence is outside the installed cut",
        ));
    }
    let role = match row.classification {
        PhysicalRowClass::BoundProtected(role) => role,
        PhysicalRowClass::ReservedUnbound | PhysicalRowClass::Other => {
            return Err(corrupt(root, "protected copy has no bound role"));
        }
    };
    if matches!(
        &row.value,
        ObservedSegmentValue::PutWithExpiry { .. } | ObservedSegmentValue::Merge(_)
    ) {
        return Err(corrupt(
            root,
            "protected copy has an invalid wire operation",
        ));
    }
    if let ObservedSegmentValue::Pointer { expires_at_ms, .. } = &row.value
        && expires_at_ms.is_some()
    {
        return Err(corrupt(root, "protected copy pointer expires"));
    }
    if role == ProtectedRole::Catalog {
        let authority = manifest
            .catalog_authority
            .as_ref()
            .ok_or_else(|| corrupt(root, "catalog authority is absent"))?;
        if row.cf != CATALOG_CF || row.cf != authority.binding.column_family {
            return Err(corrupt(
                root,
                "catalog copy role or binding differs from MANIFEST",
            ));
        }
        let key = CatalogKey::decode(&row.key, root)?;
        let anchor = matches!(&key, CatalogKey::Anchor);
        if (anchor && row.sequence != 1)
            || (!anchor && !matches!(&key, CatalogKey::Head) && row.sequence < 2)
        {
            return Err(corrupt(root, "catalog copy key has an invalid sequence"));
        }
        match &row.value {
            ObservedSegmentValue::Put(bytes) => {
                if !matches!(&key, CatalogKey::Schema(_)) {
                    let decoded = CatalogValue::decode(&key, bytes, root)?;
                    if let CatalogValue::Anchor(value) = decoded {
                        let expected = manifest
                            .record_authority
                            .as_ref()
                            .ok_or_else(|| corrupt(root, "record authority is absent"))?
                            .identity(root)?;
                        if value.database_id != expected {
                            return Err(corrupt(
                                root,
                                "catalog Anchor differs from MANIFEST identity",
                            ));
                        }
                    }
                }
            }
            ObservedSegmentValue::Pointer { .. } => {}
            ObservedSegmentValue::Delete => {
                return Err(corrupt(root, "catalog copy has forbidden Delete"));
            }
            ObservedSegmentValue::PutWithExpiry { .. } | ObservedSegmentValue::Merge(_) => {
                unreachable!("invalid operation was rejected above")
            }
        }
        return Ok(anchor);
    }
    let record_role = RecordRole::from_cf(&row.cf)
        .ok_or_else(|| corrupt(root, "record copy has no protected role"))?;
    let expected_role = match record_role {
        RecordRole::Meta => ProtectedRole::Meta,
        RecordRole::Payload => ProtectedRole::Payload,
        RecordRole::State => ProtectedRole::State,
        RecordRole::Index => ProtectedRole::Index,
    };
    if role != expected_role
        || !manifest
            .record_authority
            .as_ref()
            .ok_or_else(|| corrupt(root, "record authority is absent"))?
            .roles
            .iter()
            .any(|binding| binding.column_family == row.cf)
    {
        return Err(corrupt(
            root,
            "record copy role or binding differs from MANIFEST",
        ));
    }
    let key = RecordKey::decode(record_role, &row.key, root)?;
    if matches!(&key, RecordKey::Binding) && row.sequence != 1 {
        return Err(corrupt(
            root,
            "record Binding copy is outside bootstrap sequence",
        ));
    }
    match &row.value {
        ObservedSegmentValue::Put(bytes) => {
            let _decoded = RecordRow::decode(&key, bytes, root)?;
        }
        ObservedSegmentValue::Pointer { .. } => {}
        ObservedSegmentValue::Delete if matches!(&key, RecordKey::Payload(_)) => {}
        ObservedSegmentValue::Delete => {
            return Err(corrupt(root, "record copy has forbidden Delete"));
        }
        ObservedSegmentValue::PutWithExpiry { .. } | ObservedSegmentValue::Merge(_) => {
            unreachable!("invalid operation was rejected above")
        }
    }
    Ok(false)
}

/// Stages an owned, bounded physical ledger candidate without granting copy
/// equivalence. The next slice must replay authenticated bytes before `finish`.
#[allow(dead_code)] // Called by the private #82 integration after replay lands.
pub(crate) fn collect_protected_copy_ledger(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
) -> Result<ProtectedCopyLedgerCandidate> {
    manifest.validate_v4(root)?;
    let mut attempt = CopyAttempt::new(root, budget, COPY_PROOF_LIMITS);
    match collect_protected_segment_candidate(root, manifest, &mut *attempt.budget) {
        Ok(segment) => attempt.segment = Some(segment),
        Err(error) => return attempt.fail(error),
    }
    let rows = &attempt
        .segment
        .as_ref()
        .expect("segment receipt exists")
        .rows;
    let mut anchors = 0usize;
    let mut pointers = 0usize;
    let preflight = (|| -> Result<()> {
        if rows.len() > attempt.limits.max_rows {
            return Err(metadata_limit());
        }
        for row in rows {
            anchors += usize::from(preflight_row(root, manifest, row)?);
            pointers += usize::from(matches!(&row.value, ObservedSegmentValue::Pointer { .. }));
        }
        if anchors != 1 {
            return Err(corrupt(root, "catalog Anchor must have one physical copy"));
        }
        Ok(())
    })();
    if let Err(error) = preflight {
        return attempt.fail(error);
    }
    if pointers != 0 {
        let mut probe = ValueFileScanProbe::default();
        match collect_value_witness(root, manifest, rows, &mut *attempt.budget, &mut probe) {
            Ok(value) => attempt.value = Some(value),
            Err(error) => return attempt.fail(error),
        }
    }
    let rows = std::mem::take(
        &mut attempt
            .segment
            .as_mut()
            .expect("segment receipt exists")
            .rows,
    );
    let metadata = (|| -> Result<()> {
        attempt.reserve_descriptors(rows.len())?;
        for row in &rows {
            attempt.push_descriptor(row)?;
        }
        attempt.build_groups(manifest)
    })();
    drop(rows);
    if let Err(error) = metadata {
        return attempt.fail(error);
    }
    // No positive result is possible until a witnessed row accessor has
    // compared each group's actual bytes while all receipts remain live.
    attempt.fail(pending_replay())
}

/// A source locator stays tied to a physical row, before any version fold.
#[allow(dead_code)] // Deliberately unconstructed until the #82 GREEN admission proof.
#[derive(Debug)]
pub(crate) struct PhysicalCopySource {
    pub(crate) source: SegmentSource,
    pub(crate) block_offset: u64,
    pub(crate) row_ordinal: u32,
    pub(crate) cf: String,
    pub(crate) key: Vec<u8>,
    pub(crate) sequence: u64,
}

/// Admitted copy locations and their authenticated source-file receipts.
#[allow(dead_code)] // The RED stub cannot construct a ledger before equivalence proof.
#[derive(Debug)]
pub(crate) struct ProtectedCopyLedger {
    pub(crate) copies: Vec<PhysicalCopySource>,
    pub(crate) segment_witnesses: Vec<SegmentFileWitness>,
}

/// The future ledger must prove every same-(CF,key,S) physical source before
/// selecting a current version. It does not expose public owner authority.
#[allow(dead_code)] // Called only by the focused RED until private admission exists.
pub(crate) fn admit_protected_physical_copies(
    _root: &Path,
    _manifest: &Manifest,
    _observed: &[ObservedSegmentRow],
    _witnesses: &[SegmentFileWitness],
    _budget: &mut PhysicalWitnessBudget,
) -> Result<ProtectedCopyLedger> {
    Err(PraxisError::UnsupportedCatalogFeature {
        feature: "protected physical-copy ledger not implemented",
    })
}
