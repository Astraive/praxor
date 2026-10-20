//! Private physical-copy admission seam for protected installed rows.
//!
//! The bounded segment visitor and its witnesses precede this ledger. Until
//! equality proof exists, this entrypoint never grants copy admission.

use super::authority::CATALOG_CF;
use super::codec::{CatalogKey, CatalogValue};
use super::segment_witness::{
    CopyReplayWork, ExpectedLiteralPut, ObservedSegmentRow, ObservedSegmentValue, PhysicalRowClass,
    PhysicalRowLocator, ProtectedRole, ProtectedSegmentCandidate, SegmentFileWitness,
    SegmentSource, collect_protected_segment_candidate, recheck_all_copy_replay_witnesses,
    with_authenticated_literal_put,
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
const COPY_COMPARE_CHUNK_BYTES: usize = 64 * 1024;
const CATALOG_HEAD_LITERAL_BYTES: usize = 48;
const RECORD_ALLOCATOR_LITERAL_BYTES: usize = 56;

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

fn unproven_copy_group() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "protected physical-copy role group provenance awaits proof",
    }
}

fn unproven_index_head_group() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "record-index Head physical group provenance awaits compaction proof",
    }
}

fn unproven_external_copy() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "external protected physical-copy bytes await value replay",
    }
}

fn literal_buffer_limit() -> PraxisError {
    PraxisError::UnsupportedCatalogFeature {
        feature: "literal physical-copy comparison buffer exceeds proof profile",
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

/// This slice knows only two roles whose protocol has one logical Put per
/// sequence. In particular, a record-index Head may contain several ordered
/// Puts at one sequence, and compaction can shrink that source group.
fn singleton_literal_width(root: &Path, descriptor: &CopyDescriptor) -> Result<usize> {
    if descriptor.cf == CATALOG_CF {
        return match CatalogKey::decode(&descriptor.key, root)? {
            CatalogKey::Head => Ok(CATALOG_HEAD_LITERAL_BYTES),
            _ => Err(unproven_copy_group()),
        };
    }
    let role = RecordRole::from_cf(&descriptor.cf)
        .ok_or_else(|| corrupt(root, "copy descriptor lacks a protected role"))?;
    match RecordKey::decode(role, &descriptor.key, root)? {
        RecordKey::Allocator => Ok(RECORD_ALLOCATOR_LITERAL_BYTES),
        RecordKey::Head { .. } => Err(unproven_index_head_group()),
        _ => Err(unproven_copy_group()),
    }
}

fn witnessed_source<'a>(
    root: &Path,
    witnesses: &'a [SegmentFileWitness],
    descriptor: &CopyDescriptor,
) -> Result<&'a SegmentFileWitness> {
    let index = witnesses
        .binary_search_by_key(
            &(descriptor.source.level, descriptor.source.id),
            |witness| (witness.source.level, witness.source.id),
        )
        .map_err(|_| corrupt(root, "copy row source has no replay witness"))?;
    let witness = &witnesses[index];
    if witness.source != descriptor.source {
        return Err(corrupt(root, "copy row source differs from replay witness"));
    }
    Ok(witness)
}

/// The shared budget debit outlives both selected-row callbacks. Unwinding
/// drops its allocated bytes before the exact refund, like the source capture.
struct LiteralComparisonBuffer<'a> {
    bytes: Vec<u8>,
    budget: &'a mut PhysicalWitnessBudget,
    root: &'a Path,
    charge: usize,
}

impl<'a> LiteralComparisonBuffer<'a> {
    fn new(
        root: &'a Path,
        budget: &'a mut PhysicalWitnessBudget,
        work: &mut CopyReplayWork,
        width: usize,
    ) -> Result<Self> {
        let charge = width
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or_else(literal_buffer_limit)?;
        work.reserve_literal_comparison_buffer(charge)?;
        if charge > budget.remaining_bytes() {
            return Err(literal_buffer_limit());
        }
        budget.charge(root, charge)?;
        Ok(Self {
            bytes: Vec::new(),
            budget,
            root,
            charge,
        })
    }
}

impl Drop for LiteralComparisonBuffer<'_> {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.bytes));
        if self.budget.release(self.root, self.charge).is_err() {
            std::process::abort();
        }
    }
}

fn exact_literal_bytes_equal(canonical: &[u8], other: &[u8]) -> bool {
    canonical.len() == other.len()
        && canonical
            .chunks(COPY_COMPARE_CHUNK_BYTES)
            .zip(other.chunks(COPY_COMPARE_CHUNK_BYTES))
            .all(|(left, right)| left == right)
}

fn replay_literal_copy_groups(
    root: &Path,
    manifest: &Manifest,
    segment: &ProtectedSegmentCandidate,
    descriptors: &[CopyDescriptor],
    groups: &[CopyTripleGroup],
    budget: &mut PhysicalWitnessBudget,
    work: &mut CopyReplayWork,
) -> Result<()> {
    for group in groups {
        let copies = &descriptors[group.start..group.end];
        if copies.len() < 2 {
            continue;
        }
        let width = singleton_literal_width(root, &copies[0])?;
        if copies
            .iter()
            .any(|copy| matches!(copy.operation, CopyWireOperation::Pointer { .. }))
        {
            return Err(unproven_external_copy());
        }
        if copies.iter().any(
            |copy| !matches!(copy.operation, CopyWireOperation::Put { len } if len == width as u64),
        ) {
            return Err(corrupt(
                root,
                "singleton protected copy has conflicting wire operation or length",
            ));
        }
        let mut canonical = LiteralComparisonBuffer::new(root, budget, work, width)?;
        let first = &copies[0];
        let first_witness = witnessed_source(root, &segment.witnesses, first)?;
        let charge = canonical.charge;
        let bytes = &mut canonical.bytes;
        let replay_budget = &mut *canonical.budget;
        with_authenticated_literal_put(
            root,
            manifest,
            first_witness,
            PhysicalRowLocator {
                source: first.source,
                block_offset: first.block_offset,
                row_ordinal: first.row_ordinal,
            },
            ExpectedLiteralPut {
                cf: &first.cf,
                key: &first.key,
                sequence: first.sequence,
            },
            work,
            replay_budget,
            |actual| {
                if actual.len() != width {
                    return Err(corrupt(
                        root,
                        "singleton protected copy has invalid replay length",
                    ));
                }
                bytes
                    .try_reserve_exact(width)
                    .map_err(|_| literal_buffer_limit())?;
                if bytes.capacity() > charge {
                    return Err(literal_buffer_limit());
                }
                bytes.extend_from_slice(actual);
                Ok(())
            },
        )?;
        for copy in &copies[1..] {
            let witness = witnessed_source(root, &segment.witnesses, copy)?;
            let expected = &canonical.bytes;
            let replay_budget = &mut *canonical.budget;
            with_authenticated_literal_put(
                root,
                manifest,
                witness,
                PhysicalRowLocator {
                    source: copy.source,
                    block_offset: copy.block_offset,
                    row_ordinal: copy.row_ordinal,
                },
                ExpectedLiteralPut {
                    cf: &copy.cf,
                    key: &copy.key,
                    sequence: copy.sequence,
                },
                work,
                replay_budget,
                |actual| {
                    if !exact_literal_bytes_equal(expected, actual) {
                        return Err(corrupt(
                            root,
                            "protected physical-copy actual bytes conflict",
                        ));
                    }
                    Ok(())
                },
            )?;
        }
        drop(canonical);
    }
    // Selected-row callbacks are provisional until every retained source is
    // rebound to its MANIFEST identity and full digest at one complete fence.
    let fence = recheck_all_copy_replay_witnesses(root, manifest, &segment.witnesses, work)?;
    if !fence.confirms(&segment.witnesses) {
        return Err(corrupt(root, "complete copy replay witness set changed"));
    }
    Ok(())
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
    let mut replay_work = CopyReplayWork::production();
    let replay = replay_literal_copy_groups(
        root,
        manifest,
        attempt.segment.as_ref().expect("segment receipt exists"),
        &attempt.descriptors,
        &attempt.groups,
        &mut *attempt.budget,
        &mut replay_work,
    );
    if let Err(error) = replay {
        return attempt.fail(error);
    }
    // This slice validates only fixed singleton literal copies. No private
    // candidate can be returned until all other groups and logical value
    // forms have a complete proof and consumption-boundary recheck.
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

#[cfg(test)]
mod literal_comparison_tests {
    use super::*;
    use crate::accel::cpu::scalar::CpuAccelerator;
    use crate::config::Compression;
    use crate::core_catalog::physical::inspect_v4_owner;
    use crate::core_catalog::physical_tests::flushed_create_fixture;
    use crate::disk::DiskLayout;
    use crate::manifest::ManifestStore;
    use crate::segments::codec::decode_segment;
    use crate::segments::{SegmentWriteOptions, SegmentWriter};
    use crate::types::StoredValue;
    use crate::values::ValueLog;
    use crate::wal::catalog_witness::{WalCut, scan_v4_wals_with_budget};
    use std::fs;

    #[derive(Clone, Copy)]
    enum Case {
        IdenticalAllocator,
        ConflictingHead,
    }

    fn exercise(case: Case) {
        let (_dir, config, lease) = flushed_create_fixture();
        let root = lease.root();
        let layout = DiskLayout::at(root);
        let manifest_path = layout.manifest_path();
        let mut manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        let first_path = layout.segment_path(0, 1);
        let original_file = fs::read(&first_path).unwrap();
        let original_segment =
            decode_segment(&original_file, &first_path, &CpuAccelerator).unwrap();
        let (cf, key, sequence) = match case {
            Case::IdenticalAllocator => (RecordRole::Meta.cf(), &[1_u8][..], 1),
            Case::ConflictingHead => (CATALOG_CF, &[0_u8][..], 2),
        };
        let mut duplicate = original_segment
            .blocks
            .iter()
            .flatten()
            .find(|row| {
                row.entry.cf.0 == cf
                    && row.entry.key.as_ref() == key
                    && row.entry.version.sequence == sequence
            })
            .unwrap()
            .entry
            .clone();
        if matches!(case, Case::ConflictingHead) {
            let StoredValue::Put(original_bytes) = &duplicate.version.value else {
                panic!("writer Head must be a literal Put")
            };
            let CatalogValue::Head(mut head) =
                CatalogValue::decode(&CatalogKey::Head, original_bytes, &first_path).unwrap()
            else {
                panic!("writer Head must decode")
            };
            head.collection_count += 1;
            let changed = CatalogValue::Head(head).encode().unwrap();
            assert_eq!(changed.len(), original_bytes.len());
            assert_ne!(changed, *original_bytes);
            duplicate.version.value = StoredValue::Put(changed);
        }

        let second_path = layout.segment_path(1, 2);
        fs::create_dir_all(second_path.parent().unwrap()).unwrap();
        let value_path = layout.value_log_path(2);
        let mut value_log = ValueLog::open(&value_path).unwrap();
        let second_meta = SegmentWriter::write(
            SegmentWriteOptions {
                path: &second_path,
                id: 2,
                level: 1,
                compression: Compression::None,
                accelerator: &CpuAccelerator,
                value_log: &mut value_log,
                large_value_threshold: config.large_value_threshold,
                block_size: config.block_size,
                partitioned_bloom: None,
                direct_io: false,
            },
            vec![duplicate],
        )
        .unwrap();
        drop(value_log);
        fs::remove_file(value_path).unwrap();
        manifest.segments.push(second_meta);
        manifest.next_segment_id = 3;
        ManifestStore::new(manifest_path.clone())
            .save(&manifest)
            .unwrap();
        let manifest =
            Manifest::decode(&fs::read(&manifest_path).unwrap(), &manifest_path).unwrap();
        let before = [
            fs::read(&first_path).unwrap(),
            fs::read(&second_path).unwrap(),
            fs::read(&manifest_path).unwrap(),
        ];
        assert!(matches!(
            inspect_v4_owner(&lease, &config, &CpuAccelerator),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ));

        let cut = WalCut {
            flushed_sequence: manifest.flushed_sequence,
            last_sequence: manifest.last_sequence,
            flushed_wal_id: manifest.flushed_wal_id,
            active_wal_id: manifest.active_wal_id,
            next_wal_id: manifest.next_wal_id,
        };
        let (_wal_witnesses, mut budget) =
            scan_v4_wals_with_budget(root, cut, |_, _, _, _| Ok(())).unwrap();
        let balance = budget.remaining_bytes();
        match (
            case,
            collect_protected_copy_ledger(root, &manifest, &mut budget),
        ) {
            (
                Case::IdenticalAllocator,
                Err(PraxisError::UnsupportedCatalogFeature {
                    feature: "protected physical-copy bytes await authenticated replay",
                }),
            ) => {}
            (Case::ConflictingHead, Err(PraxisError::Corrupt { reason, .. })) => {
                assert!(
                    reason.contains("actual bytes conflict"),
                    "unexpected refusal: {reason}"
                );
            }
            (_, other) => panic!("unexpected private literal-comparison result: {other:?}"),
        }
        assert_eq!(budget.remaining_bytes(), balance, "exact witness refund");
        assert_eq!(fs::read(&first_path).unwrap(), before[0]);
        assert_eq!(fs::read(&second_path).unwrap(), before[1]);
        assert_eq!(fs::read(&manifest_path).unwrap(), before[2]);
        assert!(matches!(
            inspect_v4_owner(&lease, &config, &CpuAccelerator),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "v4 installed cut beyond narrow D0 bootstrap"
            })
        ));
    }

    #[test]
    fn writer_identical_allocator_replays_actual_bytes_but_stays_private() {
        exercise(Case::IdenticalAllocator);
    }

    #[test]
    fn writer_rechecksummed_head_conflict_refunds_after_actual_byte_compare() {
        exercise(Case::ConflictingHead);
    }

    #[test]
    fn record_index_head_group_waits_for_compaction_provenance() {
        let key = RecordKey::Head {
            index: 1,
            incarnation: 1,
            key: b"test",
        }
        .encode()
        .unwrap();
        let descriptor = CopyDescriptor {
            cf: RecordRole::Index.cf().into(),
            key,
            sequence: 2,
            source: SegmentSource {
                level: 0,
                id: 1,
                manifest_ordinal: 0,
            },
            block_offset: 21,
            row_ordinal: 0,
            operation: CopyWireOperation::Put { len: 40 },
        };
        assert!(matches!(
            singleton_literal_width(Path::new("copy-test"), &descriptor),
            Err(PraxisError::UnsupportedCatalogFeature {
                feature: "record-index Head physical group provenance awaits compaction proof"
            })
        ));
    }
}
