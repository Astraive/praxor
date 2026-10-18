//! Read-only evidence proof before any writable recovery action.
use super::codec::{Allocator, Decision, Key, Role, Row};
use super::schema::{RESERVED_PREFIX, corrupt};
use super::transition::{self, Context, Rows, Summary};
use crate::errors::{PraxisError, Result};
use crate::manifest::Manifest;
use crate::segments::codec::RawEntry;
use crate::transactions::BatchOp;
use crate::types::{StoredValue, ValuePointer};
use crate::wal::record::CoreWalRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

type RetainedHistory = Vec<(u64, Option<Summary>)>;

#[derive(Default)]
struct PrimaryEvidence {
    payload: Option<(u64, [u8; 32])>,
    live_length: Option<u64>,
    latest_live_sequence: Option<u64>,
    earliest_dead_sequence: Option<u64>,
    birth_sequence: Option<u64>,
    earliest_reference_sequence: Option<u64>,
    earliest_observation_sequence: Option<u64>,
}

impl PrimaryEvidence {
    fn observe_birth(&mut self, sequence: u64, source: &Path) -> Result<()> {
        if self.birth_sequence.is_some_and(|birth| birth != sequence)
            || self
                .earliest_reference_sequence
                .is_some_and(|reference| reference < sequence)
        {
            return Err(corrupt(source, "available fresh birth evidence disagrees"));
        }
        self.birth_sequence = Some(sequence);
        self.observe(sequence, true, source)
    }

    fn observe_reference(&mut self, sequence: u64, source: &Path) -> Result<()> {
        if self.birth_sequence.is_some_and(|birth| sequence < birth) {
            return Err(corrupt(source, "mapping Put precedes available RID birth"));
        }
        self.earliest_reference_sequence = Some(
            self.earliest_reference_sequence
                .map_or(sequence, |old| old.min(sequence)),
        );
        self.observe(sequence, true, source)
    }

    fn observe(&mut self, sequence: u64, live: bool, source: &Path) -> Result<()> {
        self.earliest_observation_sequence = Some(
            self.earliest_observation_sequence
                .map_or(sequence, |old| old.min(sequence)),
        );
        if live {
            self.latest_live_sequence = Some(
                self.latest_live_sequence
                    .map_or(sequence, |old| old.max(sequence)),
            );
        } else {
            self.earliest_dead_sequence = Some(
                self.earliest_dead_sequence
                    .map_or(sequence, |old| old.min(sequence)),
            );
        }
        if let (Some(live), Some(dead)) = (self.latest_live_sequence, self.earliest_dead_sequence)
            && live >= dead
        {
            return Err(corrupt(
                source,
                "available live primary evidence does not precede permanent death",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FactEvidence {
    sequence: u64,
    raw_sequence: u64,
    ordinal: u64,
    decision: Decision,
}

/// Temporary proof metadata, bounded by actual retained rows/operations. It
/// neither invents missing cuts nor stores primary bodies or a durable journal.
#[derive(Default)]
struct Relationships {
    allocators: BTreeMap<u64, Allocator>,
    facts: BTreeMap<Vec<u8>, FactEvidence>,
    // Key is the referenced Fact key plus the Head's actual core sequence.
    // Distinct intermediate Heads at one S retain their distinct raw keys.
    heads: BTreeMap<(Vec<u8>, u64), (u64, Decision)>,
}

impl Relationships {
    fn allocator(&mut self, sequence: u64, value: Allocator, source: &Path) -> Result<()> {
        if self
            .allocators
            .get(&sequence)
            .is_some_and(|old| *old != value)
        {
            return Err(corrupt(source, "same-commit allocator evidence disagrees"));
        }
        self.allocators.insert(sequence, value);
        Ok(())
    }

    fn projection(
        &mut self,
        encoded: &[u8],
        sequence: u64,
        bytes: &[u8],
        source: &Path,
    ) -> Result<()> {
        let key = Key::decode(Role::Index, encoded, source)?;
        match (&key, Row::decode(&key, bytes, source)?) {
            (
                Key::Fact { raw_sequence, .. },
                Row::Fact {
                    append_ordinal,
                    decision,
                },
            ) => {
                let value = FactEvidence {
                    sequence,
                    raw_sequence: *raw_sequence,
                    ordinal: append_ordinal,
                    decision,
                };
                if self.facts.get(encoded).is_some_and(|old| *old != value) {
                    return Err(corrupt(
                        source,
                        "immutable Fact evidence differs in value or core sequence",
                    ));
                }
                self.facts.insert(encoded.to_vec(), value);
            }
            (
                Key::Head {
                    index,
                    incarnation,
                    key,
                },
                Row::Head {
                    raw_sequence,
                    append_ordinal,
                    decision,
                },
            ) => {
                let fact = Key::Fact {
                    index: *index,
                    incarnation: *incarnation,
                    key,
                    raw_sequence,
                }
                .encode()?;
                let value = (append_ordinal, decision);
                let key = (fact, sequence);
                if self.heads.get(&key).is_some_and(|old| *old != value) {
                    return Err(corrupt(
                        source,
                        "Head copies disagree for the same Fact and core sequence",
                    ));
                }
                self.heads.insert(key, value);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn validate(&self, primary: &BTreeMap<u64, PrimaryEvidence>, source: &Path) -> Result<()> {
        let mut previous: Option<Allocator> = None;
        for value in self.allocators.values() {
            if previous.is_some_and(|old| {
                value.last_rid < old.last_rid
                    || value.dead_count < old.dead_count
                    || value.compatibility_sequence <= old.compatibility_sequence
                    || value.append_ordinal <= old.append_ordinal
            }) {
                return Err(corrupt(source, "available allocator cuts move backwards"));
            }
            previous = Some(*value);
        }
        for ((key, sequence), (ordinal, decision)) in &self.heads {
            let Some(fact) = self.facts.get(key) else {
                return Err(corrupt(source, "retained Head has no immutable Fact"));
            };
            if fact.sequence != *sequence || fact.ordinal != *ordinal || fact.decision != *decision
            {
                return Err(corrupt(
                    source,
                    "retained Head differs from its Fact value or core sequence",
                ));
            }
        }
        let mut previous_birth = None;
        for (rid, evidence) in primary {
            if let Some(sequence) = evidence.earliest_observation_sequence
                && self
                    .allocators
                    .range(sequence..)
                    .next()
                    .is_some_and(|(_, cut)| cut.last_rid < *rid)
            {
                return Err(corrupt(
                    source,
                    "available RID event exceeds a later allocation cut",
                ));
            }
            if let Some(birth) = evidence.birth_sequence {
                if previous_birth.is_some_and(|previous| previous > birth)
                    || self
                        .allocators
                        .range(..birth)
                        .next_back()
                        .is_some_and(|(_, cut)| cut.last_rid >= *rid)
                {
                    return Err(corrupt(
                        source,
                        "known birth contradicts RID order or an earlier allocation cut",
                    ));
                }
                previous_birth = Some(birth);
            }
        }
        let mut intervals = BTreeMap::<u64, (u64, u64)>::new();
        for fact in self.facts.values() {
            if self
                .allocators
                .range(..fact.sequence)
                .next_back()
                .is_some_and(|(_, cut)| cut.compatibility_sequence >= fact.raw_sequence)
                || self
                    .allocators
                    .range(fact.sequence..)
                    .next()
                    .is_some_and(|(_, cut)| cut.compatibility_sequence < fact.raw_sequence)
            {
                return Err(corrupt(
                    source,
                    "Fact raw position contradicts an available allocator cut",
                ));
            }
            let interval = intervals
                .entry(fact.sequence)
                .or_insert((fact.raw_sequence, fact.raw_sequence));
            interval.0 = interval.0.min(fact.raw_sequence);
            interval.1 = interval.1.max(fact.raw_sequence);
        }
        let mut previous_raw = None;
        for (minimum, maximum) in intervals.values() {
            if previous_raw.is_some_and(|old| old >= *minimum) {
                return Err(corrupt(
                    source,
                    "Fact event intervals reverse fresh append order",
                ));
            }
            previous_raw = Some(*maximum);
        }
        Ok(())
    }
}

/// An available death covered by C cannot be hidden by pruning its State
/// version or by a later suffix delete. Check the installed C state itself.
fn check_installed_death(
    rid: u64,
    evidence: &PrimaryEvidence,
    flushed_sequence: u64,
    rows: &Rows,
    source: &Path,
) -> Result<()> {
    if evidence
        .earliest_dead_sequence
        .is_none_or(|dead| dead > flushed_sequence)
    {
        return Ok(());
    }
    let key = Key::State(rid);
    let Some(Some(Summary::Bytes(bytes))) = rows.get(&(Role::State, key.encode()?)) else {
        return Err(corrupt(source, "known dead RID has no installed state"));
    };
    if !matches!(
        Row::decode(&key, bytes, source)?,
        Row::State { live: false, .. }
    ) {
        return Err(corrupt(source, "known dead RID is live in installed state"));
    }
    Ok(())
}

/// Correlate only available evidence. Dead current rows do not erase an older
/// immutable body witness, and absent history is never fabricated or required.
fn remember_primary(
    evidence: &mut BTreeMap<u64, PrimaryEvidence>,
    role: Role,
    key: &[u8],
    sequence: u64,
    value: Option<&Summary>,
    source: &Path,
) -> Result<()> {
    if !matches!(role, Role::Payload | Role::State | Role::Index) {
        return Ok(());
    }
    let key = Key::decode(role, key, source)?;
    match (&key, value) {
        (Key::Payload(rid), None) => {
            evidence
                .entry(*rid)
                .or_default()
                .observe(sequence, false, source)?;
        }
        (Key::Payload(rid), Some(Summary::Payload { len, digest })) => {
            let known = evidence.entry(*rid).or_default();
            known.observe_birth(sequence, source)?;
            if known.payload.is_some_and(|old| old != (*len, *digest))
                || known.live_length.is_some_and(|old| old != *len)
            {
                return Err(corrupt(
                    source,
                    "available immutable payload/state evidence disagrees",
                ));
            }
            known.payload = Some((*len, *digest));
        }
        (Key::State(rid), Some(Summary::Bytes(bytes))) => {
            let Row::State {
                live,
                payload_length,
            } = Row::decode(&key, bytes, source)?
            else {
                unreachable!()
            };
            let known = evidence.entry(*rid).or_default();
            if live {
                known.observe_birth(sequence, source)?;
                if known.live_length.is_some_and(|old| old != payload_length)
                    || known.payload.is_some_and(|(len, _)| len != payload_length)
                {
                    return Err(corrupt(
                        source,
                        "available live state length differs from immutable payload",
                    ));
                }
                known.live_length = Some(payload_length);
            } else {
                known.observe(sequence, false, source)?;
            }
        }
        (Key::Fact { .. }, Some(Summary::Bytes(bytes))) => {
            if let Row::Fact {
                decision: Decision::Put(rid),
                ..
            } = Row::decode(&key, bytes, source)?
            {
                evidence
                    .entry(rid)
                    .or_default()
                    .observe_reference(sequence, source)?;
            }
        }
        (Key::Head { .. }, _) => {}
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) struct Evidence {
    source: PathBuf,
    authority: Option<([u8; 16], u32)>,
    flushed_sequence: u64,
    versions: BTreeMap<(Role, Vec<u8>), BTreeMap<u64, Option<Summary>>>,
    segment_seen: BTreeSet<(Role, Vec<u8>, u64)>,
    monotonic: BTreeMap<(Role, Vec<u8>), RetainedHistory>,
    rows: Option<Rows>,
    previous_wal_sequence: Option<u64>,
    previous_record: Option<Allocator>,
    record_chain_complete: bool,
    primary: BTreeMap<u64, PrimaryEvidence>,
    relationships: Relationships,
}

impl Evidence {
    pub(crate) fn new(manifest: &Manifest, source: &Path) -> Result<Self> {
        let authority = manifest
            .record_authority
            .as_ref()
            .map(|a| a.identity(source).map(|id| (id, a.index_descriptor_count)))
            .transpose()?;
        Ok(Self {
            source: source.into(),
            authority,
            flushed_sequence: manifest.flushed_sequence,
            versions: BTreeMap::new(),
            segment_seen: BTreeSet::new(),
            monotonic: BTreeMap::new(),
            rows: None,
            previous_wal_sequence: None,
            previous_record: None,
            record_chain_complete: false,
            primary: BTreeMap::new(),
            relationships: Relationships::default(),
        })
    }

    /// Same-(key,sequence) complete source groups replace older source groups;
    /// operations inside the selected source group retain input order.
    pub(crate) fn begin_segment(&mut self) {
        self.segment_seen.clear();
    }

    pub(crate) fn segment(
        &mut self,
        raw: &RawEntry,
        mut read_blob: impl FnMut(&ValuePointer) -> Result<Vec<u8>>,
    ) -> Result<()> {
        if self.authority.is_none() {
            return Ok(());
        }
        if self.rows.is_some() {
            return Err(corrupt(
                &self.source,
                "segment arrived after authority WAL validation",
            ));
        }
        let entry = &raw.entry;
        let seq = entry.version.sequence;
        if seq > self.flushed_sequence {
            return Err(corrupt(
                &self.source,
                "segment row exceeds installed flush cutoff",
            ));
        }
        let Some(role) = Role::from_cf(&entry.cf.0) else {
            if entry.cf.0.starts_with(RESERVED_PREFIX) {
                return Err(corrupt(&self.source, "segment uses unbound reserved role"));
            }
            if seq <= 1 {
                return Err(corrupt(
                    &self.source,
                    "ordinary segment row precedes/shares bootstrap",
                ));
            }
            return Ok(());
        };
        let key = Key::decode(role, &entry.key, &self.source)?;
        if seq == 0
            || (seq == 1 && role != Role::Meta)
            || (matches!(key, Key::Binding | Key::Descriptor(_)) && seq != 1)
            || raw.blob_expiry.is_some()
        {
            return Err(corrupt(
                &self.source,
                "protected segment sequence/expiration mismatch",
            ));
        }
        let value = match &entry.version.value {
            StoredValue::Put(bytes) => {
                Some(Summary::decode(role, &entry.key, bytes, &self.source)?)
            }
            StoredValue::BlobPointer(pointer) => Some(Summary::decode(
                role,
                &entry.key,
                &read_blob(pointer)?,
                &self.source,
            )?),
            StoredValue::Delete if matches!(key, Key::Payload(_)) => None,
            _ => {
                return Err(corrupt(
                    &self.source,
                    "protected segment has forbidden operation",
                ));
            }
        };
        if matches!(key, Key::Allocator) {
            let Some(Summary::Bytes(bytes)) = &value else {
                unreachable!()
            };
            let Row::Allocator(allocator) = Row::decode(&key, bytes, &self.source)? else {
                unreachable!()
            };
            self.relationships.allocator(seq, allocator, &self.source)?;
            if (seq == 1 && allocator != Allocator::default())
                || (seq > 1 && allocator.compatibility_sequence == 0)
            {
                return Err(corrupt(
                    &self.source,
                    "allocator version violates bootstrap/transition sequence",
                ));
            }
        }
        if role == Role::Index {
            let Some(Summary::Bytes(bytes)) = &value else {
                unreachable!()
            };
            self.relationships
                .projection(&entry.key, seq, bytes, &self.source)?;
        }
        let row_key = (role, entry.key.to_vec());
        remember_primary(
            &mut self.primary,
            role,
            &entry.key,
            seq,
            value.as_ref(),
            &self.source,
        )?;
        if matches!(key, Key::Allocator | Key::State(_) | Key::Payload(_)) {
            self.monotonic
                .entry(row_key.clone())
                .or_default()
                .push((seq, value.clone()));
        }
        let chain = self.versions.entry(row_key.clone()).or_default();
        if matches!(role, Role::State | Role::Payload)
            && chain.get(&seq).is_some_and(|old| old != &value)
        {
            return Err(corrupt(
                &self.source,
                "same-sequence primary source groups disagree",
            ));
        }
        if matches!(key, Key::Binding | Key::Descriptor(_))
            && chain.values().any(|old| old != &value)
        {
            return Err(corrupt(
                &self.source,
                "immutable metadata differs across segment versions",
            ));
        }
        if matches!(key, Key::Fact { .. })
            && chain
                .iter()
                .any(|(old_seq, old)| *old_seq != seq || old != &value)
        {
            return Err(corrupt(
                &self.source,
                "immutable mapping fact was rewritten",
            ));
        }
        if self.segment_seen.insert((role, entry.key.to_vec(), seq)) {
            chain.remove(&seq);
        }
        chain.insert(seq, value);
        Ok(())
    }

    fn installed(&mut self) -> Result<()> {
        if self.rows.is_some() {
            return Ok(());
        }
        let rows = self
            .versions
            .iter()
            .filter_map(|(key, chain)| {
                chain
                    .last_key_value()
                    .map(|(_, value)| (key.clone(), value.clone()))
            })
            .collect::<Rows>();
        if let Some((id, descriptors)) = self.authority
            && self.flushed_sequence > 0
        {
            let context = Context {
                id,
                descriptors,
                source: &self.source,
            };
            let allocator = transition::validate_installed(&rows, &context)?;
            for (rid, evidence) in &self.primary {
                check_installed_death(*rid, evidence, self.flushed_sequence, &rows, &self.source)?;
            }
            for ((role, key), versions) in &self.versions {
                for value in versions.values() {
                    transition::check_summary(*role, key, value.as_ref(), allocator, &context)?;
                }
            }
            for ((role, key), history) in &mut self.monotonic {
                history.sort_by_key(|(sequence, _)| *sequence);
                let mut dead = false;
                let mut first_payload: Option<&Summary> = None;
                let mut live_length = None;
                let mut prior_allocator: Option<(u64, Allocator)> = None;
                for (sequence, value) in history {
                    transition::check_summary(*role, key, value.as_ref(), allocator, &context)?;
                    match Key::decode(*role, key, &self.source)? {
                        Key::Payload(_) => match value {
                            None => dead = true,
                            Some(summary) => {
                                if dead || first_payload.is_some_and(|old| old != summary) {
                                    return Err(corrupt(
                                        &self.source,
                                        "retained payload changed or reappeared after tombstone",
                                    ));
                                }
                                first_payload = Some(summary);
                            }
                        },
                        Key::State(_) => {
                            let Some(Summary::Bytes(bytes)) = value else {
                                unreachable!()
                            };
                            let Row::State {
                                live,
                                payload_length,
                            } = Row::decode(
                                &Key::decode(*role, key, &self.source)?,
                                bytes,
                                &self.source,
                            )?
                            else {
                                unreachable!()
                            };
                            if live {
                                if dead || live_length.is_some_and(|len| len != payload_length) {
                                    return Err(corrupt(
                                        &self.source,
                                        "retained state resurrected RID or changed payload length",
                                    ));
                                }
                                live_length = Some(payload_length);
                            } else {
                                dead = true;
                            }
                        }
                        Key::Allocator => {
                            let Some(Summary::Bytes(bytes)) = value else {
                                unreachable!()
                            };
                            let Row::Allocator(next) =
                                Row::decode(&Key::Allocator, bytes, &self.source)?
                            else {
                                unreachable!()
                            };
                            if prior_allocator.is_some_and(|(old_sequence, old)| {
                                if old_sequence == *sequence {
                                    old != next
                                } else {
                                    next.last_rid < old.last_rid
                                        || next.dead_count < old.dead_count
                                        || next.compatibility_sequence <= old.compatibility_sequence
                                        || next.append_ordinal <= old.append_ordinal
                                }
                            }) {
                                return Err(corrupt(
                                    &self.source,
                                    "retained allocator versions move backwards or disagree at one sequence",
                                ));
                            }
                            prior_allocator = Some((*sequence, next));
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        self.rows = Some(rows);
        Ok(())
    }

    pub(crate) fn wal(&mut self, record: &CoreWalRecord) -> Result<()> {
        if matches!(record, CoreWalRecord::Catalog { .. }) {
            return Err(PraxisError::CatalogAuthorityWalRequired {
                path: self.source.clone(),
            });
        }
        if self.authority.is_some() {
            let sequence = record.sequence();
            if sequence == 0
                || self
                    .previous_wal_sequence
                    .is_some_and(|old| sequence <= old)
            {
                return Err(corrupt(
                    &self.source,
                    "authority WAL sequences are not strictly ordered",
                ));
            }
            if self
                .previous_wal_sequence
                .is_some_and(|old| old.checked_add(1) != Some(sequence))
            {
                self.record_chain_complete = false;
            }
            self.previous_wal_sequence = Some(sequence);
            self.installed()?;
        }
        match (self.authority, record) {
            (_, CoreWalRecord::Catalog { .. }) => Err(PraxisError::CatalogAuthorityWalRequired {
                path: self.source.clone(),
            }),
            (None, CoreWalRecord::User(_)) => Ok(()),
            (None, CoreWalRecord::Record { .. }) => Err(PraxisError::RecordAuthorityWalRequired {
                path: self.source.clone(),
            }),
            (Some(_), CoreWalRecord::User(record)) => {
                if record.sequence <= 1
                    || record.batch.ops().iter().any(|op| {
                        let cf = match op {
                            BatchOp::Put { cf, .. }
                            | BatchOp::Delete { cf, .. }
                            | BatchOp::Merge { cf, .. }
                            | BatchOp::PutWithExpiry { cf, .. } => cf,
                        };
                        cf.0.starts_with(RESERVED_PREFIX)
                    })
                {
                    return Err(corrupt(
                        &self.source,
                        "ordinary WAL request accesses protected authority",
                    ));
                }
                Ok(())
            }
            (
                Some((id, descriptors)),
                CoreWalRecord::Record {
                    sequence,
                    envelope,
                    batch,
                },
            ) => {
                let context = Context {
                    id,
                    descriptors,
                    source: &self.source,
                };
                let rows = self.rows.as_mut().expect("installed above");
                let updates = if *sequence > self.flushed_sequence && *sequence != 1 {
                    let mut read =
                        |role, key: &[u8]| Ok(rows.get(&(role, key.to_vec())).cloned().flatten());
                    transition::validate(*sequence, envelope, batch, &context, Some(&mut read))?
                } else {
                    transition::validate(*sequence, envelope, batch, &context, None)?
                };
                let Some(Some(Summary::Bytes(bytes))) = updates.get(&(Role::Meta, vec![1])) else {
                    unreachable!()
                };
                let Row::Allocator(next) = Row::decode(&Key::Allocator, bytes, &self.source)?
                else {
                    unreachable!()
                };
                self.relationships
                    .allocator(*sequence, next, &self.source)?;
                // Validate/retain every actual Head, including intermediate
                // puts that the final per-key update map intentionally folds.
                for op in batch.ops() {
                    if let BatchOp::Put { cf, key, value } = op
                        && cf.0 == Role::Index.cf()
                    {
                        self.relationships
                            .projection(key, *sequence, value, &self.source)?;
                    }
                }
                if let Some(previous) = self.previous_record {
                    let prior = (
                        envelope.prior_rid,
                        envelope.prior_compatibility_sequence,
                        envelope.prior_append_ordinal,
                    );
                    let floor = (
                        previous.last_rid,
                        previous.compatibility_sequence,
                        previous.append_ordinal,
                    );
                    if prior.0 < floor.0
                        || prior.1 < floor.1
                        || prior.2 < floor.2
                        || (self.record_chain_complete && prior != floor)
                        || next.dead_count < previous.dead_count
                    {
                        return Err(corrupt(
                            &self.source,
                            "retained typed WAL counters decrease or skip a complete chain",
                        ));
                    }
                }
                if *sequence <= self.flushed_sequence {
                    let Some(Some(Summary::Bytes(bytes))) = rows.get(&(Role::Meta, vec![1])) else {
                        unreachable!()
                    };
                    let Row::Allocator(installed) =
                        Row::decode(&Key::Allocator, bytes, &self.source)?
                    else {
                        unreachable!()
                    };
                    for ((role, key), summary) in &updates {
                        // Monotone upper bounds, never equality with latest priors
                        // and never a current-liveness requirement for old RIDs.
                        transition::check_summary(
                            *role,
                            key,
                            summary.as_ref(),
                            installed,
                            &context,
                        )?;
                    }
                }
                for ((role, key), value) in &updates {
                    let decoded_key = Key::decode(*role, key, &self.source)?;
                    // A retained version and WAL frame at the same core
                    // sequence describe the very same commit. Compare only
                    // available versions, never a pruned version or today's
                    // row. Head alone may have multiple ordered puts at one S.
                    if matches!(
                        decoded_key,
                        Key::Allocator | Key::State(_) | Key::Payload(_)
                    ) && self
                        .versions
                        .get(&(*role, key.clone()))
                        .and_then(|chain| chain.get(sequence))
                        .is_some_and(|installed| installed != value)
                    {
                        return Err(corrupt(
                            &self.source,
                            "same-commit WAL and installed version disagree",
                        ));
                    }
                    remember_primary(
                        &mut self.primary,
                        *role,
                        key,
                        *sequence,
                        value.as_ref(),
                        &self.source,
                    )?;
                    if *sequence <= self.flushed_sequence
                        && let Key::State(rid) | Key::Payload(rid) = decoded_key
                    {
                        check_installed_death(
                            rid,
                            &self.primary[&rid],
                            self.flushed_sequence,
                            rows,
                            &self.source,
                        )?;
                    }
                    if matches!(
                        decoded_key,
                        Key::Binding | Key::Descriptor(_) | Key::Fact { .. }
                    ) && rows
                        .get(&(*role, key.clone()))
                        .is_some_and(|old| old != value)
                    {
                        return Err(corrupt(
                            &self.source,
                            "immutable bootstrap metadata was rewritten",
                        ));
                    }
                    if *sequence <= self.flushed_sequence
                        && matches!(decoded_key, Key::Fact { .. })
                        && !rows.contains_key(&(*role, key.clone()))
                    {
                        return Err(corrupt(
                            &self.source,
                            "retained WAL mapping fact is absent from installed state",
                        ));
                    }
                }
                if *sequence > self.flushed_sequence {
                    rows.extend(updates);
                }
                self.previous_record = Some(next);
                self.record_chain_complete = true;
                Ok(())
            }
        }
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        let Some((id, descriptors)) = self.authority else {
            return Ok(());
        };
        self.installed()?;
        transition::validate_installed(
            self.rows.as_ref().unwrap(),
            &Context {
                id,
                descriptors,
                source: &self.source,
            },
        )?;
        self.relationships.validate(&self.primary, &self.source)?;
        Ok(())
    }
}

/// Resolve only a previously validated physical value role. The row's maximum
/// wire size is the existing atomic WAL bound, not an arbitrary diagnostic cap.
pub(crate) fn read_blob_at(pointer: &ValuePointer, physical: &Path) -> Result<Vec<u8>> {
    if pointer.len > crate::wal::record::MAX_WAL_PAYLOAD_BYTES as u64
        || pointer
            .offset
            .checked_add(12)
            .and_then(|end| end.checked_add(pointer.len))
            .is_none_or(|end| std::fs::metadata(physical).map_or(true, |meta| end > meta.len()))
    {
        return Err(corrupt(
            physical,
            "protected value pointer exceeds actual file or atomic row bound",
        ));
    }
    let mut local = pointer.clone();
    local.path = physical.to_string_lossy().into_owned();
    crate::values::ValueLog::read_pointer(&local)
}

/// Validate the complete authority before any reconcile/save/truncate/create.
/// The retained owner lease stabilizes these physical paths throughout this scan.
pub(crate) fn validate_owner(
    root: &Path,
    manifest: &Manifest,
    accelerator: &dyn crate::accel::Accelerator,
) -> Result<Vec<CoreWalRecord>> {
    let source = root.join("MANIFEST");
    let mut evidence = Evidence::new(manifest, &source)?;
    for metadata in &manifest.segments {
        let expected = root
            .join("segments")
            .join(metadata.level.to_string())
            .join(format!("{:020}.tseg", metadata.id));
        if Path::new(&metadata.path) != expected {
            return Err(corrupt(
                &source,
                "protected owner segment label is outside its exact file role",
            ));
        }
        real_file(&expected)?;
        let bytes = std::fs::read(&expected)?;
        if blake3::hash(&bytes).to_hex().as_str() != metadata.file_digest {
            return Err(corrupt(&expected, "segment digest mismatch"));
        }
        let raw = crate::segments::codec::decode_segment(&bytes, &expected, accelerator)?;
        if raw.id != metadata.id
            || raw.level != metadata.level
            || raw
                .blocks
                .iter()
                .map(|block| block.len() as u64)
                .sum::<u64>()
                != metadata.entries
        {
            return Err(corrupt(&expected, "segment identity/count mismatch"));
        }
        evidence.begin_segment();
        for row in raw.blocks.iter().flatten() {
            evidence.segment(row, |pointer| {
                let path = Path::new(&pointer.path);
                let id = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .filter(|stem| {
                        stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .and_then(|stem| stem.parse::<u64>().ok())
                    .filter(|id| *id != 0 && *id < manifest.next_segment_id)
                    .ok_or_else(|| corrupt(path, "invalid protected value role identity"))?;
                let expected = root.join("values").join(format!("{id:020}.tval"));
                if path != expected {
                    return Err(corrupt(
                        path,
                        "protected value label is outside its exact file role",
                    ));
                }
                real_file(&expected)?;
                read_blob_at(pointer, &expected)
            })?;
        }
    }
    let records = read_owner_wals(root, manifest)?;
    for record in &records {
        evidence.wal(record)?;
    }
    evidence.finish()?;
    Ok(records)
}

fn real_file(path: &Path) -> Result<()> {
    let mut current = path;
    loop {
        let metadata = std::fs::symlink_metadata(current)?;
        if metadata.file_type().is_symlink() {
            return Err(corrupt(current, "authority file role contains an alias"));
        }
        if current == path && !metadata.is_file() {
            return Err(corrupt(current, "authority file role is not regular"));
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    Ok(())
}

fn read_owner_wals(root: &Path, manifest: &Manifest) -> Result<Vec<CoreWalRecord>> {
    if manifest.flushed_sequence > manifest.last_sequence
        || manifest.flushed_wal_id >= manifest.active_wal_id
        || manifest.next_wal_id <= manifest.active_wal_id
    {
        return Err(corrupt(root, "invalid record authority WAL cutoffs"));
    }
    let mut paths = BTreeMap::new();
    for entry in std::fs::read_dir(root.join("wal"))? {
        let path = entry?.path();
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                name.len() == 24
                    && name.ends_with(".wal")
                    && name.as_bytes()[..20].iter().all(u8::is_ascii_digit)
            })
            .and_then(|name| name[..20].parse::<u64>().ok())
            .filter(|id| *id != 0 && *id <= manifest.active_wal_id)
            .ok_or_else(|| corrupt(&path, "unexpected authority WAL role"))?;
        real_file(&path)?;
        paths.insert(id, path);
    }
    let mut previous_id = manifest.flushed_wal_id;
    for id in paths.keys().filter(|id| **id > manifest.flushed_wal_id) {
        if previous_id.checked_add(1) != Some(*id) {
            return Err(corrupt(root, "required authority WAL identity is missing"));
        }
        previous_id = *id;
    }
    if previous_id != manifest.active_wal_id {
        return Err(corrupt(root, "active authority WAL is missing"));
    }
    let mut records = Vec::new();
    let mut previous_sequence = None;
    let mut covered = manifest.flushed_sequence;
    for (id, path) in paths {
        let bytes = std::fs::read(&path)?;
        let header = [
            0x5457_4146u32.to_le_bytes().as_slice(),
            1u32.to_le_bytes().as_slice(),
            id.to_le_bytes().as_slice(),
        ]
        .concat();
        if (bytes.len() < 16 && !header.starts_with(&bytes))
            || (bytes.len() >= 16 && bytes[..16] != header)
        {
            return Err(corrupt(&path, "authority WAL header/identity mismatch"));
        }
        let (file_records, end) = crate::wal::writer::replay_core_records(&bytes, &path)?;
        if id != manifest.active_wal_id && (bytes.len() < 16 || end != bytes.len()) {
            return Err(corrupt(&path, "inactive authority WAL is incomplete"));
        }
        for record in file_records {
            let sequence = record.sequence();
            if sequence == 0 || previous_sequence.is_some_and(|previous| sequence <= previous) {
                return Err(corrupt(
                    &path,
                    "authority WAL sequences are not strictly ordered",
                ));
            }
            previous_sequence = Some(sequence);
            if sequence > manifest.flushed_sequence {
                if covered.checked_add(1) != Some(sequence) {
                    return Err(corrupt(
                        &path,
                        "authority WAL committed suffix is incomplete",
                    ));
                }
                covered = sequence;
            }
            records.push(record);
        }
    }
    if covered < manifest.last_sequence {
        return Err(corrupt(
            root,
            "authority WAL is missing persisted committed sequence",
        ));
    }
    Ok(records)
}
