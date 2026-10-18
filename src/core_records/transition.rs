//! Canonical logical transitions shared by the live planner and read-only
//! recovery. Historical frames use self-contained checks; the recovered suffix
//! additionally checks the actual installed prior state.
use super::codec::{Allocator, Decision, Envelope, Key, Kind, Role, Row};
use super::intent::{IntentKind, Mapping, RecordIntent, RecordReceipt, RecordResult};
use super::schema::corrupt;
use crate::errors::{PraxisError, Result};
use crate::store::RecordId;
use crate::transactions::{BatchOp, WriteBatch};
use crate::wal::record::CoreWalRecord;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) type RowKey = (Role, Vec<u8>);
pub(crate) type Rows = BTreeMap<RowKey, Option<Summary>>;
pub(crate) type ReadRow<'a> = dyn FnMut(Role, &[u8]) -> Result<Option<Summary>> + 'a;

/// Payload bytes remain in the canonical core, never a second validation corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Summary {
    Bytes(Vec<u8>),
    Payload { len: u64, digest: [u8; 32] },
}
impl Summary {
    pub(crate) fn decode(role: Role, key: &[u8], bytes: &[u8], source: &Path) -> Result<Self> {
        if bytes.len() > crate::wal::record::MAX_WAL_PAYLOAD_BYTES {
            return Err(corrupt(source, "protected row exceeds atomic wire bound"));
        }
        let key = Key::decode(role, key, source)?;
        Ok(match Row::decode(&key, bytes, source)? {
            Row::Payload(value) => Self::Payload {
                len: value.len() as u64,
                digest: *blake3::hash(value).as_bytes(),
            },
            _ => Self::Bytes(bytes.to_vec()),
        })
    }
    pub(crate) fn bytes(&self, source: &Path) -> Result<&[u8]> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(corrupt(source, "payload used as record metadata")),
        }
    }
}

pub(crate) struct Context<'a> {
    pub(crate) id: [u8; 16],
    pub(crate) descriptors: u32,
    pub(crate) source: &'a Path,
}

pub(crate) struct PlannedRecord {
    pub(crate) record: CoreWalRecord,
    pub(crate) receipt: RecordReceipt,
    pub(crate) updates: Rows,
    pub(crate) encoded_len: usize,
}

fn allocator(read: &mut ReadRow<'_>, source: &Path) -> Result<Allocator> {
    let bytes =
        read(Role::Meta, &[1])?.ok_or_else(|| corrupt(source, "missing record allocator"))?;
    match Row::decode(&Key::Allocator, bytes.bytes(source)?, source)? {
        Row::Allocator(value) => Ok(value),
        _ => unreachable!(),
    }
}

fn state(read: &mut ReadRow<'_>, rid: u64, source: &Path) -> Result<(bool, u64)> {
    if rid == 0 {
        return Err(PraxisError::KeyNotFound);
    }
    let key = Key::State(rid);
    let bytes = read(Role::State, &key.encode()?)?.ok_or(PraxisError::KeyNotFound)?;
    match Row::decode(&key, bytes.bytes(source)?, source)? {
        Row::State {
            live,
            payload_length,
        } => Ok((live, payload_length)),
        _ => unreachable!(),
    }
}

fn add(value: u64, delta: u64) -> Result<u64> {
    value
        .checked_add(delta)
        .ok_or_else(|| PraxisError::WriteStalled {
            reason: "record counter space exhausted".into(),
        })
}
fn covers_minimum_events(value: Allocator, facts: usize) -> bool {
    u64::try_from(facts)
        .ok()
        .and_then(|facts| {
            value
                .last_rid
                .checked_add(value.dead_count)?
                .checked_add(facts)
        })
        .is_some_and(|minimum| {
            value.compatibility_sequence >= minimum && value.append_ordinal >= minimum
        })
}
fn step(value: &mut Allocator) -> Result<()> {
    value.compatibility_sequence = add(value.compatibility_sequence, 1)?;
    value.append_ordinal = add(value.append_ordinal, 1)?;
    Ok(())
}
fn put(batch: &mut WriteBatch, role: Role, key: Key<'_>, row: Row<'_>) -> Result<()> {
    batch.put(role.cf(), key.encode()?, row.encode()?);
    Ok(())
}
fn mapping_pair(
    batch: &mut WriteBatch,
    next: &mut Allocator,
    mapping: &Mapping,
    decision: Decision,
    context: &Context<'_>,
) -> Result<()> {
    if mapping.index == 0 || mapping.index > context.descriptors {
        return Err(PraxisError::InvalidConfig(
            "unknown record mapping descriptor".into(),
        ));
    }
    step(next)?;
    put(
        batch,
        Role::Index,
        Key::Fact {
            index: mapping.index,
            incarnation: 1,
            key: &mapping.key,
            raw_sequence: next.compatibility_sequence,
        },
        Row::Fact {
            append_ordinal: next.append_ordinal,
            decision,
        },
    )?;
    put(
        batch,
        Role::Index,
        Key::Head {
            index: mapping.index,
            incarnation: 1,
            key: &mapping.key,
        },
        Row::Head {
            raw_sequence: next.compatibility_sequence,
            append_ordinal: next.append_ordinal,
            decision,
        },
    )
}

/// Build into a request-local batch. Nothing is merged into the accepted group
/// overlay until the receipt, exact frame sizing and shared validator succeed.
pub(crate) fn plan(
    intent: &RecordIntent,
    sequence: u64,
    context: &Context<'_>,
    read: &mut ReadRow<'_>,
) -> Result<PlannedRecord> {
    let prior = allocator(read, context.source)?;
    let mut next = prior;
    let mut batch = WriteBatch::new();
    let mut records = 0u32;
    let mut deleted = BTreeMap::<u64, (bool, u64)>::new();
    let mut result = RecordResult::Unit;
    let kind;
    let mut delete = |rid: RecordId, batch: &mut WriteBatch, next: &mut Allocator| -> Result<()> {
        let (live, len) = match deleted.get(&rid.0) {
            Some(value) => *value,
            None => state(read, rid.0, context.source)?,
        };
        if live {
            next.live_count = next
                .live_count
                .checked_sub(1)
                .ok_or_else(|| corrupt(context.source, "record live count underflow"))?;
            next.dead_count = add(next.dead_count, 1)?;
            next.live_payload_bytes = next
                .live_payload_bytes
                .checked_sub(len)
                .ok_or_else(|| corrupt(context.source, "record byte count underflow"))?;
        }
        deleted.insert(rid.0, (false, 0));
        step(next)?;
        put(
            batch,
            Role::State,
            Key::State(rid.0),
            Row::State {
                live: false,
                payload_length: 0,
            },
        )?;
        batch.delete(Role::Payload.cf(), Key::Payload(rid.0).encode()?);
        Ok(())
    };
    match intent.kind() {
        IntentKind::Create(inputs) => {
            kind = Kind::Create;
            let mut ids = Vec::with_capacity(inputs.len());
            for input in inputs {
                next.last_rid = add(next.last_rid, 1)?;
                next.live_count = add(next.live_count, 1)?;
                next.live_payload_bytes = add(next.live_payload_bytes, input.payload.len() as u64)?;
                step(&mut next)?;
                put(
                    &mut batch,
                    Role::Payload,
                    Key::Payload(next.last_rid),
                    Row::Payload(&input.payload),
                )?;
                put(
                    &mut batch,
                    Role::State,
                    Key::State(next.last_rid),
                    Row::State {
                        live: true,
                        payload_length: input.payload.len() as u64,
                    },
                )?;
                ids.push(RecordId(next.last_rid));
                for mapping in &input.mappings {
                    let rid = next.last_rid;
                    mapping_pair(&mut batch, &mut next, mapping, Decision::Put(rid), context)?;
                }
            }
            records = u32::try_from(inputs.len())
                .map_err(|_| corrupt(context.source, "record count overflow"))?;
            result = RecordResult::Created(ids);
        }
        IntentKind::DeleteRecords(ids) => {
            kind = Kind::DeleteRecords;
            for rid in ids {
                delete(*rid, &mut batch, &mut next)?;
            }
            records = u32::try_from(ids.len())
                .map_err(|_| corrupt(context.source, "record count overflow"))?;
        }
        IntentKind::IndexPut(mapping, rid) => {
            kind = Kind::IndexPut;
            if !state(read, rid.0, context.source)?.0 {
                return Err(PraxisError::KeyNotFound);
            }
            mapping_pair(
                &mut batch,
                &mut next,
                mapping,
                Decision::Put(rid.0),
                context,
            )?;
        }
        IntentKind::IndexDelete(mapping) => {
            kind = Kind::IndexDelete;
            mapping_pair(&mut batch, &mut next, mapping, Decision::Delete, context)?;
        }
        IntentKind::Cleanup(rid, mappings) => {
            kind = if mappings.is_empty() {
                Kind::DeleteRecords
            } else {
                Kind::DeleteWithIndexCleanup
            };
            for mapping in mappings {
                mapping_pair(&mut batch, &mut next, mapping, Decision::Delete, context)?;
            }
            delete(*rid, &mut batch, &mut next)?;
            records = 1;
        }
        IntentKind::DeleteByIndex(mapping) => {
            // End the delete closure's borrow before reading the current head.
            let key = Key::Head {
                index: mapping.index,
                incarnation: 1,
                key: &mapping.key,
            };
            let found = match read(Role::Index, &key.encode()?)? {
                None => None,
                Some(bytes) => {
                    match Row::decode(&key, bytes.bytes(context.source)?, context.source)? {
                        Row::Head {
                            decision: Decision::Put(rid),
                            ..
                        } => Some(RecordId(rid)),
                        Row::Head {
                            decision: Decision::Delete,
                            ..
                        } => None,
                        _ => unreachable!(),
                    }
                }
            };
            let lowered = RecordIntent::new(match found {
                Some(rid) => IntentKind::Cleanup(rid, vec![mapping.clone()]),
                None => IntentKind::IndexDelete(mapping.clone()),
            })?;
            let mut planned = plan(&lowered, sequence, context, read)?;
            if planned.encoded_len > intent.admission_bytes() {
                return Err(corrupt(
                    context.source,
                    "resolved cleanup exceeds original admission charge",
                ));
            }
            planned.receipt.result = RecordResult::DeletedByIndex(found);
            return Ok(planned);
        }
    }
    if batch.is_empty() {
        return Err(PraxisError::InvalidConfig(
            "empty record request must bypass admission".into(),
        ));
    }
    put(&mut batch, Role::Meta, Key::Allocator, Row::Allocator(next))?;
    let logical = u32::try_from(next.compatibility_sequence - prior.compatibility_sequence)
        .map_err(|_| corrupt(context.source, "logical count exceeds u32"))?;
    let envelope = Envelope {
        kind,
        database_id: context.id,
        prior_rid: prior.last_rid,
        new_rid: next.last_rid,
        prior_compatibility_sequence: prior.compatibility_sequence,
        new_compatibility_sequence: next.compatibility_sequence,
        prior_append_ordinal: prior.append_ordinal,
        new_append_ordinal: next.append_ordinal,
        record_count: records,
        logical_entry_count: logical,
    };
    let encoded_len = crate::wal::record::checked_core_encoded_len(sequence, &batch, &envelope)?;
    if encoded_len > intent.admission_bytes() {
        return Err(corrupt(
            context.source,
            "record materialization exceeds admission charge",
        ));
    }
    let updates = validate(sequence, &envelope, &batch, context, Some(read))?;
    let receipt = RecordReceipt {
        core_sequence: sequence,
        compatibility_sequence: next.compatibility_sequence,
        result,
    };
    Ok(PlannedRecord {
        record: CoreWalRecord::Record {
            sequence,
            envelope,
            batch,
        },
        receipt,
        updates,
        encoded_len,
    })
}

struct Cursor<'a, 'b> {
    ops: &'a [BatchOp],
    position: usize,
    context: &'b Context<'b>,
    updates: Rows,
}
impl<'a> Cursor<'a, '_> {
    fn peek_role(&self) -> Option<Role> {
        self.ops.get(self.position).and_then(|op| match op {
            BatchOp::Put { cf, .. } | BatchOp::Delete { cf, .. } => Role::from_cf(&cf.0),
            _ => None,
        })
    }
    fn put(&mut self) -> Result<(Key<'a>, Row<'a>)> {
        let Some(BatchOp::Put { cf, key, value }) = self.ops.get(self.position) else {
            return Err(corrupt(
                self.context.source,
                "canonical record expected put",
            ));
        };
        let role = Role::from_cf(&cf.0)
            .ok_or_else(|| corrupt(self.context.source, "record contains an unrelated CF"))?;
        let parsed_key = Key::decode(role, key, self.context.source)?;
        let row = Row::decode(&parsed_key, value, self.context.source)?;
        self.updates.insert(
            (role, key.clone()),
            Some(Summary::decode(role, key, value, self.context.source)?),
        );
        self.position += 1;
        Ok((parsed_key, row))
    }
    fn payload_delete(&mut self, rid: u64) -> Result<()> {
        let Some(BatchOp::Delete { cf, key }) = self.ops.get(self.position) else {
            return Err(corrupt(
                self.context.source,
                "canonical record expected payload tombstone",
            ));
        };
        if cf.0 != Role::Payload.cf()
            || Key::decode(Role::Payload, key, self.context.source)? != Key::Payload(rid)
        {
            return Err(corrupt(
                self.context.source,
                "record payload tombstone mismatch",
            ));
        }
        self.updates.insert((Role::Payload, key.clone()), None);
        self.position += 1;
        Ok(())
    }
    fn mapping(
        &mut self,
        raw: u64,
        ordinal: u64,
        expected: Option<Decision>,
        max_rid: u64,
    ) -> Result<()> {
        let (
            Key::Fact {
                index,
                incarnation,
                key,
                raw_sequence,
            },
            Row::Fact {
                append_ordinal,
                decision,
            },
        ) = self.put()?
        else {
            return Err(corrupt(
                self.context.source,
                "expected canonical mapping fact",
            ));
        };
        if index > self.context.descriptors
            || incarnation != 1
            || raw_sequence != raw
            || append_ordinal != ordinal
            || expected.is_some_and(|value| value != decision)
            || matches!(decision, Decision::Put(rid) if rid > max_rid || raw <= rid)
        {
            return Err(corrupt(
                self.context.source,
                "canonical fact binding/order/RID mismatch",
            ));
        }
        let (head_key, head_row) = self.put()?;
        if head_key
            != (Key::Head {
                index,
                incarnation,
                key,
            })
            || head_row
                != (Row::Head {
                    raw_sequence,
                    append_ordinal,
                    decision,
                })
        {
            return Err(corrupt(
                self.context.source,
                "canonical mapping head mismatch",
            ));
        }
        Ok(())
    }
}

fn validate_envelope_context(
    sequence: u64,
    envelope: &Envelope,
    context: &Context<'_>,
) -> Result<()> {
    envelope.validate(sequence, context.source)?;
    if envelope.database_id != context.id
        || envelope.prior_compatibility_sequence != envelope.prior_append_ordinal
        || envelope.new_compatibility_sequence != envelope.new_append_ordinal
    {
        return Err(corrupt(
            context.source,
            "authority identity/fresh counter domains mismatch",
        ));
    }
    Ok(())
}

/// Check a bootstrap envelope and its borrowed record-only operations without
/// constructing row updates. V4 calls this on the prefix before its catalog
/// Head and Anchor; v3 retains its historical materialized updates below.
pub(crate) fn validate_bootstrap_ops(
    sequence: u64,
    envelope: &Envelope,
    ops: &[BatchOp],
    context: &Context<'_>,
) -> Result<()> {
    validate_envelope_context(sequence, envelope, context)?;
    if envelope.kind != Kind::Bootstrap {
        return Err(corrupt(
            context.source,
            "record bootstrap envelope kind mismatch",
        ));
    }
    check_bootstrap_ops(ops, context)
}

/// Parse by actual operations, never a claimed count. In historical mode every
/// RID is bounded by that envelope's prior/new floor, not today's liveness.
pub(crate) fn validate(
    sequence: u64,
    envelope: &Envelope,
    batch: &WriteBatch,
    context: &Context<'_>,
    mut read: Option<&mut ReadRow<'_>>,
) -> Result<Rows> {
    validate_envelope_context(sequence, envelope, context)?;
    if envelope.kind == Kind::Bootstrap {
        return bootstrap(batch, context);
    }
    let mut expected = read
        .as_mut()
        .map(|get| allocator(*get, context.source))
        .transpose()?;
    if expected.is_some_and(|value| {
        value.last_rid != envelope.prior_rid
            || value.compatibility_sequence != envelope.prior_compatibility_sequence
            || value.append_ordinal != envelope.prior_append_ordinal
    }) {
        return Err(corrupt(
            context.source,
            "record envelope prior differs from committed state",
        ));
    }
    let mut cursor = Cursor {
        ops: batch.ops(),
        position: 0,
        context,
        updates: Rows::new(),
    };
    let mut raw = envelope.prior_compatibility_sequence;
    let mut ordinal = envelope.prior_append_ordinal;
    let mut record_count = 0u64;
    let mut created_bytes = 0u64;
    let mut rid_floor = envelope.prior_rid;
    let mut deleted = BTreeMap::new();
    let mut deleted_rids = std::collections::BTreeSet::new();
    let advance = |raw: &mut u64, ordinal: &mut u64| -> Result<()> {
        *raw = raw
            .checked_add(1)
            .ok_or_else(|| corrupt(context.source, "raw counter overflow"))?;
        *ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| corrupt(context.source, "ordinal overflow"))?;
        Ok(())
    };
    match envelope.kind {
        Kind::Create => {
            while cursor.peek_role() == Some(Role::Payload) {
                let (Key::Payload(rid), Row::Payload(payload)) = cursor.put()? else {
                    return Err(corrupt(context.source, "create payload shape mismatch"));
                };
                rid_floor = rid_floor
                    .checked_add(1)
                    .ok_or_else(|| corrupt(context.source, "RID overflow"))?;
                if rid != rid_floor {
                    return Err(corrupt(
                        context.source,
                        "create allocation is not contiguous",
                    ));
                }
                let (key, row) = cursor.put()?;
                if key != Key::State(rid)
                    || row
                        != (Row::State {
                            live: true,
                            payload_length: payload.len() as u64,
                        })
                {
                    return Err(corrupt(context.source, "create state/payload mismatch"));
                }
                created_bytes = created_bytes
                    .checked_add(payload.len() as u64)
                    .ok_or_else(|| corrupt(context.source, "payload bytes overflow"))?;
                record_count += 1;
                advance(&mut raw, &mut ordinal)?;
                while cursor.peek_role() == Some(Role::Index) {
                    advance(&mut raw, &mut ordinal)?;
                    cursor.mapping(raw, ordinal, Some(Decision::Put(rid)), rid)?;
                }
            }
            if let Some(value) = &mut expected {
                value.last_rid = rid_floor;
                value.live_count = value
                    .live_count
                    .checked_add(record_count)
                    .ok_or_else(|| corrupt(context.source, "live count overflow"))?;
                value.live_payload_bytes = value
                    .live_payload_bytes
                    .checked_add(created_bytes)
                    .ok_or_else(|| corrupt(context.source, "byte count overflow"))?;
            }
        }
        Kind::IndexPut | Kind::IndexDelete => {
            let rid = match cursor.ops.first() {
                Some(BatchOp::Put { key, value, .. }) => match Row::decode(
                    &Key::decode(Role::Index, key, context.source)?,
                    value,
                    context.source,
                )? {
                    Row::Fact {
                        decision: Decision::Put(rid),
                        ..
                    } => Some(rid),
                    _ => None,
                },
                _ => None,
            };
            if (envelope.kind == Kind::IndexPut) != rid.is_some() {
                return Err(corrupt(context.source, "index mutation decision mismatch"));
            }
            if let (Some(get), Some(rid)) = (read.as_mut(), rid)
                && !state(*get, rid, context.source)?.0
            {
                return Err(corrupt(context.source, "index put targets dead RID"));
            }
            advance(&mut raw, &mut ordinal)?;
            cursor.mapping(
                raw,
                ordinal,
                Some(rid.map_or(Decision::Delete, Decision::Put)),
                envelope.prior_rid,
            )?;
        }
        Kind::DeleteRecords | Kind::DeleteWithIndexCleanup => {
            while envelope.kind == Kind::DeleteWithIndexCleanup
                && cursor.peek_role() == Some(Role::Index)
            {
                advance(&mut raw, &mut ordinal)?;
                cursor.mapping(raw, ordinal, Some(Decision::Delete), envelope.prior_rid)?;
            }
            while cursor.peek_role() == Some(Role::State) {
                let (
                    Key::State(rid),
                    Row::State {
                        live: false,
                        payload_length: 0,
                    },
                ) = cursor.put()?
                else {
                    return Err(corrupt(context.source, "delete state shape mismatch"));
                };
                if rid > envelope.prior_rid {
                    return Err(corrupt(
                        context.source,
                        "delete RID is not allocated at this frame",
                    ));
                }
                cursor.payload_delete(rid)?;
                deleted_rids.insert(rid);
                if let (Some(get), Some(value)) = (read.as_mut(), &mut expected) {
                    let (live, len) = match deleted.get(&rid) {
                        Some(value) => *value,
                        None => state(*get, rid, context.source)?,
                    };
                    if live {
                        value.live_count = value
                            .live_count
                            .checked_sub(1)
                            .ok_or_else(|| corrupt(context.source, "live count underflow"))?;
                        value.dead_count = value
                            .dead_count
                            .checked_add(1)
                            .ok_or_else(|| corrupt(context.source, "dead count overflow"))?;
                        value.live_payload_bytes = value
                            .live_payload_bytes
                            .checked_sub(len)
                            .ok_or_else(|| corrupt(context.source, "payload byte underflow"))?;
                    }
                    deleted.insert(rid, (false, 0));
                }
                record_count += 1;
                advance(&mut raw, &mut ordinal)?;
            }
        }
        Kind::Bootstrap => unreachable!(),
    }
    let (Key::Allocator, Row::Allocator(actual)) = cursor.put()? else {
        return Err(corrupt(context.source, "final record allocator is missing"));
    };
    if !covers_minimum_events(actual, 0)
        || cursor.position != cursor.ops.len()
        || record_count != u64::from(envelope.record_count)
        || rid_floor != envelope.new_rid
        || raw != envelope.new_compatibility_sequence
        || ordinal != envelope.new_append_ordinal
        || actual.last_rid != envelope.new_rid
        || actual.compatibility_sequence != raw
        || actual.append_ordinal != ordinal
        || actual.dead_count < deleted_rids.len() as u64
        || (actual.live_count == 0 && actual.live_payload_bytes != 0)
        || (envelope.kind == Kind::IndexPut && actual.live_count == 0)
        || (envelope.kind == Kind::Create
            && envelope.prior_rid == 0
            && actual.live_payload_bytes != created_bytes)
        || (envelope.kind == Kind::Create
            && (actual.live_count < record_count
                || actual.dead_count > envelope.prior_rid
                || actual.live_payload_bytes < created_bytes))
    {
        return Err(corrupt(
            context.source,
            "canonical operation count/order/final allocator mismatch",
        ));
    }
    if let Some(mut value) = expected {
        value.compatibility_sequence = raw;
        value.append_ordinal = ordinal;
        if value != actual {
            return Err(corrupt(
                context.source,
                "record counter transition differs from actual prior state",
            ));
        }
    }
    Ok(cursor.updates)
}

fn borrowed_bootstrap_put<'a>(
    op: &'a BatchOp,
    context: &Context<'_>,
) -> Result<(Key<'a>, Row<'a>)> {
    let BatchOp::Put { cf, key, value } = op else {
        return Err(corrupt(context.source, "canonical record expected put"));
    };
    if cf.0 != Role::Meta.cf() {
        return Err(corrupt(context.source, "bootstrap record role mismatch"));
    }
    let key = Key::decode(Role::Meta, key, context.source)?;
    let row = Row::decode(&key, value, context.source)?;
    Ok((key, row))
}

pub(crate) fn check_bootstrap_ops(ops: &[BatchOp], context: &Context<'_>) -> Result<()> {
    let Some(expected_len) = usize::try_from(context.descriptors)
        .ok()
        .and_then(|descriptors| descriptors.checked_add(2))
    else {
        return Err(corrupt(context.source, "bootstrap registry count overflow"));
    };
    if ops.len() != expected_len {
        return Err(corrupt(context.source, "bootstrap registry count mismatch"));
    }
    let (key, row) = borrowed_bootstrap_put(&ops[0], context)?;
    if key != Key::Binding
        || row
            != (Row::Binding {
                database_id: context.id,
                descriptor_count: context.descriptors,
            })
    {
        return Err(corrupt(context.source, "bootstrap binding mismatch"));
    }
    let (key, row) = borrowed_bootstrap_put(&ops[1], context)?;
    if key != Key::Allocator || row != Row::Allocator(Allocator::default()) {
        return Err(corrupt(context.source, "bootstrap allocator mismatch"));
    }
    let mut previous = None;
    for (position, op) in ops.iter().enumerate().skip(2) {
        let expected = u32::try_from(position - 1)
            .map_err(|_| corrupt(context.source, "descriptor ID overflow"))?;
        let (key, row) = borrowed_bootstrap_put(op, context)?;
        let Row::Descriptor { name, .. } = row else {
            return Err(corrupt(context.source, "bootstrap descriptor shape"));
        };
        if key != Key::Descriptor(expected)
            || previous.is_some_and(|value: &str| value.as_bytes() >= name.as_bytes())
        {
            return Err(corrupt(context.source, "bootstrap descriptor order"));
        }
        previous = Some(name);
    }
    Ok(())
}

fn bootstrap(batch: &WriteBatch, context: &Context<'_>) -> Result<Rows> {
    check_bootstrap_ops(batch.ops(), context)?;
    let mut cursor = Cursor {
        ops: batch.ops(),
        position: 0,
        context,
        updates: Rows::new(),
    };
    let (key, row) = cursor.put()?;
    if key != Key::Binding
        || row
            != (Row::Binding {
                database_id: context.id,
                descriptor_count: context.descriptors,
            })
    {
        return Err(corrupt(context.source, "bootstrap binding mismatch"));
    }
    let (key, row) = cursor.put()?;
    if key != Key::Allocator || row != Row::Allocator(Allocator::default()) {
        return Err(corrupt(context.source, "bootstrap allocator mismatch"));
    }
    let mut previous = None;
    while cursor.position < cursor.ops.len() {
        let expected = u32::try_from(cursor.position - 1)
            .map_err(|_| corrupt(context.source, "descriptor ID overflow"))?;
        let (key, row) = cursor.put()?;
        let Row::Descriptor { name, .. } = row else {
            return Err(corrupt(context.source, "bootstrap descriptor shape"));
        };
        if key != Key::Descriptor(expected)
            || previous.is_some_and(|value: &str| value.as_bytes() >= name.as_bytes())
        {
            return Err(corrupt(context.source, "bootstrap descriptor order"));
        }
        previous = Some(name);
    }
    Ok(cursor.updates)
}

/// Cross-check installed state by walking actual rows. The allocator is a
/// claim to prove, never a capacity or iteration bound.
pub(crate) fn validate_installed(rows: &Rows, context: &Context<'_>) -> Result<Allocator> {
    let mut get = |role, key: &[u8]| Ok(rows.get(&(role, key.to_vec())).cloned().flatten());
    let value = allocator(&mut get, context.source)?;
    if value.compatibility_sequence != value.append_ordinal {
        return Err(corrupt(
            context.source,
            "fresh allocator counter domains differ",
        ));
    }
    let mut states = 0u64;
    let mut live = 0u64;
    let mut bytes = 0u64;
    let mut descriptors = 0u32;
    let mut binding = false;
    let mut previous_name: Option<String> = None;
    let mut facts = BTreeMap::new();
    let mut ordinals = std::collections::BTreeSet::new();
    let mut heads = BTreeMap::new();
    for ((role, encoded), summary) in rows {
        let key = Key::decode(*role, encoded, context.source)?;
        check_summary(*role, encoded, summary.as_ref(), value, context)?;
        let Some(summary) = summary else {
            continue;
        };
        if let Summary::Payload { .. } = summary {
            continue;
        }
        let row = Row::decode(&key, summary.bytes(context.source)?, context.source)?;
        match (key, row) {
            (
                Key::Binding,
                Row::Binding {
                    database_id,
                    descriptor_count,
                },
            ) => {
                if database_id != context.id || descriptor_count != context.descriptors {
                    return Err(corrupt(
                        context.source,
                        "installed authority binding mismatch",
                    ));
                }
                binding = true;
            }
            (Key::Descriptor(index), Row::Descriptor { name, .. }) => {
                descriptors = descriptors
                    .checked_add(1)
                    .ok_or_else(|| corrupt(context.source, "descriptor count overflow"))?;
                if index != descriptors
                    || previous_name
                        .as_ref()
                        .is_some_and(|prior| prior.as_bytes() >= name.as_bytes())
                {
                    return Err(corrupt(
                        context.source,
                        "installed registry is not contiguous/canonical",
                    ));
                }
                previous_name = Some(name.into());
            }
            (
                Key::State(rid),
                Row::State {
                    live: is_live,
                    payload_length,
                },
            ) => {
                states = states
                    .checked_add(1)
                    .ok_or_else(|| corrupt(context.source, "state count overflow"))?;
                if rid != states {
                    return Err(corrupt(
                        context.source,
                        "allocated RID states are not contiguous",
                    ));
                }
                let payload = rows
                    .get(&(Role::Payload, Key::Payload(rid).encode()?))
                    .and_then(Option::as_ref);
                if is_live {
                    if !matches!(payload, Some(Summary::Payload { len, .. }) if *len == payload_length)
                    {
                        return Err(corrupt(
                            context.source,
                            "live state/payload length mismatch",
                        ));
                    }
                    live += 1;
                    bytes = bytes
                        .checked_add(payload_length)
                        .ok_or_else(|| corrupt(context.source, "live payload byte overflow"))?;
                } else if payload.is_some() {
                    return Err(corrupt(
                        context.source,
                        "dead RID retains a current payload",
                    ));
                }
            }
            (
                Key::Fact {
                    index,
                    key,
                    raw_sequence,
                    ..
                },
                Row::Fact {
                    append_ordinal,
                    decision,
                },
            ) => {
                if !ordinals.insert(append_ordinal) {
                    return Err(corrupt(
                        context.source,
                        "mapping append ordinal has multiple fact owners",
                    ));
                }
                let latest = facts.entry((index, key.to_vec())).or_insert((
                    raw_sequence,
                    append_ordinal,
                    decision,
                ));
                if latest.1 < append_ordinal {
                    *latest = (raw_sequence, append_ordinal, decision);
                }
            }
            (
                Key::Head { index, key, .. },
                Row::Head {
                    raw_sequence,
                    append_ordinal,
                    decision,
                },
            ) => {
                heads.insert(
                    (index, key.to_vec()),
                    (raw_sequence, append_ordinal, decision),
                );
            }
            _ => {}
        }
    }
    if !covers_minimum_events(value, ordinals.len())
        || !binding
        || descriptors != context.descriptors
        || states != value.last_rid
        || live != value.live_count
        || states.checked_sub(live) != Some(value.dead_count)
        || bytes != value.live_payload_bytes
        || facts != heads
    {
        return Err(corrupt(
            context.source,
            "installed record rows/counters/facts/heads disagree",
        ));
    }
    Ok(value)
}

pub(crate) fn check_summary(
    role: Role,
    encoded: &[u8],
    summary: Option<&Summary>,
    allocator: Allocator,
    context: &Context<'_>,
) -> Result<()> {
    let key = Key::decode(role, encoded, context.source)?;
    if let Key::Payload(rid) | Key::State(rid) = key
        && rid > allocator.last_rid
    {
        return Err(corrupt(
            context.source,
            "row RID exceeds installed allocation",
        ));
    }
    let Some(summary) = summary else {
        if !matches!(key, Key::Payload(_)) {
            return Err(corrupt(context.source, "forbidden protected tombstone"));
        }
        return Ok(());
    };
    if let Summary::Payload { .. } = summary {
        if !matches!(key, Key::Payload(_)) {
            return Err(corrupt(context.source, "payload summary has wrong role"));
        }
        return Ok(());
    }
    match Row::decode(&key, summary.bytes(context.source)?, context.source)? {
        Row::Allocator(old)
            if !covers_minimum_events(old, 0)
                || (old.live_count == 0 && old.live_payload_bytes != 0)
                || old.last_rid > allocator.last_rid
                || old.dead_count > allocator.dead_count
                || old.compatibility_sequence > allocator.compatibility_sequence
                || old.append_ordinal > allocator.append_ordinal
                || old.compatibility_sequence != old.append_ordinal =>
        {
            return Err(corrupt(
                context.source,
                "retained allocator exceeds installed monotone floors",
            ));
        }
        Row::Fact {
            append_ordinal,
            decision,
        }
        | Row::Head {
            append_ordinal,
            decision,
            ..
        } => {
            let (index, raw_sequence) = match key {
                Key::Fact {
                    index,
                    raw_sequence,
                    ..
                } => (index, raw_sequence),
                Key::Head { index, .. } => {
                    let Row::Head { raw_sequence, .. } =
                        Row::decode(&key, summary.bytes(context.source)?, context.source)?
                    else {
                        unreachable!()
                    };
                    (index, raw_sequence)
                }
                _ => unreachable!(),
            };
            if index > context.descriptors
                || raw_sequence == 0
                || raw_sequence != append_ordinal
                || raw_sequence > allocator.compatibility_sequence
                || append_ordinal > allocator.append_ordinal
                || matches!(decision, Decision::Put(rid) if rid > allocator.last_rid || raw_sequence <= rid)
            {
                return Err(corrupt(
                    context.source,
                    "installed mapping reference/counter mismatch",
                ));
            }
        }
        Row::Binding {
            database_id,
            descriptor_count,
        } if database_id != context.id || descriptor_count != context.descriptors => {
            return Err(corrupt(context.source, "binding mismatch"));
        }
        Row::Descriptor { .. } if matches!(key, Key::Descriptor(id) if id > context.descriptors) => {
            return Err(corrupt(context.source, "unknown registry descriptor"));
        }
        _ => {}
    }
    Ok(())
}
