//! Pure relation checks for one typed v4 catalog WAL frame.
use super::authority::CatalogAuthorityV1;
use super::codec::{CatalogKey, CatalogValue, Head, anchor_digest, canonical_head_at_1};
use super::control::CatalogControl;
use crate::core_records::RecordAuthority;
use crate::core_records::transition::{self, Context as RecordContext};
use crate::errors::{PraxisError, Result};
use crate::transactions::BatchOp;
use crate::wal::record::CoreWalRecord;
use std::path::Path;

pub(crate) struct FrameContext<'a> {
    id: [u8; 16],
    descriptors: u32,
    source: &'a Path,
}

impl<'a> FrameContext<'a> {
    pub(crate) fn new(
        record: &RecordAuthority,
        catalog: &CatalogAuthorityV1,
        source: &'a Path,
    ) -> Result<Self> {
        record.validate_binding(source)?;
        catalog.validate(record, source)?;
        Ok(Self {
            id: record.identity(source)?,
            descriptors: record.index_descriptor_count,
            source,
        })
    }
}

pub(crate) trait PriorCatalog {
    /// Read both facts from one retained, immutable prior endpoint. Stage C
    /// holds its writer fence; replay supplies one validated prior state.
    fn head_and_name_presence(&mut self, exact_key: &[u8]) -> Result<(Head, bool)>;
}

pub(crate) struct ValidatedCatalogFrame<'a> {
    sequence: u64,
    ops: &'a [BatchOp],
}

impl ValidatedCatalogFrame<'_> {
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn ops(&self) -> &[BatchOp] {
        self.ops
    }
}

pub(crate) fn validate_bootstrap<'a>(
    record: &'a CoreWalRecord,
    context: &FrameContext<'_>,
) -> Result<ValidatedCatalogFrame<'a>> {
    let CoreWalRecord::Catalog {
        sequence,
        control:
            CatalogControl::Bootstrap {
                database_id,
                catalog_epoch,
                envelope,
            },
        batch,
    } = record
    else {
        return Err(corrupt(context, "expected typed catalog bootstrap frame"));
    };
    if *sequence != 1 || *database_id != context.id || *catalog_epoch != 1 {
        return Err(corrupt(
            context,
            "catalog bootstrap identity or sequence mismatch",
        ));
    }
    let Some(expected_len) = usize::try_from(context.descriptors)
        .ok()
        .and_then(|descriptors| descriptors.checked_add(4))
    else {
        return Err(corrupt(
            context,
            "catalog bootstrap operation count overflow",
        ));
    };
    let ops = batch.ops();
    if ops.len() != expected_len {
        return Err(corrupt(
            context,
            "catalog bootstrap operation count mismatch",
        ));
    }
    let record_context = RecordContext {
        id: context.id,
        descriptors: context.descriptors,
        source: context.source,
    };
    transition::validate_bootstrap_ops(
        *sequence,
        envelope,
        &ops[..expected_len - 2],
        &record_context,
    )?;
    let (head_key, head_bytes) = plain_catalog_put(&ops[expected_len - 2], context)?;
    if CatalogKey::decode(head_key, context.source)? != CatalogKey::Head {
        return Err(corrupt(context, "catalog bootstrap Head key mismatch"));
    }
    if !matches!(
        CatalogValue::decode(&CatalogKey::Head, head_bytes, context.source)?,
        CatalogValue::Head(_)
    ) || head_bytes != canonical_head_at_1(context.id)?.as_slice()
    {
        return Err(corrupt(context, "catalog bootstrap Head value mismatch"));
    }
    let (anchor_key, anchor_bytes) = plain_catalog_put(&ops[expected_len - 1], context)?;
    if CatalogKey::decode(anchor_key, context.source)? != CatalogKey::Anchor {
        return Err(corrupt(context, "catalog bootstrap Anchor key mismatch"));
    }
    if !matches!(
        CatalogValue::decode(&CatalogKey::Anchor, anchor_bytes, context.source)?,
        CatalogValue::Anchor(_)
    ) || anchor_bytes != canonical_anchor_at_1(context.id)?.as_slice()
    {
        return Err(corrupt(context, "catalog bootstrap Anchor value mismatch"));
    }
    Ok(ValidatedCatalogFrame {
        sequence: *sequence,
        ops,
    })
}

pub(crate) fn validate_create<'a>(
    record: &'a CoreWalRecord,
    context: &FrameContext<'_>,
    prior: &mut dyn PriorCatalog,
) -> Result<ValidatedCatalogFrame<'a>> {
    let CoreWalRecord::Catalog {
        sequence,
        control:
            CatalogControl::Create {
                database_id,
                catalog_epoch,
                prior_revision,
                prior_count,
                new_revision,
                new_count,
            },
        batch,
    } = record
    else {
        return Err(corrupt(context, "expected typed catalog CREATE frame"));
    };
    if *sequence <= 1 || *database_id != context.id || *catalog_epoch != 1 {
        return Err(corrupt(
            context,
            "catalog CREATE identity or sequence mismatch",
        ));
    }
    let ops = batch.ops();
    if ops.len() != 4 {
        return Err(corrupt(context, "catalog CREATE operation count mismatch"));
    }
    let (head_key, head_bytes) = plain_catalog_put(&ops[0], context)?;
    let (name_key, name_bytes) = plain_catalog_put(&ops[1], context)?;
    let (schema_key, schema_bytes) = plain_catalog_put(&ops[2], context)?;
    let (namespace_key, namespace_bytes) = plain_catalog_put(&ops[3], context)?;
    if CatalogKey::decode(head_key, context.source)? != CatalogKey::Head {
        return Err(corrupt(context, "catalog CREATE Head key mismatch"));
    }
    let CatalogValue::Head(head) =
        CatalogValue::decode(&CatalogKey::Head, head_bytes, context.source)?
    else {
        return Err(corrupt(context, "catalog CREATE Head value mismatch"));
    };
    let CatalogKey::Name(name) = CatalogKey::decode(name_key, context.source)? else {
        return Err(corrupt(context, "catalog CREATE Name key mismatch"));
    };
    let CatalogValue::Name(collection_id) =
        CatalogValue::decode(&CatalogKey::Name(name), name_bytes, context.source)?
    else {
        return Err(corrupt(context, "catalog CREATE Name value mismatch"));
    };
    let CatalogKey::Schema(schema_key_id) = CatalogKey::decode(schema_key, context.source)? else {
        return Err(corrupt(context, "catalog CREATE Schema key mismatch"));
    };
    let CatalogValue::Schema(schema) = CatalogValue::decode(
        &CatalogKey::Schema(schema_key_id),
        schema_bytes,
        context.source,
    )?
    else {
        return Err(corrupt(context, "catalog CREATE Schema value mismatch"));
    };
    let CatalogKey::Namespace(namespace_key_id) =
        CatalogKey::decode(namespace_key, context.source)?
    else {
        return Err(corrupt(context, "catalog CREATE Namespace key mismatch"));
    };
    let CatalogValue::Namespace(namespace_collection_id) = CatalogValue::decode(
        &CatalogKey::Namespace(namespace_key_id),
        namespace_bytes,
        context.source,
    )?
    else {
        return Err(corrupt(context, "catalog CREATE Namespace value mismatch"));
    };
    let (prior_head, name_exists) = prior.head_and_name_presence(name_key)?;
    let expected_count = prior_head
        .collection_count
        .checked_add(1)
        .ok_or_else(|| corrupt(context, "catalog collection count overflow"))?;
    if prior_head.database_id != context.id
        || prior_head.revision == 0
        || *prior_revision != prior_head.revision
        || *prior_count != prior_head.collection_count
        || *new_revision != *sequence
        || *new_count != expected_count
        || *sequence <= prior_head.revision
        || head.database_id != context.id
        || head.revision != *sequence
        || head.collection_count != expected_count
        || collection_id.get() != *sequence
        || schema_key_id.get() != *sequence
        || schema.collection_id.get() != *sequence
        || schema.namespace_id.get() != *sequence
        || schema.name.as_bytes() != name.as_bytes()
        || namespace_key_id.get() != *sequence
        || namespace_collection_id.get() != *sequence
    {
        return Err(corrupt(context, "catalog CREATE frame relation mismatch"));
    }
    if name_exists {
        return Err(corrupt(context, "catalog CREATE name already exists"));
    }
    Ok(ValidatedCatalogFrame {
        sequence: *sequence,
        ops,
    })
}

fn plain_catalog_put<'a>(
    op: &'a BatchOp,
    context: &FrameContext<'_>,
) -> Result<(&'a [u8], &'a [u8])> {
    let BatchOp::Put { cf, key, value } = op else {
        return Err(corrupt(context, "catalog frame requires plain Put"));
    };
    if cf.0 != super::authority::CATALOG_CF {
        return Err(corrupt(context, "catalog frame column family mismatch"));
    }
    Ok((key, value))
}

fn canonical_anchor_at_1(database_id: [u8; 16]) -> Result<[u8; 72]> {
    let mut anchor = [0u8; 72];
    anchor[..4].copy_from_slice(b"PCA1");
    anchor[4..6].copy_from_slice(&1u16.to_le_bytes());
    anchor[8..24].copy_from_slice(&database_id);
    anchor[24..32].copy_from_slice(&1u64.to_le_bytes());
    anchor[32..40].copy_from_slice(&1u64.to_le_bytes());
    anchor[40..].copy_from_slice(&anchor_digest(database_id)?);
    Ok(anchor)
}

fn corrupt(context: &FrameContext<'_>, reason: &'static str) -> PraxisError {
    PraxisError::Corrupt {
        path: context.source.to_path_buf(),
        reason: reason.into(),
    }
}
