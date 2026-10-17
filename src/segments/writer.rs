use crate::accel::Accelerator;
use crate::config::Compression;
use crate::errors::Result;
use crate::io::{BinaryWriter, file_digest, write_file_with_policy};
use crate::manifest::SegmentMetadata;
use crate::segments::block::SegmentEntry;
use crate::segments::bloom::{BloomFilter, bloom_key};
use crate::segments::format::{
    BlockIndexEntry, SEGMENT_FOOTER_MAGIC, SEGMENT_MAGIC, SEGMENT_VERSION,
};
use crate::types::StoredValue;
use crate::values::ValueLog;
use std::path::Path;

pub struct SegmentWriter;

pub struct SegmentWriteOptions<'a> {
    pub path: &'a Path,
    pub id: u64,
    pub level: u32,
    pub compression: Compression,
    pub accelerator: &'a dyn Accelerator,
    pub value_log: &'a mut ValueLog,
    pub large_value_threshold: usize,
    pub block_size: usize,
    pub partitioned_bloom: Option<(usize, usize)>,
    pub direct_io: bool,
}

impl SegmentWriter {
    pub fn write(
        mut options: SegmentWriteOptions<'_>,
        mut entries: Vec<SegmentEntry>,
    ) -> Result<SegmentMetadata> {
        entries.sort_by(|left, right| {
            (&left.cf.0, left.key.as_ref()).cmp(&(&right.cf.0, right.key.as_ref()))
        });
        let mut bloom_filter = BloomFilter::with_expected_items(entries.len());
        let mut partitioned_bloom_filter =
            options.partitioned_bloom.map(|(prefix_len, partitions)| {
                crate::segments::PartitionedBloomFilter::new(prefix_len, entries.len(), partitions)
            });
        let mut out = BinaryWriter::new();
        out.write_u32(SEGMENT_MAGIC);
        out.write_u32(SEGMENT_VERSION);
        out.write_u8(match options.compression {
            Compression::None => 0,
            Compression::Lz4 => 1,
            Compression::Zstd => 2,
        });
        out.write_u32(options.level);
        out.write_u64(options.id);

        let mut index = Vec::new();
        let mut block_entries = Vec::new();
        let mut block_bytes = 0usize;
        for entry in &entries {
            let estimated = entry.cf.0.len() + entry.key.len() + 32 + encoded_value_len(entry);
            if !block_entries.is_empty() && block_bytes + estimated > options.block_size {
                write_block(
                    &mut options,
                    &mut out,
                    &block_entries,
                    &mut bloom_filter,
                    partitioned_bloom_filter.as_mut(),
                    &mut index,
                )?;
                block_entries.clear();
                block_bytes = 0;
            }
            block_bytes += estimated;
            block_entries.push(entry.clone());
        }
        if !block_entries.is_empty() {
            write_block(
                &mut options,
                &mut out,
                &block_entries,
                &mut bloom_filter,
                partitioned_bloom_filter.as_mut(),
                &mut index,
            )?;
        }

        let footer = encode_footer(&index);
        let footer_checksum = options.accelerator.crc32c(&footer);
        out.write_bytes(&footer);
        out.write_u32(footer.len() as u32);
        out.write_u32(footer_checksum);
        out.write_u32(SEGMENT_FOOTER_MAGIC);
        write_file_with_policy(options.path, &out.into_inner(), options.direct_io)?;
        let digest = file_digest(options.path)?;
        let min_key = entries
            .first()
            .map(|entry| entry.key.to_vec())
            .unwrap_or_default();
        let max_key = entries
            .last()
            .map(|entry| entry.key.to_vec())
            .unwrap_or_default();
        Ok(SegmentMetadata {
            id: options.id,
            level: options.level,
            path: options.path.to_string_lossy().to_string(),
            min_key,
            max_key,
            entries: entries.len() as u64,
            bloom_filter,
            partitioned_bloom_filter,
            file_digest: digest.to_hex().to_string(),
        })
    }
}

fn write_block(
    options: &mut SegmentWriteOptions<'_>,
    out: &mut BinaryWriter,
    entries: &[SegmentEntry],
    bloom_filter: &mut BloomFilter,
    partitioned_bloom_filter: Option<&mut crate::segments::PartitionedBloomFilter>,
    index: &mut Vec<BlockIndexEntry>,
) -> Result<()> {
    let offset = out.len() as u64;
    let payload = encode_block_entries(options, entries, bloom_filter, partitioned_bloom_filter)?;
    let compressed = options
        .accelerator
        .encode_block(options.compression, &payload)?;
    out.write_u32(compressed.len() as u32);
    out.write_u32(payload.len() as u32);
    out.write_u32(options.accelerator.crc32c(&compressed));
    out.write_bytes(&compressed);
    let len = out.len() as u64 - offset;
    index.push(BlockIndexEntry {
        first_key: entries.first().expect("block has entries").key.to_vec(),
        last_key: entries.last().expect("block has entries").key.to_vec(),
        offset,
        len,
    });
    Ok(())
}

fn encode_block_entries(
    options: &mut SegmentWriteOptions<'_>,
    entries: &[SegmentEntry],
    bloom_filter: &mut BloomFilter,
    mut partitioned_bloom_filter: Option<&mut crate::segments::PartitionedBloomFilter>,
) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(entries.len());
    for entry in entries {
        bloom_filter.insert(&bloom_key(&entry.cf.0, &entry.key));
        if let Some(partitioned) = partitioned_bloom_filter.as_deref_mut() {
            partitioned.insert(&bloom_key(&entry.cf.0, &entry.key));
        }
        let mut entry = entry.clone();
        let mut blob_expiry = None;
        entry.version.value = match &entry.version.value {
            StoredValue::Put(value) if value.len() > options.large_value_threshold => {
                StoredValue::BlobPointer(options.value_log.append(value)?)
            }
            StoredValue::PutWithExpiry {
                value,
                expires_at_ms,
            } if value.len() > options.large_value_threshold => {
                blob_expiry = Some(*expires_at_ms);
                StoredValue::BlobPointer(options.value_log.append(value)?)
            }
            value => value.clone(),
        };
        raw.push(crate::segments::codec::RawEntry { entry, blob_expiry });
    }
    crate::segments::codec::encode_entries(&raw)
}

fn encode_footer(index: &[BlockIndexEntry]) -> Vec<u8> {
    let mut footer = BinaryWriter::new();
    footer.write_u32(index.len() as u32);
    for entry in index {
        footer.write_len_bytes(&entry.first_key);
        footer.write_len_bytes(&entry.last_key);
        footer.write_u64(entry.offset);
        footer.write_u64(entry.len);
    }
    footer.into_inner()
}

fn encoded_value_len(entry: &SegmentEntry) -> usize {
    match &entry.version.value {
        StoredValue::Put(value) => value.len(),
        StoredValue::PutWithExpiry { value, .. } => value.len() + 8,
        StoredValue::Merge(value) => value.len(),
        StoredValue::BlobPointer(pointer) => pointer.path.len() + 24,
        StoredValue::Delete => 1,
    }
}
