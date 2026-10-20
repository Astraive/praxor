use serde::{Deserialize, Serialize};

/// Failure to establish a bounded, fallible Bloom reconstruction from
/// observed physical rows. Persisted writer construction is unchanged.
#[allow(dead_code)] // Used by the upcoming private v4 segment visitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BloomBuildError {
    LimitExceeded,
    ArithmeticOverflow,
    AllocationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BloomFilter {
    bits: Vec<u64>,
    hash_count: u8,
    bit_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartitionedBloomFilter {
    pub partitions: Vec<BloomFilter>,
    pub prefix_len: usize,
}

impl BloomFilter {
    fn observed_bit_count(items: usize) -> Result<usize, BloomBuildError> {
        items
            .max(1)
            .checked_mul(12)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(BloomBuildError::ArithmeticOverflow)
    }

    pub(crate) fn observed_bits_len_bytes(items: usize) -> Result<usize, BloomBuildError> {
        Self::observed_bit_count(items)?
            .div_ceil(64)
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(BloomBuildError::ArithmeticOverflow)
    }

    pub(crate) fn observed_bits_capacity_limit_bytes(
        max_items: usize,
    ) -> Result<usize, BloomBuildError> {
        Self::observed_bit_count(max_items)?
            .div_ceil(64)
            .checked_mul(2)
            .and_then(|words| words.checked_add(16))
            .and_then(|words| words.checked_mul(std::mem::size_of::<u64>()))
            .ok_or(BloomBuildError::ArithmeticOverflow)
    }

    pub(crate) fn observed_bits_capacity_bytes(&self) -> Result<usize, BloomBuildError> {
        self.bits
            .capacity()
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(BloomBuildError::ArithmeticOverflow)
    }

    pub fn with_expected_items(items: usize) -> Self {
        let bit_count = ((items.max(1) * 12).next_power_of_two()) as u64;
        let words = bit_count.div_ceil(64) as usize;
        Self {
            bits: vec![0; words],
            hash_count: 7,
            bit_count,
        }
    }

    /// Reproduce the writer's exact Bloom shape, but only after an observed
    /// row count is checked against the reader's policy limit. The live Vec
    /// capacity is also capped because allocators may exceed a reservation.
    #[allow(dead_code)] // Used by the upcoming private v4 segment visitor.
    pub(crate) fn try_with_observed_items(
        items: usize,
        max_items: usize,
    ) -> Result<Self, BloomBuildError> {
        if items > max_items {
            return Err(BloomBuildError::LimitExceeded);
        }
        let bit_count = Self::observed_bit_count(items)?;
        let bit_count_u64 =
            u64::try_from(bit_count).map_err(|_| BloomBuildError::ArithmeticOverflow)?;
        let words = bit_count.div_ceil(64);
        let capacity_limit = Self::observed_bits_capacity_limit_bytes(max_items)?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(words)
            .map_err(|_| BloomBuildError::AllocationFailed)?;
        if bits
            .capacity()
            .checked_mul(std::mem::size_of::<u64>())
            .is_none_or(|bytes| bytes > capacity_limit)
        {
            return Err(BloomBuildError::LimitExceeded);
        }
        bits.resize(words, 0);
        Ok(Self {
            bits,
            hash_count: 7,
            bit_count: bit_count_u64,
        })
    }

    /// Insert the writer's `CF || 0 || key` form without allocating an
    /// unbounded temporary key. The caller reuses `scratch` across rows.
    #[allow(dead_code)] // Used by the upcoming private v4 segment visitor.
    pub(crate) fn try_insert_parts(
        &mut self,
        cf: &str,
        key: &[u8],
        scratch: &mut Vec<u8>,
        max_encoded_bytes: usize,
    ) -> Result<(), BloomBuildError> {
        let needed = cf
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(key.len()))
            .ok_or(BloomBuildError::ArithmeticOverflow)?;
        if needed > max_encoded_bytes {
            return Err(BloomBuildError::LimitExceeded);
        }
        let capacity_limit = max_encoded_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(64))
            .ok_or(BloomBuildError::ArithmeticOverflow)?;
        if scratch.capacity() > capacity_limit {
            return Err(BloomBuildError::LimitExceeded);
        }
        if scratch.capacity() < needed {
            scratch
                .try_reserve_exact(needed.saturating_sub(scratch.len()))
                .map_err(|_| BloomBuildError::AllocationFailed)?;
            if scratch.capacity() > capacity_limit {
                return Err(BloomBuildError::LimitExceeded);
            }
        }
        scratch.clear();
        scratch.extend_from_slice(cf.as_bytes());
        scratch.push(0);
        scratch.extend_from_slice(key);
        self.insert(scratch);
        Ok(())
    }

    pub fn insert(&mut self, key: &[u8]) {
        let (h1, h2) = hashes(key);
        for i in 0..self.hash_count {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.bit_count;
            self.bits[(bit / 64) as usize] |= 1_u64 << (bit % 64);
        }
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        let (h1, h2) = hashes(key);
        for i in 0..self.hash_count {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.bit_count;
            if self.bits[(bit / 64) as usize] & (1_u64 << (bit % 64)) == 0 {
                return false;
            }
        }
        true
    }
}

impl PartitionedBloomFilter {
    pub fn new(prefix_len: usize, expected_items: usize, partition_count: usize) -> Self {
        let count = partition_count.max(1);
        let mut partitions = Vec::with_capacity(count);
        for _ in 0..count {
            partitions.push(BloomFilter::with_expected_items(expected_items / count + 1));
        }
        Self {
            partitions,
            prefix_len,
        }
    }

    pub fn insert(&mut self, key: &[u8]) {
        let partition = self.partition_for_key(key);
        self.partitions[partition].insert(key);
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        let partition = self.partition_for_key(key);
        self.partitions[partition].may_contain(key)
    }

    fn partition_for_key(&self, key: &[u8]) -> usize {
        if self.partitions.len() == 1 {
            return 0;
        }
        let prefix = &key[..key.len().min(self.prefix_len.max(1))];
        let hash = blake3::hash(prefix);
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[..8]);
        (u64::from_le_bytes(bytes) as usize) % self.partitions.len()
    }
}

pub fn bloom_key(cf: &str, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cf.len() + 1 + key.len());
    out.extend_from_slice(cf.as_bytes());
    out.push(0);
    out.extend_from_slice(key);
    out
}

fn hashes(key: &[u8]) -> (u64, u64) {
    let hash = blake3::hash(key);
    let bytes = hash.as_bytes();
    let mut left = [0_u8; 8];
    let mut right = [0_u8; 8];
    left.copy_from_slice(&bytes[..8]);
    right.copy_from_slice(&bytes[8..16]);
    let h1 = u64::from_le_bytes(left);
    let h2 = u64::from_le_bytes(right) | 1;
    (h1, h2)
}

#[cfg(test)]
mod tests {
    use super::{BloomBuildError, BloomFilter, bloom_key};

    #[test]
    fn bloom_rejects_absent_key() {
        let mut bloom = BloomFilter::with_expected_items(8);
        bloom.insert(&bloom_key("default", b"present"));
        assert!(bloom.may_contain(&bloom_key("default", b"present")));
        assert!(!bloom.may_contain(&bloom_key("default", b"absent")));
    }

    #[test]
    fn observed_bloom_preserves_writer_shape_and_wire_bits() {
        const MAX_OBSERVED_ROWS: usize = 1_048_576 / 17;
        for count in [0, 1, 8, 63, 64, MAX_OBSERVED_ROWS] {
            let mut observed =
                BloomFilter::try_with_observed_items(count, MAX_OBSERVED_ROWS).unwrap();
            let mut writer = BloomFilter::with_expected_items(count);
            assert_eq!(observed, writer);
            let mut scratch = Vec::new();
            for (cf, key) in [
                ("default", &b"present"[..]),
                ("__praxor_record_catalog_v1", &b"\0"[..]),
            ] {
                observed
                    .try_insert_parts(cf, key, &mut scratch, 1_048_576)
                    .unwrap();
                writer.insert(&bloom_key(cf, key));
                assert_eq!(observed, writer);
            }
            assert!(scratch.capacity() <= 2 * 1_048_576 + 64);
        }
        let empty = BloomFilter::try_with_observed_items(0, MAX_OBSERVED_ROWS).unwrap();
        assert_eq!(
            (empty.bit_count, empty.bits.len(), empty.hash_count),
            (16, 1, 7)
        );
        let maximum =
            BloomFilter::try_with_observed_items(MAX_OBSERVED_ROWS, MAX_OBSERVED_ROWS).unwrap();
        assert_eq!((maximum.bit_count, maximum.bits.len()), (1_048_576, 16_384));
        assert!(maximum.bits.capacity() * std::mem::size_of::<u64>() <= 262_272);
    }

    #[test]
    fn observed_bloom_rejects_limits_and_overflow_without_mutation() {
        const MAX_OBSERVED_ROWS: usize = 1_048_576 / 17;
        assert_eq!(
            BloomFilter::try_with_observed_items(MAX_OBSERVED_ROWS + 1, MAX_OBSERVED_ROWS),
            Err(BloomBuildError::LimitExceeded)
        );
        assert_eq!(
            BloomFilter::try_with_observed_items(usize::MAX, usize::MAX),
            Err(BloomBuildError::ArithmeticOverflow)
        );
        let mut filter = BloomFilter::try_with_observed_items(1, 1).unwrap();
        let unchanged = filter.clone();
        let mut scratch = vec![0xaa];
        assert_eq!(
            filter.try_insert_parts("default", b"present", &mut scratch, 4),
            Err(BloomBuildError::LimitExceeded)
        );
        assert_eq!(filter, unchanged);
        assert_eq!(scratch, vec![0xaa]);
        assert_eq!(
            filter.try_insert_parts("", b"", &mut scratch, usize::MAX),
            Err(BloomBuildError::ArithmeticOverflow)
        );
        assert_eq!(filter, unchanged);
        assert_eq!(scratch, vec![0xaa]);
    }
}
