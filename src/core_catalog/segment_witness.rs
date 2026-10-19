//! Provisional, read-only evidence for every physical v4 segment row.
//!
//! No caller may turn these observations into an owner proof until the later
//! protected-copy, installed-relation, and WAL-history proofs are complete.

use crate::config::Compression;
use crate::disk::DiskLayout;
use crate::errors::{PraxisError, Result};
use crate::io::{BinaryReader, crc32c};
use crate::manifest::{Manifest, SegmentMetadata};
use crate::segments::BloomFilter;
use crate::segments::bloom::BloomBuildError;
use crate::segments::format::{SEGMENT_FOOTER_MAGIC, SEGMENT_MAGIC, SEGMENT_VERSION};
use crate::types::ValuePointer;
use crate::wal::catalog_witness::{
    PhysicalWitnessBudget, clone_witness_path, path_charge, physical_set_charge, vector_charge,
};
use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::Hash;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use zstd::zstd_safe::zstd_sys as zstd_ffi;

const MAX_SEGMENT_FILES: usize = 4_096;
const MAX_SEGMENT_LEVELS: usize = 4_096;
const MAX_ROOT_ENCODED_BYTES: usize = 65_536;
const MAX_LITERAL_SEGMENT_BYTES: usize = 1_048_576;
const MAX_LITERAL_ROWS: usize = MAX_LITERAL_SEGMENT_BYTES / 17;
const SEGMENT_HEADER_BYTES: usize = 21;
const SEGMENT_TRAILER_BYTES: usize = 12;
const BLOCK_HEADER_BYTES: usize = 12;
const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Private proof policy for compressed files only. Literal admission is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // The bounded stream scanner consumes the remaining fields in the next cut.
pub(super) struct ProofProfile {
    pub(super) max_physical_file_bytes: u64,
    pub(super) max_physical_visit_bytes: u64,
    pub(super) max_encoded_block_bytes: u64,
    pub(super) max_decoded_block_bytes: u64,
    pub(super) max_footer_bytes: u64,
    pub(super) max_decoded_file_bytes: u64,
    pub(super) max_decoded_visit_bytes: u64,
    pub(super) max_blocks_file: u64,
    pub(super) max_blocks_visit: u64,
    pub(super) max_rows_file: u64,
    pub(super) max_rows_visit: u64,
    pub(super) max_parser_owned_peak_bytes: usize,
    pub(super) max_zstd_native_workspace_bytes: usize,
}

pub(super) const PRODUCTION_COMPRESSED_PROOF_PROFILE: ProofProfile = ProofProfile {
    max_physical_file_bytes: 128 * 1024 * 1024,
    max_physical_visit_bytes: 512 * 1024 * 1024,
    max_encoded_block_bytes: 9 * 1024 * 1024,
    max_decoded_block_bytes: 8 * 1024 * 1024,
    max_footer_bytes: 8 * 1024 * 1024,
    max_decoded_file_bytes: 256 * 1024 * 1024,
    max_decoded_visit_bytes: 1024 * 1024 * 1024,
    max_blocks_file: 65_536,
    max_blocks_visit: 131_072,
    max_rows_file: 4_194_304,
    max_rows_visit: 8_388_608,
    max_parser_owned_peak_bytes: 128 * 1024 * 1024,
    max_zstd_native_workspace_bytes: 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CompressedWorkFacts {
    pub(super) decoded_bytes: u64,
    pub(super) blocks: u64,
    pub(super) rows: u64,
}

/// One file's pass carries the prior-file baseline. Replay passes subtract
/// this file's authenticated first-pass facts instead of charging it twice.
#[derive(Clone, Copy, Debug)]
pub(super) struct CompressedPassContext {
    prior: CompressedWorkFacts,
    authenticated_file: Option<CompressedWorkFacts>,
}

impl CompressedPassContext {
    pub(super) fn require_exact_replay(
        self,
        actual: CompressedWorkFacts,
        path: &Path,
    ) -> Result<()> {
        if self
            .authenticated_file
            .is_some_and(|expected| expected != actual)
        {
            return Err(corrupt(path, "compressed v4 replay facts changed"));
        }
        Ok(())
    }
}

/// Only authenticated first-pass facts are committed to the visit totals.
pub(super) struct WorkLedger {
    profile: ProofProfile,
    compressed_physical_bytes: u64,
    accepted: CompressedWorkFacts,
}

impl WorkLedger {
    pub(super) fn new(profile: ProofProfile) -> Self {
        Self {
            profile,
            compressed_physical_bytes: 0,
            accepted: CompressedWorkFacts::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn lower_row_caps_for_test(&mut self, file: u64, visit: u64) {
        assert!(file <= self.profile.max_rows_file);
        assert!(visit <= self.profile.max_rows_visit);
        self.profile.max_rows_file = file;
        self.profile.max_rows_visit = visit;
    }

    #[allow(dead_code)] // Private diagnostics read these counters in direct tests.
    pub(super) fn compressed_physical_bytes(&self) -> u64 {
        self.compressed_physical_bytes
    }

    #[allow(dead_code)] // Private diagnostics read these counters in direct tests.
    pub(super) fn accepted(&self) -> CompressedWorkFacts {
        self.accepted
    }

    pub(super) fn first_pass(&self) -> CompressedPassContext {
        CompressedPassContext {
            prior: self.accepted,
            authenticated_file: None,
        }
    }

    pub(super) fn replay_pass(
        &self,
        authenticated_file: CompressedWorkFacts,
    ) -> Result<CompressedPassContext> {
        let prior = CompressedWorkFacts {
            decoded_bytes: self
                .accepted
                .decoded_bytes
                .checked_sub(authenticated_file.decoded_bytes)
                .ok_or_else(|| unsupported("compressed v4 replay decoded baseline underflow"))?,
            blocks: self
                .accepted
                .blocks
                .checked_sub(authenticated_file.blocks)
                .ok_or_else(|| unsupported("compressed v4 replay block baseline underflow"))?,
            rows: self
                .accepted
                .rows
                .checked_sub(authenticated_file.rows)
                .ok_or_else(|| unsupported("compressed v4 replay row baseline underflow"))?,
        };
        Ok(CompressedPassContext {
            prior,
            authenticated_file: Some(authenticated_file),
        })
    }

    fn check_pass_context(&self, pass: CompressedPassContext) -> Result<()> {
        let expected = match pass.authenticated_file {
            Some(file) => CompressedWorkFacts {
                decoded_bytes: pass
                    .prior
                    .decoded_bytes
                    .checked_add(file.decoded_bytes)
                    .ok_or_else(|| unsupported("compressed v4 replay decoded baseline overflow"))?,
                blocks: pass
                    .prior
                    .blocks
                    .checked_add(file.blocks)
                    .ok_or_else(|| unsupported("compressed v4 replay block baseline overflow"))?,
                rows: pass
                    .prior
                    .rows
                    .checked_add(file.rows)
                    .ok_or_else(|| unsupported("compressed v4 replay row baseline overflow"))?,
            },
            None => pass.prior,
        };
        if expected != self.accepted {
            return Err(unsupported("compressed v4 pass baseline changed"));
        }
        Ok(())
    }

    /// Call after opened-handle identity admission, before buffer reservation.
    pub(super) fn admit_compressed_file(&mut self, len: u64, _path: &Path) -> Result<()> {
        if len > self.profile.max_physical_file_bytes {
            return Err(unsupported(
                "compressed v4 physical file exceeds proof profile",
            ));
        }
        // Policy-counter overflow is Unsupported, before doing any file work.
        let total = self
            .compressed_physical_bytes
            .checked_add(len)
            .ok_or_else(|| unsupported("compressed v4 visit physical counter overflow"))?;
        if total > self.profile.max_physical_visit_bytes {
            return Err(unsupported(
                "compressed v4 visit physical bytes exceed proof profile",
            ));
        }
        self.compressed_physical_bytes = total;
        Ok(())
    }

    /// Preview a block claim before decoding or allocating its output.
    pub(super) fn check_next_block(
        &self,
        current: CompressedWorkFacts,
        decoded_len: u64,
        pass: CompressedPassContext,
        path: &Path,
    ) -> Result<CompressedWorkFacts> {
        self.check_pass_context(pass)?;
        if decoded_len == 0 {
            return Err(corrupt(path, "zero-length compressed v4 decoded block"));
        }
        if decoded_len > self.profile.max_decoded_block_bytes {
            return Err(unsupported(
                "compressed v4 decoded block exceeds proof profile",
            ));
        }
        let decoded_bytes = current
            .decoded_bytes
            .checked_add(decoded_len)
            .ok_or_else(|| unsupported("compressed v4 file decoded counter overflow"))?;
        let blocks = current
            .blocks
            .checked_add(1)
            .ok_or_else(|| unsupported("compressed v4 file block counter overflow"))?;
        if decoded_bytes > self.profile.max_decoded_file_bytes {
            return Err(unsupported(
                "compressed v4 file decoded bytes exceed proof profile",
            ));
        }
        if blocks > self.profile.max_blocks_file {
            return Err(unsupported(
                "compressed v4 file block count exceeds proof profile",
            ));
        }
        if let Some(first) = pass.authenticated_file {
            if decoded_bytes > first.decoded_bytes {
                return Err(unsupported(
                    "compressed v4 replay decoded bytes exceed authenticated facts",
                ));
            }
            if blocks > first.blocks {
                return Err(unsupported(
                    "compressed v4 replay block count exceeds authenticated facts",
                ));
            }
        }
        let visit_decoded = pass
            .prior
            .decoded_bytes
            .checked_add(decoded_bytes)
            .ok_or_else(|| unsupported("compressed v4 visit decoded counter overflow"))?;
        let visit_blocks = pass
            .prior
            .blocks
            .checked_add(blocks)
            .ok_or_else(|| unsupported("compressed v4 visit block counter overflow"))?;
        if visit_decoded > self.profile.max_decoded_visit_bytes {
            return Err(unsupported(
                "compressed v4 visit decoded bytes exceed proof profile",
            ));
        }
        if visit_blocks > self.profile.max_blocks_visit {
            return Err(unsupported(
                "compressed v4 visit block count exceeds proof profile",
            ));
        }
        Ok(CompressedWorkFacts {
            decoded_bytes,
            blocks,
            ..current
        })
    }

    /// Check one parsed row before cloning it or calling an observer.
    pub(super) fn check_next_row(
        &self,
        current: CompressedWorkFacts,
        pass: CompressedPassContext,
        path: &Path,
    ) -> Result<CompressedWorkFacts> {
        self.check_next_rows(current, 1, pass, path)
    }

    /// Preview an entire decoded block before a later pass can call back or
    /// allocate owned rows. The caller still accounts each parsed row.
    pub(super) fn check_next_rows(
        &self,
        current: CompressedWorkFacts,
        count: u64,
        pass: CompressedPassContext,
        _path: &Path,
    ) -> Result<CompressedWorkFacts> {
        self.check_pass_context(pass)?;
        let rows = current
            .rows
            .checked_add(count)
            .ok_or_else(|| unsupported("compressed v4 file row counter overflow"))?;
        if rows > self.profile.max_rows_file {
            return Err(unsupported(
                "compressed v4 file row count exceeds proof profile",
            ));
        }
        if pass
            .authenticated_file
            .is_some_and(|first| rows > first.rows)
        {
            return Err(unsupported(
                "compressed v4 replay exceeds authenticated row facts",
            ));
        }
        let visit_rows = pass
            .prior
            .rows
            .checked_add(rows)
            .ok_or_else(|| unsupported("compressed v4 visit row counter overflow"))?;
        if visit_rows > self.profile.max_rows_visit {
            return Err(unsupported(
                "compressed v4 visit row count exceeds proof profile",
            ));
        }
        Ok(CompressedWorkFacts { rows, ..current })
    }

    /// The caller invokes this only after its same-handle pass digest matches MANIFEST.
    pub(super) fn accept_authenticated_file(
        &mut self,
        pass: CompressedPassContext,
        facts: CompressedWorkFacts,
        _path: &Path,
    ) -> Result<()> {
        self.check_pass_context(pass)?;
        if pass.authenticated_file.is_some() {
            return Err(unsupported(
                "compressed v4 replay cannot charge visit twice",
            ));
        }
        if facts.decoded_bytes > self.profile.max_decoded_file_bytes
            || facts.blocks > self.profile.max_blocks_file
            || facts.rows > self.profile.max_rows_file
        {
            return Err(unsupported("compressed v4 file work exceeds proof profile"));
        }
        let decoded_bytes = self
            .accepted
            .decoded_bytes
            .checked_add(facts.decoded_bytes)
            .ok_or_else(|| unsupported("compressed v4 visit decoded counter overflow"))?;
        let blocks = self
            .accepted
            .blocks
            .checked_add(facts.blocks)
            .ok_or_else(|| unsupported("compressed v4 visit block counter overflow"))?;
        let rows = self
            .accepted
            .rows
            .checked_add(facts.rows)
            .ok_or_else(|| unsupported("compressed v4 visit row counter overflow"))?;
        if decoded_bytes > self.profile.max_decoded_visit_bytes
            || blocks > self.profile.max_blocks_visit
            || rows > self.profile.max_rows_visit
        {
            return Err(unsupported(
                "compressed v4 visit work exceeds proof profile",
            ));
        }
        self.accepted = CompressedWorkFacts {
            decoded_bytes,
            blocks,
            rows,
        };
        Ok(())
    }
}

/// Each slot represents one enrolled parser-owned Vec. On pinned Rust 1.99.0
/// this models requested layouts and reported Vec capacities, including
/// old/new growth overlap. The Zstd static decoder's caller-owned workspace
/// is separately charged. It excludes allocator usable-size surplus,
/// unenrolled buffers, OS commit and process RSS.
/// Re-audit the requested-layout behavior on a Rust toolchain upgrade.
/// Bloom words need 128 bytes of allowance beyond 2x logical capacity.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Additional slots are consumed by the next streaming scanner cut.
pub(super) enum ScratchSlot {
    Encoded,
    Decoded,
    Footer,
    Previous,
    BloomScratch,
    BloomBits,
    OwnedCf,
    OwnedKey,
    OwnedValue,
}

#[allow(dead_code)]
impl ScratchSlot {
    const fn index(self) -> usize {
        self as usize
    }

    fn logical_limit(self, profile: ProofProfile) -> Result<usize> {
        if matches!(self, Self::BloomBits) {
            let max_rows = usize::try_from(profile.max_rows_file)
                .map_err(|_| unsupported("compressed v4 Bloom row limit exceeds platform range"))?;
            return BloomFilter::observed_bits_len_bytes(max_rows)
                .map_err(|_| unsupported("compressed v4 Bloom shape exceeds platform range"));
        }
        let bytes = match self {
            Self::Encoded => profile.max_encoded_block_bytes,
            Self::Footer => profile.max_footer_bytes,
            Self::Decoded
            | Self::Previous
            | Self::BloomScratch
            | Self::OwnedCf
            | Self::OwnedKey
            | Self::OwnedValue => profile.max_decoded_block_bytes,
            Self::BloomBits => unreachable!("Bloom bits use their row-derived bound"),
        };
        usize::try_from(bytes)
            .map_err(|_| unsupported("compressed v4 scratch limit exceeds platform range"))
    }

    const fn allowance_overhead(self) -> usize {
        match self {
            Self::BloomBits => 128,
            _ => 64,
        }
    }
}

/// Owns the original allocation pointer and layout; static Zstd contexts
/// have no matching ZSTD_freeDCtx call.
struct StaticZstdWorkspace {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl Drop for StaticZstdWorkspace {
    fn drop(&mut self) {
        // SAFETY: pointer came from alloc with this exact layout and is owned
        // once by this workspace for its entire static-context lifetime.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

struct StaticZstdContext {
    workspace: StaticZstdWorkspace,
    context: NonNull<zstd_ffi::ZSTD_DCtx>,
}

/// A fresh native charge is refunded on allocation/init error or unwind.
struct PendingZstdCharge<'a> {
    scratch: &'a mut ScratchLedger,
    previous_live: usize,
    armed: bool,
}

impl PendingZstdCharge<'_> {
    fn install(mut self, context: StaticZstdContext) {
        self.scratch.native_zstd = Some(context);
        self.armed = false;
    }
}

impl Drop for PendingZstdCharge<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.scratch.native_zstd_bytes = 0;
            self.scratch.live_bytes = self.previous_live;
        }
    }
}

#[allow(dead_code)] // The private stream scanner will account its additional live Vecs here.
pub(super) struct ScratchLedger {
    profile: ProofProfile,
    capacities: [usize; 9],
    native_zstd: Option<StaticZstdContext>,
    native_zstd_bytes: usize,
    pending_owned_bytes: usize,
    live_bytes: usize,
    poisoned: bool,
}

#[allow(dead_code)] // Direct helper tests pin preallocation refusal and overlap accounting.
impl ScratchLedger {
    pub(super) fn new(profile: ProofProfile) -> Self {
        Self {
            profile,
            capacities: [0; 9],
            native_zstd: None,
            native_zstd_bytes: 0,
            pending_owned_bytes: 0,
            live_bytes: 0,
            poisoned: false,
        }
    }

    pub(super) fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    pub(super) fn native_zstd_bytes(&self) -> usize {
        self.native_zstd_bytes
    }

    fn check_zstd_accounting(&mut self, decoded: &Vec<u8>) -> Result<()> {
        let vec_bytes = self
            .capacities
            .iter()
            .try_fold(0_usize, |sum, capacity| sum.checked_add(*capacity));
        let expected = vec_bytes
            .and_then(|sum| sum.checked_add(self.native_zstd_bytes))
            .and_then(|sum| sum.checked_add(self.pending_owned_bytes));
        let native_valid = match self.native_zstd.as_ref() {
            None => self.native_zstd_bytes == 0,
            Some(native) => {
                self.native_zstd_bytes > 0
                    && self.native_zstd_bytes == native.workspace.layout.size()
                    && native.workspace.layout.align() == 8
                    && (native.workspace.pointer.as_ptr() as usize).is_multiple_of(8)
                    && native.context.as_ptr().cast::<u8>() == native.workspace.pointer.as_ptr()
                    && self.native_zstd_bytes <= self.profile.max_zstd_native_workspace_bytes
            }
        };
        if self.poisoned
            || self.capacities[ScratchSlot::Decoded.index()] != decoded.capacity()
            || !native_valid
            || expected != Some(self.live_bytes)
            || self.live_bytes > self.profile.max_parser_owned_peak_bytes
        {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        Ok(())
    }

    /// No allocation occurs until the native cap and parser peak are known.
    fn preflight_zstd_context(&mut self) -> Result<Option<Layout>> {
        if self.poisoned {
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        if self.native_zstd.is_some() {
            return Ok(None);
        }
        if self.native_zstd_bytes != 0 {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        let estimate = unsafe { zstd_ffi::ZSTD_estimateDCtxSize() };
        if estimate == 0 {
            return Err(unsupported(
                "compressed v4 Zstd native workspace estimate is zero",
            ));
        }
        let rounded = estimate
            .checked_add(7)
            .map(|size| size & !7)
            .ok_or_else(|| unsupported("compressed v4 Zstd native workspace size overflow"))?;
        let layout = Layout::from_size_align(rounded, 8)
            .map_err(|_| unsupported("compressed v4 Zstd native workspace layout invalid"))?;
        if layout.size() > self.profile.max_zstd_native_workspace_bytes {
            return Err(unsupported(
                "compressed v4 Zstd native workspace exceeds proof profile",
            ));
        }
        let peak = self
            .live_bytes
            .checked_add(layout.size())
            .ok_or_else(|| unsupported("compressed v4 Zstd native peak overflow"))?;
        if peak > self.profile.max_parser_owned_peak_bytes {
            return Err(unsupported(
                "compressed v4 Zstd native peak exceeds proof profile",
            ));
        }
        Ok(Some(layout))
    }

    fn ensure_zstd_context(&mut self, layout: Option<Layout>) -> Result<()> {
        let Some(layout) = layout else {
            return Ok(());
        };
        let previous_live = self.live_bytes;
        let charged_live = previous_live
            .checked_add(layout.size())
            .ok_or_else(|| unsupported("compressed v4 Zstd native peak overflow"))?;
        if self.poisoned
            || self.native_zstd.is_some()
            || self.native_zstd_bytes != 0
            || layout.size() > self.profile.max_zstd_native_workspace_bytes
            || charged_live > self.profile.max_parser_owned_peak_bytes
        {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        self.live_bytes = charged_live;
        self.native_zstd_bytes = layout.size();
        let pending = PendingZstdCharge {
            scratch: self,
            previous_live,
            armed: true,
        };
        // SAFETY: the checked layout is nonzero and 8-byte aligned. A null
        // return is handled without reserving any decoded output.
        let pointer = NonNull::new(unsafe { alloc(layout) })
            .ok_or_else(|| unsupported("compressed v4 Zstd native workspace allocation failed"))?;
        let workspace = StaticZstdWorkspace { pointer, layout };
        // SAFETY: workspace stays at its original pointer until the context
        // is dropped; pinned libzstd never reallocates a static DCtx.
        let context = NonNull::new(unsafe {
            zstd_ffi::ZSTD_initStaticDCtx(pointer.as_ptr().cast(), layout.size())
        })
        .ok_or_else(|| unsupported("compressed v4 Zstd static context initialization failed"))?;
        if context.as_ptr().cast::<u8>() != workspace.pointer.as_ptr() {
            return Err(unsupported(
                "compressed v4 Zstd static context moved workspace",
            ));
        }
        pending.install(StaticZstdContext { workspace, context });
        Ok(())
    }

    pub(super) fn release_zstd_context(&mut self) -> Result<()> {
        let Some(native) = self.native_zstd.as_ref() else {
            if self.native_zstd_bytes == 0 {
                return Ok(());
            }
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 Zstd native charge is inconsistent",
            ));
        };
        let bytes = self.native_zstd_bytes;
        let remainder = self.live_bytes.checked_sub(bytes);
        if bytes == 0
            || bytes != native.workspace.layout.size()
            || native.workspace.layout.align() != 8
            || !(native.workspace.pointer.as_ptr() as usize).is_multiple_of(8)
            || native.context.as_ptr().cast::<u8>() != native.workspace.pointer.as_ptr()
            || remainder.is_none()
        {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 Zstd native charge is inconsistent",
            ));
        }
        let owner = self.native_zstd.take().expect("validated context exists");
        self.native_zstd_bytes = 0;
        self.live_bytes = remainder.expect("validated native charge subtraction");
        drop(owner);
        Ok(())
    }

    pub(super) fn reserve_vec(
        &mut self,
        slot: ScratchSlot,
        buffer: &mut Vec<u8>,
        required_len: usize,
        path: &Path,
    ) -> Result<()> {
        if self.poisoned || self.capacities[slot.index()] != buffer.capacity() {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        let logical_limit = slot.logical_limit(self.profile)?;
        if required_len > logical_limit {
            return Err(unsupported(
                "compressed v4 scratch vector exceeds proof profile",
            ));
        }
        if buffer.capacity() >= required_len {
            return Ok(());
        }
        let allowance = logical_limit
            .checked_mul(2)
            .and_then(|size| size.checked_add(slot.allowance_overhead()))
            .ok_or_else(|| unsupported("compressed v4 scratch allowance overflow"))?;
        // Under pinned Rust 1.99.0, the old requested layout remains live
        // during growth. Precharge its reported capacity plus the full
        // allowed new requested capacity, then verify the reported result.
        let peak = self
            .live_bytes
            .checked_add(allowance)
            .ok_or_else(|| unsupported("compressed v4 scratch peak counter overflow"))?;
        if peak > self.profile.max_parser_owned_peak_bytes {
            return Err(unsupported(
                "compressed v4 scratch peak exceeds proof profile",
            ));
        }
        let old_capacity = buffer.capacity();
        let additional = required_len
            .checked_sub(buffer.len())
            .ok_or_else(|| corrupt(path, "compressed v4 scratch length exceeds request"))?;
        if buffer.try_reserve_exact(additional).is_err() {
            self.poisoned = true;
            return Err(corrupt(path, "compressed v4 scratch allocation failed"));
        }
        let new_capacity = buffer.capacity();
        // A successful allocator call may increase capacity even when a
        // later policy check rejects it. Retain that actual charge and poison
        // the ledger so the caller must drop its scratch/output pair.
        self.capacities[slot.index()] = new_capacity;
        let live_bytes = self
            .live_bytes
            .checked_sub(old_capacity)
            .and_then(|bytes| bytes.checked_add(new_capacity));
        self.live_bytes = live_bytes.unwrap_or(usize::MAX);
        let Some(live_bytes) = live_bytes else {
            self.poisoned = true;
            return Err(unsupported("compressed v4 scratch live counter overflow"));
        };
        if new_capacity > allowance {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch allocation exceeds proof profile",
            ));
        }
        if live_bytes > self.profile.max_parser_owned_peak_bytes {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch live bytes exceed proof profile",
            ));
        }
        Ok(())
    }

    /// Charge the maximum permitted Vec<u64> layout before the hidden Bloom
    /// allocation, then retain only its reported live capacity. The full
    /// allowance overlaps every parser buffer already enrolled here.
    pub(super) fn reserve_observed_bloom(
        &mut self,
        observed_rows: u64,
        path: &Path,
    ) -> Result<BloomFilter> {
        let slot = ScratchSlot::BloomBits.index();
        if self.poisoned || self.capacities[slot] != 0 {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 Bloom scratch accounting is inconsistent",
            ));
        }
        let rows = usize::try_from(observed_rows)
            .map_err(|_| unsupported("compressed v4 Bloom rows exceed platform range"))?;
        let max_rows = usize::try_from(self.profile.max_rows_file)
            .map_err(|_| unsupported("compressed v4 Bloom row limit exceeds platform range"))?;
        if rows > max_rows {
            return Err(unsupported("compressed v4 Bloom rows exceed proof profile"));
        }
        let allowance = BloomFilter::observed_bits_capacity_limit_bytes(max_rows)
            .map_err(|_| unsupported("compressed v4 Bloom shape exceeds platform range"))?;
        let peak = self
            .live_bytes
            .checked_add(allowance)
            .ok_or_else(|| unsupported("compressed v4 Bloom peak counter overflow"))?;
        if peak > self.profile.max_parser_owned_peak_bytes {
            return Err(unsupported(
                "compressed v4 Bloom peak exceeds proof profile",
            ));
        }
        self.capacities[slot] = allowance;
        self.live_bytes = peak;
        let built = BloomFilter::try_with_observed_items(rows, max_rows);
        let bloom = match built {
            Ok(bloom) => bloom,
            Err(error) => {
                self.capacities[slot] = 0;
                self.live_bytes -= allowance;
                return Err(match error {
                    BloomBuildError::AllocationFailed => {
                        corrupt(path, "compressed v4 Bloom allocation failed")
                    }
                    _ => unsupported("compressed v4 Bloom shape exceeds proof profile"),
                });
            }
        };
        let actual = bloom.observed_bits_capacity_bytes().unwrap_or(usize::MAX);
        if actual > allowance {
            drop(bloom);
            self.capacities[slot] = 0;
            self.live_bytes -= allowance;
            return Err(unsupported(
                "compressed v4 Bloom capacity exceeds proof profile",
            ));
        }
        self.capacities[slot] = actual;
        self.live_bytes -= allowance - actual;
        Ok(bloom)
    }

    pub(super) fn release_observed_bloom(
        &mut self,
        bloom: BloomFilter,
        _path: &Path,
    ) -> Result<()> {
        let slot = ScratchSlot::BloomBits.index();
        let actual = bloom.observed_bits_capacity_bytes().unwrap_or(usize::MAX);
        if self.poisoned || self.capacities[slot] != actual || self.live_bytes < actual {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 Bloom scratch accounting is inconsistent",
            ));
        }
        drop(bloom);
        self.capacities[slot] = 0;
        self.live_bytes -= actual;
        Ok(())
    }

    fn release_vec(&mut self, slot: ScratchSlot, buffer: Vec<u8>) -> Result<()> {
        let capacity = buffer.capacity();
        if self.poisoned || self.capacities[slot.index()] != capacity || self.live_bytes < capacity
        {
            self.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        drop(buffer);
        self.capacities[slot.index()] = 0;
        self.live_bytes -= capacity;
        Ok(())
    }
}

pub(super) struct BlockFrame<'a> {
    pub(super) codec: Compression,
    pub(super) encoded: &'a [u8],
    pub(super) checksum: u32,
    pub(super) decoded_len: u64,
}

/// Bounded reusable block decoder for one enrolled output Vec. The caller
/// must separately enroll its encoded/footer/row buffers. This helper does
/// not authenticate a file digest. Visitor callbacks remain fenced.
#[allow(dead_code)]
pub(super) fn decode_bounded_block(
    frame: BlockFrame<'_>,
    work: &WorkLedger,
    current: CompressedWorkFacts,
    pass: CompressedPassContext,
    decoded: &mut Vec<u8>,
    scratch: &mut ScratchLedger,
    path: &Path,
) -> Result<CompressedWorkFacts> {
    if frame.codec == Compression::Zstd {
        return decode_bounded_zstd_block(frame, work, current, pass, decoded, scratch, path);
    }
    if frame.codec != Compression::Lz4 {
        return Err(unsupported("compressed v4 block codec is not supported"));
    }
    if scratch.profile != work.profile {
        return Err(unsupported(
            "compressed v4 scratch and work profiles disagree",
        ));
    }
    let next = work.check_next_block(current, frame.decoded_len, pass, path)?;
    if frame.encoded.len() as u64 > work.profile.max_encoded_block_bytes {
        return Err(unsupported(
            "compressed v4 encoded block exceeds proof profile",
        ));
    }
    if frame.encoded.is_empty() {
        return Err(corrupt(path, "empty compressed v4 encoded block"));
    }
    if crc32c(frame.encoded) != frame.checksum {
        return Err(corrupt(path, "compressed v4 block checksum mismatch"));
    }
    let prefix = frame
        .encoded
        .get(..4)
        .ok_or_else(|| corrupt(path, "missing compressed v4 LZ4 size prefix"))?;
    if u64::from(u32::from_le_bytes(
        prefix.try_into().expect("four-byte prefix"),
    )) != frame.decoded_len
    {
        return Err(corrupt(
            path,
            "compressed v4 LZ4 inner and outer lengths disagree",
        ));
    }
    let target = usize::try_from(frame.decoded_len)
        .map_err(|_| unsupported("compressed v4 decoded block exceeds platform range"))?;
    decoded.clear();
    scratch.reserve_vec(ScratchSlot::Decoded, decoded, target, path)?;
    decoded.resize(target, 0);
    let result = lz4_flex::block::decompress_into(&frame.encoded[4..], decoded.as_mut_slice());
    match result {
        Ok(written) if written == target => Ok(next),
        _ => {
            decoded.clear();
            Err(corrupt(path, "invalid compressed v4 LZ4 block"))
        }
    }
}

/// Private single-frame Zstd decoder. Its native context is caller-owned,
/// charged to ScratchLedger, and never creates owned rows or callbacks.
fn decode_bounded_zstd_block(
    frame: BlockFrame<'_>,
    work: &WorkLedger,
    current: CompressedWorkFacts,
    pass: CompressedPassContext,
    decoded: &mut Vec<u8>,
    scratch: &mut ScratchLedger,
    path: &Path,
) -> Result<CompressedWorkFacts> {
    // A second block must never expose bytes from a previously successful
    // decode if any of the following fallible checks rejects it.
    decoded.clear();
    let result = (|| {
        if scratch.profile != work.profile {
            return Err(unsupported(
                "compressed v4 scratch and work profiles disagree",
            ));
        }
        scratch.check_zstd_accounting(decoded)?;
        let next = work.check_next_block(current, frame.decoded_len, pass, path)?;
        let encoded_len = u64::try_from(frame.encoded.len())
            .map_err(|_| unsupported("compressed v4 encoded length exceeds platform range"))?;
        if encoded_len > work.profile.max_encoded_block_bytes {
            return Err(unsupported(
                "compressed v4 encoded block exceeds proof profile",
            ));
        }
        if frame.encoded.is_empty() {
            return Err(corrupt(path, "empty compressed v4 encoded block"));
        }
        if crc32c(frame.encoded) != frame.checksum {
            return Err(corrupt(path, "compressed v4 block checksum mismatch"));
        }
        if frame.encoded.get(..4) != Some(&[0x28, 0xb5, 0x2f, 0xfd][..]) {
            return Err(corrupt(
                path,
                "compressed v4 Zstd standard frame magic missing",
            ));
        }

        let mut header = std::mem::MaybeUninit::<zstd_ffi::ZSTD_FrameHeader>::uninit();
        // SAFETY: the encoded slice is live and immutable through this call;
        // pinned libzstd fills the header only when the result is zero.
        let header_status = unsafe {
            zstd_ffi::ZSTD_getFrameHeader(
                header.as_mut_ptr(),
                frame.encoded.as_ptr().cast(),
                frame.encoded.len(),
            )
        };
        if unsafe { zstd_ffi::ZSTD_isError(header_status) } != 0 || header_status != 0 {
            return Err(corrupt(path, "invalid compressed v4 Zstd frame header"));
        }
        // SAFETY: ZSTD_getFrameHeader returned exactly zero above.
        let header = unsafe { header.assume_init() };
        if header.frameType != zstd_ffi::ZSTD_FrameType_e::ZSTD_frame {
            return Err(corrupt(path, "compressed v4 Zstd frame is not ordinary"));
        }
        if header.frameContentSize == u64::MAX {
            return Err(unsupported("compressed v4 Zstd content size is unknown"));
        }
        if header.frameContentSize == u64::MAX - 1 {
            return Err(corrupt(path, "invalid compressed v4 Zstd content size"));
        }
        if header.frameContentSize > work.profile.max_decoded_block_bytes {
            return Err(unsupported(
                "compressed v4 Zstd content size exceeds proof profile",
            ));
        }
        if header.windowSize > work.profile.max_decoded_block_bytes {
            return Err(unsupported(
                "compressed v4 Zstd window exceeds proof profile",
            ));
        }
        if header.dictID != 0 {
            return Err(unsupported(
                "compressed v4 Zstd dictionary ID is not supported",
            ));
        }
        if header.frameContentSize != frame.decoded_len {
            return Err(corrupt(
                path,
                "compressed v4 Zstd inner and outer lengths disagree",
            ));
        }
        // SAFETY: the source is a live immutable slice; the pinned API reads
        // at most its supplied length to locate the first frame boundary.
        let first_frame_size = unsafe {
            zstd_ffi::ZSTD_findFrameCompressedSize(
                frame.encoded.as_ptr().cast(),
                frame.encoded.len(),
            )
        };
        if unsafe { zstd_ffi::ZSTD_isError(first_frame_size) } != 0
            || first_frame_size != frame.encoded.len()
        {
            return Err(corrupt(
                path,
                "compressed v4 Zstd block is not one complete frame",
            ));
        }

        let target = usize::try_from(frame.decoded_len)
            .map_err(|_| unsupported("compressed v4 decoded block exceeds platform range"))?;
        let layout = scratch.preflight_zstd_context()?;
        scratch.ensure_zstd_context(layout)?;
        scratch.reserve_vec(ScratchSlot::Decoded, decoded, target, path)?;
        decoded.resize(target, 0);
        let native = scratch
            .native_zstd
            .as_ref()
            .ok_or_else(|| unsupported("compressed v4 Zstd native context is missing"))?;
        // SAFETY: the static context owns an aligned, fixed workspace for
        // this call; src/dst slices are disjoint and have checked lengths.
        let written = unsafe {
            zstd_ffi::ZSTD_decompressDCtx(
                native.context.as_ptr(),
                decoded.as_mut_ptr().cast(),
                target,
                frame.encoded.as_ptr().cast(),
                frame.encoded.len(),
            )
        };
        if unsafe { zstd_ffi::ZSTD_isError(written) } != 0 {
            let code = unsafe { zstd_ffi::ZSTD_getErrorCode(written) };
            if matches!(
                code,
                zstd_ffi::ZSTD_ErrorCode::ZSTD_error_memory_allocation
                    | zstd_ffi::ZSTD_ErrorCode::ZSTD_error_workSpace_tooSmall
            ) {
                return Err(unsupported("compressed v4 Zstd static workspace exhausted"));
            }
            return Err(corrupt(path, "invalid compressed v4 Zstd block"));
        }
        if written != target {
            return Err(corrupt(path, "compressed v4 Zstd decoded length mismatch"));
        }
        Ok(next)
    })();
    if result.is_err() {
        decoded.clear();
        scratch.release_zstd_context()?;
    }
    result
}

/// This position is from the original, unsorted MANIFEST segment vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SegmentSource {
    pub(crate) level: u32,
    pub(crate) id: u64,
    pub(crate) manifest_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedRole {
    Meta,
    Payload,
    State,
    Index,
    Catalog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalRowClass {
    BoundProtected(ProtectedRole),
    ReservedUnbound,
    Other,
}

/// This retains the wire tag, including unresolved pointer expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObservedSegmentValue {
    Put(Vec<u8>),
    Delete,
    Pointer {
        pointer: ValuePointer,
        expires_at_ms: Option<u64>,
    },
    PutWithExpiry {
        value: Vec<u8>,
        expires_at_ms: u64,
    },
    Merge(Vec<u8>),
}

/// All fields are owned; no borrowed bytes can outlive a file buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedSegmentRow {
    pub(crate) source: SegmentSource,
    pub(crate) block_offset: u64,
    /// Zero-based position within this block.
    pub(crate) row_ordinal: u32,
    pub(crate) classification: PhysicalRowClass,
    pub(crate) cf: String,
    pub(crate) key: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) value: ObservedSegmentValue,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SegmentPhysicalId {
    pub(crate) volume: u64,
    pub(crate) file: [u8; 16],
}

/// Witnesses are only candidates until a complete final namespace recheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentFileWitness {
    pub(crate) source: SegmentSource,
    pub(crate) path: PathBuf,
    pub(crate) identity: SegmentPhysicalId,
    pub(crate) len: u64,
    pub(crate) digest: blake3::Hash,
    pub(crate) observed_rows: u64,
}

struct SegmentLocator {
    source: SegmentSource,
    path: PathBuf,
    witness_path: Option<PathBuf>,
    identity: Option<SegmentPhysicalId>,
    rechecked: bool,
}

struct SegmentInventory {
    locators: Vec<SegmentLocator>,
    witnesses: Vec<SegmentFileWitness>,
    retained_witness_bytes: usize,
}

fn corrupt(path: &Path, reason: &str) -> PraxisError {
    PraxisError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn budget_error(path: &Path) -> PraxisError {
    corrupt(path, "v4 segment physical witness metadata budget exceeded")
}

fn checked_double(path: &Path, count: usize) -> Result<usize> {
    count.checked_mul(2).ok_or_else(|| budget_error(path))
}

/// Own the witness-budget debit for the entire physical attempt, including
/// inventory and callbacks. The exclusively borrowed budget cannot be changed
/// without updating this tally while the guard is armed.
struct WitnessAttempt<'budget, 'root> {
    budget: &'budget mut PhysicalWitnessBudget,
    root: &'root Path,
    charged: usize,
    armed: bool,
}

impl<'budget, 'root> WitnessAttempt<'budget, 'root> {
    fn new(root: &'root Path, budget: &'budget mut PhysicalWitnessBudget) -> Self {
        Self {
            budget,
            root,
            charged: 0,
            armed: true,
        }
    }

    fn charged(&self) -> usize {
        self.charged
    }

    fn charge(&mut self, path: &Path, bytes: usize) -> Result<()> {
        let total = self
            .charged
            .checked_add(bytes)
            .ok_or_else(|| budget_error(path))?;
        self.budget.charge(path, bytes)?;
        self.charged = total;
        Ok(())
    }

    fn release(&mut self, path: &Path, bytes: usize) -> Result<()> {
        let total = self
            .charged
            .checked_sub(bytes)
            .ok_or_else(|| budget_error(path))?;
        self.budget.release(path, bytes)?;
        self.charged = total;
        Ok(())
    }

    /// The returned witness vector takes over this still-live debit. Only the
    /// caller's discard path may release it after those witnesses are dropped.
    fn transfer_retained(&mut self, expected: usize) -> Result<()> {
        if self.charged != expected {
            return Err(budget_error(self.root));
        }
        self.charged = 0;
        self.armed = false;
        Ok(())
    }
}

impl Drop for WitnessAttempt<'_, '_> {
    fn drop(&mut self) {
        if self.armed && self.charged != 0 {
            // No other mutable budget borrower exists, so underflow here is an
            // internal invariant failure. Never panic while unwinding.
            if self.budget.release(self.root, self.charged).is_err() {
                std::process::abort();
            }
        }
    }
}

fn reserved_vec<T>(
    count: usize,
    path: &Path,
    attempt: &mut WitnessAttempt<'_, '_>,
) -> Result<(Vec<T>, usize)> {
    let allowance = vector_charge::<T>(path, checked_double(path, count)?)?;
    attempt.charge(path, allowance)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| corrupt(path, "v4 segment metadata budget reservation failed"))?;
    if vector_charge::<T>(path, values.capacity())? > allowance {
        return Err(budget_error(path));
    }
    Ok((values, allowance))
}

fn reserved_set<T: Eq + Hash>(
    count: usize,
    path: &Path,
    attempt: &mut WitnessAttempt<'_, '_>,
) -> Result<(HashSet<T>, usize)> {
    let prospective = count
        .checked_mul(4)
        .map(|count| count.max(16))
        .ok_or_else(|| budget_error(path))?;
    let allowance = physical_set_charge::<T>(path, prospective)?;
    attempt.charge(path, allowance)?;
    let mut values = HashSet::new();
    values
        .try_reserve(count)
        .map_err(|_| corrupt(path, "v4 segment metadata budget reservation failed"))?;
    if physical_set_charge::<T>(path, values.capacity())? > allowance {
        return Err(budget_error(path));
    }
    Ok((values, allowance))
}

fn check_real(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(corrupt(ancestor, "v4 segment path crosses a symbolic link"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(corrupt(ancestor, "v4 segment path crosses a reparse point"));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn physical_id(file: &File, path: &Path) -> Result<SegmentPhysicalId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx,
    };

    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut links = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut links) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if links.nNumberOfLinks != 1 {
        return Err(corrupt(path, "v4 segment has an external hardlink alias"));
    }
    Ok(SegmentPhysicalId {
        volume: info.VolumeSerialNumber,
        file: info.FileId.Identifier,
    })
}

#[cfg(unix)]
pub(super) fn physical_id(file: &File, path: &Path) -> Result<SegmentPhysicalId> {
    use std::os::unix::fs::MetadataExt;

    let meta = file.metadata()?;
    if meta.nlink() != 1 {
        return Err(corrupt(path, "v4 segment has an external hardlink alias"));
    }
    let mut id = [0; 16];
    id[..8].copy_from_slice(&meta.ino().to_le_bytes());
    Ok(SegmentPhysicalId {
        volume: meta.dev(),
        file: id,
    })
}

#[cfg(not(any(unix, windows)))]
compile_error!("v4 segment witnesses require opened-handle physical identity");

fn parse_level(path: &Path) -> Result<u32> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "invalid v4 segment level name"))?;
    let level: u32 = name
        .parse()
        .map_err(|_| corrupt(path, "invalid v4 segment level name"))?;
    if level.to_string() != name {
        return Err(corrupt(path, "noncanonical v4 segment level name"));
    }
    Ok(level)
}

fn parse_segment_id(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| corrupt(path, "invalid v4 segment file name"))?;
    let digits = name
        .strip_suffix(".tseg")
        .filter(|digits| digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| corrupt(path, "invalid v4 segment file name"))?;
    let id: u64 = digits
        .parse()
        .map_err(|_| corrupt(path, "v4 segment id overflows u64"))?;
    if id == 0 {
        return Err(corrupt(path, "zero v4 segment id"));
    }
    Ok(id)
}

fn inventory(
    root: &Path,
    manifest: &Manifest,
    attempt: &mut WitnessAttempt<'_, '_>,
) -> Result<SegmentInventory> {
    if root.as_os_str().as_encoded_bytes().len() > MAX_ROOT_ENCODED_BYTES || root.to_str().is_none()
    {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 segment root path exceeds the private proof profile",
        });
    }
    if manifest.format_version != 4 {
        return Err(PraxisError::UnsupportedCatalogFeature {
            feature: "v4 segment visitor requires a strict v4 manifest",
        });
    }
    manifest.validate_v4(&root.join("MANIFEST"))?;
    if manifest.segments.len() > MAX_SEGMENT_FILES {
        return Err(corrupt(root, "v4 segment listed-file limit exceeded"));
    }

    (|| -> Result<SegmentInventory> {
        let layout = DiskLayout::at(root);
        let segment_root = layout.segment_root();
        check_real(&segment_root)?;
        if !fs::symlink_metadata(&segment_root)?.is_dir() {
            return Err(corrupt(&segment_root, "v4 segment root is not a directory"));
        }

        let count = manifest.segments.len();
        let (mut locators, _) = reserved_vec::<SegmentLocator>(count, root, attempt)?;
        let (mut global_ids, global_set_charge) = reserved_set::<u64>(count, root, attempt)?;
        for (manifest_ordinal, meta) in manifest.segments.iter().enumerate() {
            if meta.id == 0 || !global_ids.insert(meta.id) {
                return Err(corrupt(root, "duplicate or zero v4 segment global id"));
            }
            let path = layout.segment_path(meta.level, meta.id);
            let encoded = path
                .to_str()
                .ok_or(PraxisError::UnsupportedCatalogFeature {
                    feature: "v4 segment path is not representable as UTF-8",
                })?;
            if meta.path != encoded {
                return Err(corrupt(&path, "noncanonical v4 segment MANIFEST path"));
            }
            let path_bytes = path_charge(&path)?;
            if path.capacity() > path_bytes {
                return Err(budget_error(&path));
            }
            attempt.charge(&path, path_bytes)?;
            locators.push(SegmentLocator {
                source: SegmentSource {
                    level: meta.level,
                    id: meta.id,
                    manifest_ordinal,
                },
                path,
                witness_path: None,
                identity: None,
                rechecked: false,
            });
        }
        locators.sort_unstable_by_key(|item| (item.source.level, item.source.id));
        drop(global_ids);
        attempt.release(root, global_set_charge)?;

        let (mut seen, seen_charge) = reserved_vec::<u8>(count, root, attempt)?;
        seen.resize(count, 0);
        let (mut physical_ids, physical_set_charge) =
            reserved_set::<SegmentPhysicalId>(count, root, attempt)?;
        let mut observed = 0;
        for (levels, level_entry) in fs::read_dir(&segment_root)?.enumerate() {
            if levels == MAX_SEGMENT_LEVELS {
                return Err(corrupt(
                    &segment_root,
                    "v4 segment level-entry limit exceeded",
                ));
            }
            let level_path = level_entry?.path();
            check_real(&level_path)?;
            if !fs::symlink_metadata(&level_path)?.is_dir() {
                return Err(corrupt(
                    &level_path,
                    "v4 segment level entry is not a directory",
                ));
            }
            let level = parse_level(&level_path)?;
            for file_entry in fs::read_dir(&level_path)? {
                if observed == MAX_SEGMENT_FILES {
                    return Err(corrupt(
                        &level_path,
                        "v4 segment observed-file limit exceeded",
                    ));
                }
                observed += 1;
                let path = file_entry?.path();
                check_real(&path)?;
                if !fs::symlink_metadata(&path)?.is_file() {
                    return Err(corrupt(&path, "v4 segment entry is not a regular file"));
                }
                let id = parse_segment_id(&path)?;
                let position = locators
                    .binary_search_by_key(&(level, id), |item| (item.source.level, item.source.id))
                    .map_err(|_| corrupt(&path, "unlisted v4 segment file"))?;
                if path != locators[position].path || seen[position] != 0 {
                    return Err(corrupt(&path, "v4 segment path is aliased or repeated"));
                }
                let file = File::open(&path)?;
                if !file.metadata()?.is_file() {
                    return Err(corrupt(&path, "v4 segment opened entry is not a file"));
                }
                let identity = physical_id(&file, &path)?;
                check_real(&path)?;
                let reopened = File::open(&path)?;
                if physical_id(&reopened, &path)? != identity {
                    return Err(corrupt(
                        &path,
                        "v4 segment identity changed during inventory",
                    ));
                }
                if !physical_ids.insert(identity) {
                    return Err(corrupt(&path, "v4 segment files alias one physical file"));
                }
                locators[position].identity = Some(identity);
                seen[position] = 1;
            }
        }
        if observed != count || seen.contains(&0) {
            return Err(corrupt(&segment_root, "listed v4 segment file is missing"));
        }

        drop(physical_ids);
        attempt.release(root, physical_set_charge)?;
        drop(seen);
        attempt.release(root, seen_charge)?;

        let (witnesses, witness_charge) = reserved_vec::<SegmentFileWitness>(count, root, attempt)?;
        let mut retained_witness_bytes = witness_charge;
        for locator in &mut locators {
            let path_bytes = path_charge(&locator.path)?;
            retained_witness_bytes = retained_witness_bytes
                .checked_add(path_bytes)
                .ok_or_else(|| budget_error(&locator.path))?;
            attempt.charge(&locator.path, path_bytes)?;
            locator.witness_path = Some(clone_witness_path(&locator.path)?);
        }
        Ok(SegmentInventory {
            locators,
            witnesses,
            retained_witness_bytes,
        })
    })()
}

#[derive(Clone, Copy)]
enum BorrowedValue<'a> {
    Put(&'a [u8]),
    Delete,
    Pointer {
        path: &'a str,
        offset: u64,
        len: u64,
        checksum: u32,
        expires_at_ms: Option<u64>,
    },
    PutWithExpiry {
        value: &'a [u8],
        expires_at_ms: u64,
    },
    Merge(&'a [u8]),
}

#[derive(Clone, Copy)]
struct BorrowedRow<'a> {
    cf: &'a str,
    key: &'a [u8],
    sequence: u64,
    value: BorrowedValue<'a>,
}

fn borrowed_row<'a>(reader: &mut BinaryReader<'a>, path: &Path) -> Result<BorrowedRow<'a>> {
    let cf = std::str::from_utf8(reader.read_len_slice()?)
        .map_err(|_| corrupt(path, "invalid v4 segment family UTF-8"))?;
    let key = reader.read_len_slice()?;
    let sequence = reader.read_u64()?;
    let value = match reader.read_u8()? {
        1 => BorrowedValue::Put(reader.read_len_slice()?),
        2 => BorrowedValue::Delete,
        tag @ (3 | 4) => {
            let expires_at_ms = if tag == 4 {
                Some(reader.read_u64()?)
            } else {
                None
            };
            let pointer_path = std::str::from_utf8(reader.read_len_slice()?)
                .map_err(|_| corrupt(path, "invalid v4 segment pointer UTF-8"))?;
            BorrowedValue::Pointer {
                path: pointer_path,
                offset: reader.read_u64()?,
                len: reader.read_u64()?,
                checksum: reader.read_u32()?,
                expires_at_ms,
            }
        }
        5 => BorrowedValue::PutWithExpiry {
            expires_at_ms: reader.read_u64()?,
            value: reader.read_len_slice()?,
        },
        6 => BorrowedValue::Merge(reader.read_len_slice()?),
        _ => return Err(corrupt(path, "unknown v4 segment value tag")),
    };
    Ok(BorrowedRow {
        cf,
        key,
        sequence,
        value,
    })
}

fn owned_bytes(bytes: &[u8], path: &Path) -> Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| corrupt(path, "v4 segment owned row allocation failed"))?;
    if owned.capacity() > MAX_LITERAL_SEGMENT_BYTES * 2 + 64 {
        return Err(corrupt(path, "v4 segment owned row allocation exceeds cap"));
    }
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn owned_string(value: &str, path: &Path) -> Result<String> {
    String::from_utf8(owned_bytes(value.as_bytes(), path)?)
        .map_err(|_| corrupt(path, "invalid v4 segment owned string"))
}

fn classify(cf: &str) -> PhysicalRowClass {
    let role = match cf {
        "__praxor_record_meta_v1" => Some(ProtectedRole::Meta),
        "__praxor_record_payload_v1" => Some(ProtectedRole::Payload),
        "__praxor_record_state_v1" => Some(ProtectedRole::State),
        "__praxor_record_index_v1" => Some(ProtectedRole::Index),
        "__praxor_record_catalog_v1" => Some(ProtectedRole::Catalog),
        _ => None,
    };
    if let Some(role) = role {
        PhysicalRowClass::BoundProtected(role)
    } else if cf.starts_with("__praxor_record_") {
        PhysicalRowClass::ReservedUnbound
    } else {
        PhysicalRowClass::Other
    }
}

fn owned_row(
    row: BorrowedRow<'_>,
    source: SegmentSource,
    block_offset: u64,
    row_ordinal: u32,
    path: &Path,
) -> Result<ObservedSegmentRow> {
    let value = match row.value {
        BorrowedValue::Put(value) => ObservedSegmentValue::Put(owned_bytes(value, path)?),
        BorrowedValue::Delete => ObservedSegmentValue::Delete,
        BorrowedValue::Pointer {
            path: pointer_path,
            offset,
            len,
            checksum,
            expires_at_ms,
        } => ObservedSegmentValue::Pointer {
            pointer: ValuePointer {
                path: owned_string(pointer_path, path)?,
                offset,
                len,
                checksum,
            },
            expires_at_ms,
        },
        BorrowedValue::PutWithExpiry {
            value,
            expires_at_ms,
        } => ObservedSegmentValue::PutWithExpiry {
            value: owned_bytes(value, path)?,
            expires_at_ms,
        },
        BorrowedValue::Merge(value) => ObservedSegmentValue::Merge(owned_bytes(value, path)?),
    };
    Ok(ObservedSegmentRow {
        source,
        block_offset,
        row_ordinal,
        classification: classify(row.cf),
        cf: owned_string(row.cf, path)?,
        key: owned_bytes(row.key, path)?,
        sequence: row.sequence,
        value,
    })
}

/// A compressed row's three destination allocations overlap the decoder
/// buffers. The guard owns their charge until the callback consumes the row;
/// a callback that keeps it must account for that retained row itself.
struct PendingOwnedRowCharge<'a> {
    scratch: &'a mut ScratchLedger,
    allowances: [usize; 3],
    charged: usize,
}

impl<'a> PendingOwnedRowCharge<'a> {
    fn new(scratch: &'a mut ScratchLedger, lengths: [usize; 3]) -> Result<Self> {
        if scratch.poisoned || scratch.pending_owned_bytes != 0 {
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        let mut allowances = [0; 3];
        let mut charged = 0_usize;
        for (index, length) in lengths.into_iter().enumerate() {
            if length as u64 > scratch.profile.max_decoded_block_bytes {
                return Err(unsupported(
                    "compressed v4 owned field exceeds proof profile",
                ));
            }
            let allowance = if length == 0 {
                0
            } else {
                length
                    .checked_mul(2)
                    .and_then(|bytes| bytes.checked_add(64))
                    .ok_or_else(|| unsupported("compressed v4 owned allowance overflow"))?
            };
            charged = charged
                .checked_add(allowance)
                .ok_or_else(|| unsupported("compressed v4 owned allowance overflow"))?;
            allowances[index] = allowance;
        }
        let peak = scratch
            .live_bytes
            .checked_add(charged)
            .ok_or_else(|| unsupported("compressed v4 owned peak overflow"))?;
        if peak > scratch.profile.max_parser_owned_peak_bytes {
            return Err(unsupported(
                "compressed v4 owned peak exceeds proof profile",
            ));
        }
        scratch.live_bytes = peak;
        scratch.pending_owned_bytes = charged;
        Ok(Self {
            scratch,
            allowances,
            charged,
        })
    }

    fn settle(&mut self, capacities: [usize; 3]) -> Result<()> {
        if capacities
            .iter()
            .zip(self.allowances)
            .any(|(actual, allowance)| *actual > allowance)
        {
            self.scratch.poisoned = true;
            return Err(unsupported(
                "compressed v4 owned allocation exceeds proof profile",
            ));
        }
        let actual = capacities
            .into_iter()
            .try_fold(0_usize, |sum, capacity| sum.checked_add(capacity));
        let Some(actual) = actual else {
            self.scratch.poisoned = true;
            return Err(unsupported("compressed v4 owned capacity overflow"));
        };
        if self.scratch.pending_owned_bytes != self.charged
            || self.scratch.live_bytes < self.charged
            || actual > self.charged
        {
            self.scratch.poisoned = true;
            return Err(unsupported(
                "compressed v4 scratch accounting is inconsistent",
            ));
        }
        self.scratch.live_bytes -= self.charged - actual;
        self.scratch.pending_owned_bytes = actual;
        self.charged = actual;
        Ok(())
    }

    fn copy(&mut self, field: usize, bytes: &[u8], path: &Path) -> Result<Vec<u8>> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| corrupt(path, "compressed v4 owned row allocation failed"))?;
        if owned.capacity() > self.allowances[field] {
            self.scratch.poisoned = true;
            return Err(unsupported(
                "compressed v4 owned allocation exceeds proof profile",
            ));
        }
        owned.extend_from_slice(bytes);
        Ok(owned)
    }
}

impl Drop for PendingOwnedRowCharge<'_> {
    fn drop(&mut self) {
        if self.scratch.pending_owned_bytes != self.charged
            || self.scratch.live_bytes < self.charged
        {
            std::process::abort();
        }
        self.scratch.pending_owned_bytes = 0;
        self.scratch.live_bytes -= self.charged;
    }
}

fn visit_bounded_owned_row(
    row: BorrowedRow<'_>,
    source: SegmentSource,
    block_offset: u64,
    row_ordinal: u32,
    scratch: &mut ScratchLedger,
    path: &Path,
    visit: &mut impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<()> {
    let value_len = match row.value {
        BorrowedValue::Put(value)
        | BorrowedValue::PutWithExpiry { value, .. }
        | BorrowedValue::Merge(value) => value.len(),
        BorrowedValue::Pointer { path, .. } => path.len(),
        BorrowedValue::Delete => 0,
    };
    let mut pending =
        PendingOwnedRowCharge::new(scratch, [row.cf.len(), row.key.len(), value_len])?;
    let cf = String::from_utf8(pending.copy(0, row.cf.as_bytes(), path)?)
        .map_err(|_| corrupt(path, "invalid compressed v4 owned family"))?;
    let key = pending.copy(1, row.key, path)?;
    let value = match row.value {
        BorrowedValue::Put(value) => ObservedSegmentValue::Put(pending.copy(2, value, path)?),
        BorrowedValue::Delete => ObservedSegmentValue::Delete,
        BorrowedValue::Pointer {
            path: pointer_path,
            offset,
            len,
            checksum,
            expires_at_ms,
        } => ObservedSegmentValue::Pointer {
            pointer: ValuePointer {
                path: String::from_utf8(pending.copy(2, pointer_path.as_bytes(), path)?)
                    .map_err(|_| corrupt(path, "invalid compressed v4 owned pointer path"))?,
                offset,
                len,
                checksum,
            },
            expires_at_ms,
        },
        BorrowedValue::PutWithExpiry {
            value,
            expires_at_ms,
        } => ObservedSegmentValue::PutWithExpiry {
            value: pending.copy(2, value, path)?,
            expires_at_ms,
        },
        BorrowedValue::Merge(value) => ObservedSegmentValue::Merge(pending.copy(2, value, path)?),
    };
    let owned = ObservedSegmentRow {
        source,
        block_offset,
        row_ordinal,
        classification: classify(row.cf),
        cf,
        key,
        sequence: row.sequence,
        value,
    };
    let value_capacity = match &owned.value {
        ObservedSegmentValue::Put(value)
        | ObservedSegmentValue::PutWithExpiry { value, .. }
        | ObservedSegmentValue::Merge(value) => value.capacity(),
        ObservedSegmentValue::Pointer { pointer, .. } => pointer.path.capacity(),
        ObservedSegmentValue::Delete => 0,
    };
    pending.settle([owned.cf.capacity(), owned.key.capacity(), value_capacity])?;
    visit(owned)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct WalkFacts<'a> {
    rows: usize,
    first_key: Option<&'a [u8]>,
    last_key: Option<&'a [u8]>,
}

fn walk_literal<'a>(
    bytes: &'a [u8],
    path: &Path,
    mut visit: impl FnMut(u64, u32, BorrowedRow<'a>) -> Result<()>,
) -> Result<WalkFacts<'a>> {
    if bytes.len() < SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES {
        return Err(corrupt(path, "short v4 segment"));
    }
    let trailer_start = bytes.len() - SEGMENT_TRAILER_BYTES;
    let mut trailer = BinaryReader::new(&bytes[trailer_start..], path);
    let footer_len = trailer.read_u32()? as usize;
    let footer_checksum = trailer.read_u32()?;
    if trailer.read_u32()? != SEGMENT_FOOTER_MAGIC {
        return Err(corrupt(path, "bad v4 segment footer magic"));
    }
    let footer_start = trailer_start
        .checked_sub(footer_len)
        .filter(|start| *start >= SEGMENT_HEADER_BYTES)
        .ok_or_else(|| corrupt(path, "v4 segment footer out of bounds"))?;
    let footer_bytes = &bytes[footer_start..trailer_start];
    if crc32c(footer_bytes) != footer_checksum {
        return Err(corrupt(path, "v4 segment footer checksum mismatch"));
    }
    let mut footer = BinaryReader::new(footer_bytes, path);
    let block_count = footer.read_u32()? as usize;
    if block_count > footer.remaining() / 24 {
        return Err(corrupt(path, "v4 segment block count exceeds footer"));
    }
    let mut previous_end = SEGMENT_HEADER_BYTES;
    let mut previous_row: Option<(&str, &[u8])> = None;
    let mut facts = WalkFacts {
        rows: 0,
        first_key: None,
        last_key: None,
    };
    for _ in 0..block_count {
        let first_key = footer.read_len_slice()?;
        let last_key = footer.read_len_slice()?;
        let offset = usize::try_from(footer.read_u64()?)
            .map_err(|_| corrupt(path, "v4 segment block offset overflows platform"))?;
        let len = usize::try_from(footer.read_u64()?)
            .map_err(|_| corrupt(path, "v4 segment block length overflows platform"))?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| corrupt(path, "v4 segment block offset overflow"))?;
        if offset != previous_end || end > footer_start || len < BLOCK_HEADER_BYTES {
            return Err(corrupt(path, "v4 segment block is not contiguous"));
        }
        let mut block = BinaryReader::new(&bytes[offset..end], path);
        let encoded_len = block.read_u32()? as usize;
        let decoded_len = block.read_u32()? as usize;
        let checksum = block.read_u32()?;
        let payload = block.read_slice(encoded_len)?;
        if block.remaining() != 0 || encoded_len != decoded_len || crc32c(payload) != checksum {
            return Err(corrupt(
                path,
                "v4 literal segment block length or checksum mismatch",
            ));
        }
        let mut rows = BinaryReader::new(payload, path);
        let row_count = rows.read_u32()? as usize;
        if row_count == 0 || row_count > rows.remaining() / 17 {
            return Err(corrupt(path, "v4 segment row count exceeds block"));
        }
        let mut block_first: Option<&[u8]> = None;
        let mut block_last: Option<&[u8]> = None;
        for row_index in 0..row_count {
            let row = borrowed_row(&mut rows, path)?;
            if let Some((cf, key)) = previous_row
                && (row.cf.as_bytes(), row.key) < (cf.as_bytes(), key)
            {
                return Err(corrupt(path, "v4 segment rows are out of writer order"));
            }
            previous_row = Some((row.cf, row.key));
            block_first.get_or_insert(row.key);
            block_last = Some(row.key);
            facts.first_key.get_or_insert(row.key);
            facts.last_key = Some(row.key);
            facts.rows = facts
                .rows
                .checked_add(1)
                .filter(|count| *count <= MAX_LITERAL_ROWS)
                .ok_or_else(|| corrupt(path, "v4 literal segment row limit exceeded"))?;
            let row_ordinal = u32::try_from(row_index)
                .map_err(|_| corrupt(path, "v4 segment row ordinal overflow"))?;
            visit(offset as u64, row_ordinal, row)?;
        }
        if rows.remaining() != 0 || block_first != Some(first_key) || block_last != Some(last_key) {
            return Err(corrupt(
                path,
                "v4 segment block key range or framing mismatch",
            ));
        }
        previous_end = end;
    }
    if footer.remaining() != 0 || previous_end != footer_start {
        return Err(corrupt(path, "unconsumed v4 segment framing bytes"));
    }
    Ok(facts)
}

fn unsupported(feature: &'static str) -> PraxisError {
    PraxisError::UnsupportedCatalogFeature { feature }
}

fn hash_exact(file: &mut File, expected_len: u64, path: &Path) -> Result<blake3::Hash> {
    let mut remaining = expected_len;
    let mut buffer = [0_u8; HASH_CHUNK_BYTES];
    let mut hasher = blake3::Hasher::new();
    while remaining != 0 {
        let amount = remaining.min(HASH_CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..amount])
            .map_err(|_| corrupt(path, "v4 segment truncated during recheck"))?;
        hasher.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 || file.metadata()?.len() != expected_len {
        return Err(corrupt(path, "v4 segment length changed during recheck"));
    }
    Ok(hasher.finalize())
}

fn capture_literal(file: &mut File, path: &Path) -> Result<(Vec<u8>, u64)> {
    let len = file.metadata()?.len();
    if len > MAX_LITERAL_SEGMENT_BYTES as u64 {
        return Err(unsupported(
            "v4 segment exceeds the 1 MiB literal proof profile",
        ));
    }
    let count = usize::try_from(len)
        .map_err(|_| corrupt(path, "v4 segment length exceeds platform range"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count)
        .map_err(|_| corrupt(path, "v4 segment capture allocation failed"))?;
    if bytes.capacity() > MAX_LITERAL_SEGMENT_BYTES * 2 + 64 {
        return Err(unsupported(
            "v4 segment capture allocation exceeds proof profile",
        ));
    }
    bytes.resize(count, 0);
    file.read_exact(&mut bytes)
        .map_err(|_| corrupt(path, "v4 segment truncated during capture"))?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 || file.metadata()?.len() != len {
        return Err(corrupt(path, "v4 segment length changed during capture"));
    }
    Ok((bytes, len))
}

/// A pass reads only from its admitted File. Every parsed byte is hashed as
/// it is consumed, so a separately timed A/B/A rewrite cannot authenticate
/// different parser input with the original MANIFEST digest.
struct CompressedPassReader<'a> {
    file: &'a mut File,
    path: &'a Path,
    expected_len: u64,
    cursor: u64,
    hasher: blake3::Hasher,
}

impl CompressedPassReader<'_> {
    fn read_hashed(&mut self, bytes: &mut [u8]) -> Result<()> {
        let end = self
            .cursor
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.expected_len)
            .ok_or_else(|| corrupt(self.path, "compressed v4 read exceeds opened length"))?;
        self.file
            .read_exact(bytes)
            .map_err(|_| corrupt(self.path, "compressed v4 truncated during pass"))?;
        self.hasher.update(bytes);
        self.cursor = end;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedLz4Pass {
    pub(super) work: CompressedWorkFacts,
    pub(super) digest: blake3::Hash,
    pub(super) len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Lz4PassProbe {
    AfterFooterPreread,
    AfterContiguousRead { digest: blake3::Hash },
}

// The Zstd passes use the same authenticated framing as LZ4, but do not yet
// grant either visitor or installed-owner authority.
#[allow(dead_code)] // Exercised by private tests; visitor admission is a later cut.
pub(super) type AuthenticatedZstdPass = AuthenticatedLz4Pass;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ZstdPassProbe {
    AfterFooterPreread,
    AfterContiguousRead {
        digest: blake3::Hash,
    },
    /// Emitted when `check_next_block` refuses a block's claims before this
    /// block reserves further encoded/output capacity or decodes. Reports the
    /// scanner's actual local capacities and native Zstd charge, which may
    /// include storage retained from earlier successful blocks. Bounded footer
    /// preread is separate.
    #[cfg(test)]
    RefusedDecodedClaimBeforeReserve {
        encoded_capacity: usize,
        decoded_capacity: usize,
        native_zstd_bytes: usize,
    },
}

/// Scanner-local events let both codecs share the authenticated byte walk
/// while keeping their existing private probe contracts separate.
#[derive(Clone, Copy)]
enum CompressedPassProbe {
    AfterFooterPreread,
    AfterContiguousRead {
        digest: blake3::Hash,
    },
    #[cfg(test)]
    RefusedDecodedClaimBeforeReserve {
        encoded_capacity: usize,
        decoded_capacity: usize,
        native_zstd_bytes: usize,
    },
}

impl CompressedPassProbe {
    fn dispatch_lz4(self, probe: &mut impl FnMut(Lz4PassProbe)) {
        match self {
            Self::AfterFooterPreread => probe(Lz4PassProbe::AfterFooterPreread),
            Self::AfterContiguousRead { digest } => {
                probe(Lz4PassProbe::AfterContiguousRead { digest });
            }
            #[cfg(test)]
            Self::RefusedDecodedClaimBeforeReserve { .. } => {}
        }
    }

    fn into_zstd(self) -> ZstdPassProbe {
        match self {
            Self::AfterFooterPreread => ZstdPassProbe::AfterFooterPreread,
            Self::AfterContiguousRead { digest } => ZstdPassProbe::AfterContiguousRead { digest },
            #[cfg(test)]
            Self::RefusedDecodedClaimBeforeReserve {
                encoded_capacity,
                decoded_capacity,
                native_zstd_bytes,
            } => ZstdPassProbe::RefusedDecodedClaimBeforeReserve {
                encoded_capacity,
                decoded_capacity,
                native_zstd_bytes,
            },
        }
    }
}

#[allow(dead_code)] // Exercised by private tests; visitor admission is a later cut.
pub(super) fn scan_zstd_pass1(
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &mut WorkLedger,
    mut probe: impl FnMut(ZstdPassProbe),
) -> Result<AuthenticatedZstdPass> {
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(path, "compressed v4 identity changed before pass"));
    }
    let len = file.metadata()?.len();
    if len < (SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES) as u64 {
        return Err(corrupt(path, "short compressed v4 segment"));
    }
    work.admit_compressed_file(len, path)?;
    let pass = work.first_pass();
    scan_compressed_opened_pass(
        &mut file,
        path,
        expected_identity,
        meta,
        work,
        pass,
        None,
        len,
        Compression::Zstd,
        |event| probe(event.into_zstd()),
    )
}

#[allow(dead_code)] // Exercised by private tests; visitor admission is a later cut.
pub(super) fn scan_zstd_pass2(
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &WorkLedger,
    first: AuthenticatedZstdPass,
    mut probe: impl FnMut(ZstdPassProbe),
) -> Result<AuthenticatedZstdPass> {
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(
            path,
            "compressed v4 identity changed before replay",
        ));
    }
    let len = file.metadata()?.len();
    if len < (SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES) as u64 {
        return Err(corrupt(path, "short compressed v4 segment"));
    }
    if len != first.len {
        return Err(corrupt(path, "compressed v4 replay length changed"));
    }
    if len > work.profile.max_physical_file_bytes {
        return Err(unsupported(
            "compressed v4 physical file exceeds proof profile",
        ));
    }
    let pass = work.replay_pass(first.work)?;
    scan_compressed_opened_pass(
        &mut file,
        path,
        expected_identity,
        meta,
        work,
        pass,
        Some(first),
        len,
        Compression::Zstd,
        |event| probe(event.into_zstd()),
    )
}

/// Callback-free first pass. Its work can be committed only after the
/// integrated digest has authenticated the parser-consumed bytes.
pub(super) fn scan_lz4_pass1(
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &mut WorkLedger,
    mut probe: impl FnMut(Lz4PassProbe),
) -> Result<AuthenticatedLz4Pass> {
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(path, "compressed v4 identity changed before pass"));
    }
    let len = file.metadata()?.len();
    if len < (SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES) as u64 {
        return Err(corrupt(path, "short compressed v4 segment"));
    }
    work.admit_compressed_file(len, path)?;
    let pass = work.first_pass();
    scan_compressed_opened_pass(
        &mut file,
        path,
        expected_identity,
        meta,
        work,
        pass,
        None,
        len,
        Compression::Lz4,
        |event| event.dispatch_lz4(&mut probe),
    )
}

/// Both codecs parse and hash every byte through their own admitted handle.
/// Replay alone builds a provisional Bloom, which cannot leave this function.
#[allow(clippy::too_many_arguments)]
fn scan_compressed_opened_pass(
    file: &mut File,
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &WorkLedger,
    pass: CompressedPassContext,
    first: Option<AuthenticatedLz4Pass>,
    len: u64,
    codec: Compression,
    mut probe: impl FnMut(CompressedPassProbe),
) -> Result<AuthenticatedLz4Pass> {
    let tag = match codec {
        Compression::Lz4 => 1,
        Compression::Zstd => 2,
        _ => return Err(unsupported("compressed v4 pass codec is not supported")),
    };
    let mut scratch = ScratchLedger::new(work.profile);
    let mut bloom = match first {
        Some(first) => Some(scratch.reserve_observed_bloom(first.work.rows, path)?),
        None => None,
    };
    let mut bloom_scratch = Vec::new();

    // The index is provisional until the later, contiguous read hashes and
    // compares every footer and trailer byte from this same opened handle.
    file.seek(SeekFrom::End(-(SEGMENT_TRAILER_BYTES as i64)))?;
    let mut trailer = [0_u8; SEGMENT_TRAILER_BYTES];
    file.read_exact(&mut trailer)
        .map_err(|_| corrupt(path, "compressed v4 trailer truncated"))?;
    let footer_len = u64::from(u32::from_le_bytes(trailer[..4].try_into().unwrap()));
    let footer_crc = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
    if u32::from_le_bytes(trailer[8..].try_into().unwrap()) != SEGMENT_FOOTER_MAGIC {
        return Err(corrupt(path, "bad compressed v4 footer magic"));
    }
    let trailer_start = len - SEGMENT_TRAILER_BYTES as u64;
    let footer_start = trailer_start
        .checked_sub(footer_len)
        .filter(|start| *start >= SEGMENT_HEADER_BYTES as u64)
        .ok_or_else(|| corrupt(path, "compressed v4 footer out of bounds"))?;
    if footer_len > work.profile.max_footer_bytes {
        return Err(unsupported("compressed v4 footer exceeds proof profile"));
    }
    let footer_len_usize = usize::try_from(footer_len)
        .map_err(|_| unsupported("compressed v4 footer exceeds platform range"))?;
    let mut footer_bytes = Vec::new();
    scratch.reserve_vec(
        ScratchSlot::Footer,
        &mut footer_bytes,
        footer_len_usize,
        path,
    )?;
    footer_bytes.resize(footer_len_usize, 0);
    file.seek(SeekFrom::Start(footer_start))?;
    file.read_exact(&mut footer_bytes)
        .map_err(|_| corrupt(path, "compressed v4 footer truncated"))?;
    if crc32c(&footer_bytes) != footer_crc {
        return Err(corrupt(path, "compressed v4 footer checksum mismatch"));
    }
    let mut footer = BinaryReader::new(&footer_bytes, path);
    let block_count = u64::from(footer.read_u32()?);
    if block_count > (footer.remaining() / 24) as u64 {
        return Err(corrupt(path, "compressed v4 block count exceeds footer"));
    }
    if block_count > work.profile.max_blocks_file
        || pass
            .prior
            .blocks
            .checked_add(block_count)
            .is_none_or(|count| count > work.profile.max_blocks_visit)
    {
        return Err(unsupported(
            "compressed v4 block count exceeds proof profile",
        ));
    }

    probe(CompressedPassProbe::AfterFooterPreread);
    file.seek(SeekFrom::Start(0))?;
    let mut reader = CompressedPassReader {
        file,
        path,
        expected_len: len,
        cursor: 0,
        hasher: blake3::Hasher::new(),
    };
    let mut header = [0_u8; SEGMENT_HEADER_BYTES];
    reader.read_hashed(&mut header)?;
    let mut header_reader = BinaryReader::new(&header, path);
    if header_reader.read_u32()? != SEGMENT_MAGIC || header_reader.read_u32()? != SEGMENT_VERSION {
        return Err(corrupt(path, "bad compressed v4 segment magic or version"));
    }
    if header_reader.read_u8()? != tag {
        let reason = if codec == Compression::Lz4 {
            "compressed v4 pass expected LZ4 tag"
        } else {
            "compressed v4 pass expected Zstd tag"
        };
        return Err(corrupt(path, reason));
    }
    if header_reader.read_u32()? != meta.level || header_reader.read_u64()? != meta.id {
        return Err(corrupt(path, "compressed v4 header level or id mismatch"));
    }
    if meta.partitioned_bloom_filter.is_some() {
        return Err(unsupported(
            "partitioned v4 segment Bloom is not yet proven",
        ));
    }

    let mut facts = CompressedWorkFacts::default();
    let mut encoded = Vec::new();
    let mut decoded = Vec::new();
    let mut previous = Vec::new();
    let mut previous_cf_len = 0;
    let mut previous_valid = false;
    let mut first_seen = false;
    let mut last_key_matches = meta.max_key.is_empty();
    for _ in 0..block_count {
        let first_key = footer.read_len_slice()?;
        let last_key = footer.read_len_slice()?;
        let offset = footer.read_u64()?;
        let block_len = footer.read_u64()?;
        let end = offset
            .checked_add(block_len)
            .ok_or_else(|| corrupt(path, "compressed v4 block offset overflow"))?;
        if offset != reader.cursor || block_len < BLOCK_HEADER_BYTES as u64 || end > footer_start {
            return Err(corrupt(path, "compressed v4 block is not contiguous"));
        }
        let mut block_header = [0_u8; BLOCK_HEADER_BYTES];
        reader.read_hashed(&mut block_header)?;
        let encoded_len = u64::from(u32::from_le_bytes(block_header[..4].try_into().unwrap()));
        let decoded_len = u64::from(u32::from_le_bytes(block_header[4..8].try_into().unwrap()));
        let checksum = u32::from_le_bytes(block_header[8..].try_into().unwrap());
        if encoded_len
            .checked_add(BLOCK_HEADER_BYTES as u64)
            .filter(|total| *total == block_len)
            .is_none()
            || encoded_len == 0
        {
            return Err(corrupt(path, "compressed v4 block length mismatch"));
        }
        if encoded_len > work.profile.max_encoded_block_bytes {
            return Err(unsupported(
                "compressed v4 encoded block exceeds proof profile",
            ));
        }
        // Refuse forged output claims before encoded or decoded allocation.
        let block_admission = work.check_next_block(facts, decoded_len, pass, path);
        #[cfg(test)]
        if block_admission.is_err() && codec == Compression::Zstd {
            probe(CompressedPassProbe::RefusedDecodedClaimBeforeReserve {
                encoded_capacity: encoded.capacity(),
                decoded_capacity: decoded.capacity(),
                native_zstd_bytes: scratch.native_zstd_bytes(),
            });
        }
        block_admission?;
        let encoded_len_usize = usize::try_from(encoded_len)
            .map_err(|_| unsupported("compressed v4 encoded block exceeds platform range"))?;
        encoded.clear();
        scratch.reserve_vec(ScratchSlot::Encoded, &mut encoded, encoded_len_usize, path)?;
        encoded.resize(encoded_len_usize, 0);
        reader.read_hashed(&mut encoded)?;
        facts = decode_bounded_block(
            BlockFrame {
                codec,
                encoded: &encoded,
                checksum,
                decoded_len,
            },
            work,
            facts,
            pass,
            &mut decoded,
            &mut scratch,
            path,
        )?;
        let mut rows = BinaryReader::new(&decoded, path);
        let row_count = u64::from(rows.read_u32()?);
        if row_count == 0 || row_count > (rows.remaining() / 17) as u64 {
            return Err(corrupt(path, "compressed v4 row count exceeds block"));
        }
        work.check_next_rows(facts, row_count, pass, path)?;
        let mut block_first = None;
        let mut block_last: Option<(&str, &[u8])> = None;
        for _ in 0..row_count {
            let row = borrowed_row(&mut rows, path)?;
            let prior = block_last.or_else(|| {
                previous_valid.then(|| {
                    let (cf, key) = previous.split_at(previous_cf_len);
                    (
                        std::str::from_utf8(cf).expect("previous family was validated"),
                        key,
                    )
                })
            });
            if prior.is_some_and(|(cf, key)| (row.cf.as_bytes(), row.key) < (cf.as_bytes(), key)) {
                return Err(corrupt(path, "compressed v4 rows are out of writer order"));
            }
            if !first_seen {
                first_seen = true;
                if row.key != meta.min_key.as_slice() {
                    return Err(corrupt(
                        path,
                        "compressed v4 first key disagrees with MANIFEST",
                    ));
                }
            }
            last_key_matches = row.key == meta.max_key.as_slice();
            block_first.get_or_insert(row.key);
            block_last = Some((row.cf, row.key));
            facts = work.check_next_row(facts, pass, path)?;
            if let Some(filter) = &mut bloom {
                let needed = row
                    .cf
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(row.key.len()))
                    .ok_or_else(|| unsupported("compressed v4 Bloom key length overflow"))?;
                scratch.reserve_vec(ScratchSlot::BloomScratch, &mut bloom_scratch, needed, path)?;
                let enrolled_capacity = bloom_scratch.capacity();
                filter
                    .try_insert_parts(
                        row.cf,
                        row.key,
                        &mut bloom_scratch,
                        ScratchSlot::BloomScratch.logical_limit(work.profile)?,
                    )
                    .map_err(|_| {
                        unsupported("compressed v4 Bloom insert exceeded proof profile")
                    })?;
                if bloom_scratch.capacity() != enrolled_capacity {
                    return Err(unsupported(
                        "compressed v4 Bloom scratch grew outside ledger",
                    ));
                }
            }
        }
        if rows.remaining() != 0
            || block_first != Some(first_key)
            || block_last.map(|(_, key)| key) != Some(last_key)
        {
            return Err(corrupt(
                path,
                "compressed v4 block key range or framing mismatch",
            ));
        }
        let (last_cf, last_key) = block_last.expect("nonempty block was checked");
        previous_cf_len = last_cf.len();
        let previous_len = previous_cf_len
            .checked_add(last_key.len())
            .ok_or_else(|| unsupported("compressed v4 prior key length overflow"))?;
        scratch.reserve_vec(ScratchSlot::Previous, &mut previous, previous_len, path)?;
        previous.clear();
        previous.extend_from_slice(last_cf.as_bytes());
        previous.extend_from_slice(last_key);
        previous_valid = true;
    }
    if footer.remaining() != 0 || reader.cursor != footer_start {
        return Err(corrupt(path, "unconsumed compressed v4 framing bytes"));
    }
    if facts.rows != meta.entries || (!first_seen && !meta.min_key.is_empty()) || !last_key_matches
    {
        return Err(corrupt(
            path,
            "compressed v4 observed count or key range mismatch",
        ));
    }

    let mut chunk = [0_u8; HASH_CHUNK_BYTES];
    for expected in footer_bytes.chunks(HASH_CHUNK_BYTES) {
        let actual = &mut chunk[..expected.len()];
        reader.read_hashed(actual)?;
        if actual != expected {
            return Err(corrupt(path, "compressed v4 footer changed during pass"));
        }
    }
    let mut reread_trailer = [0_u8; SEGMENT_TRAILER_BYTES];
    reader.read_hashed(&mut reread_trailer)?;
    if reread_trailer != trailer || reader.cursor != len {
        return Err(corrupt(path, "compressed v4 trailer changed during pass"));
    }
    let mut extra = [0_u8; 1];
    if reader.file.read(&mut extra)? != 0
        || reader.file.metadata()?.len() != len
        || physical_id(reader.file, path)? != expected_identity
    {
        return Err(corrupt(
            path,
            "compressed v4 length or identity changed during pass",
        ));
    }
    let digest = reader.hasher.finalize();
    probe(CompressedPassProbe::AfterContiguousRead { digest });
    if digest.to_hex().as_str() != meta.file_digest.as_str() {
        return Err(corrupt(
            path,
            "compressed v4 integrated pass digest mismatch",
        ));
    }
    if first.is_some_and(|first| first.digest != digest || first.len != len) {
        return Err(corrupt(
            path,
            "compressed v4 integrated replay digest or length changed",
        ));
    }
    pass.require_exact_replay(facts, path)?;
    if let Some(observed) = bloom {
        if observed != meta.bloom_filter {
            return Err(corrupt(
                path,
                "compressed v4 observed Bloom disagrees with MANIFEST",
            ));
        }
        scratch.release_observed_bloom(observed, path)?;
        scratch.release_vec(ScratchSlot::BloomScratch, bloom_scratch)?;
    }
    Ok(AuthenticatedLz4Pass {
        work: facts,
        digest,
        len,
    })
}

/// Private third pass emits provisional owned rows only. It mirrors the
/// authenticated bounded parser rather than changing the established first
/// and Bloom passes; the caller must discard its rows on any late error.
#[allow(clippy::too_many_arguments)]
fn scan_lz4_opened_owned_pass(
    file: &mut File,
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &WorkLedger,
    pass: CompressedPassContext,
    first: AuthenticatedLz4Pass,
    len: u64,
    source: SegmentSource,
    mut visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<AuthenticatedLz4Pass> {
    let mut scratch = ScratchLedger::new(work.profile);

    // The index is provisional until the later, contiguous read hashes and
    // compares every footer and trailer byte from this same opened handle.
    file.seek(SeekFrom::End(-(SEGMENT_TRAILER_BYTES as i64)))?;
    let mut trailer = [0_u8; SEGMENT_TRAILER_BYTES];
    file.read_exact(&mut trailer)
        .map_err(|_| corrupt(path, "compressed v4 trailer truncated"))?;
    let footer_len = u64::from(u32::from_le_bytes(trailer[..4].try_into().unwrap()));
    let footer_crc = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
    if u32::from_le_bytes(trailer[8..].try_into().unwrap()) != SEGMENT_FOOTER_MAGIC {
        return Err(corrupt(path, "bad compressed v4 footer magic"));
    }
    let trailer_start = len - SEGMENT_TRAILER_BYTES as u64;
    let footer_start = trailer_start
        .checked_sub(footer_len)
        .filter(|start| *start >= SEGMENT_HEADER_BYTES as u64)
        .ok_or_else(|| corrupt(path, "compressed v4 footer out of bounds"))?;
    if footer_len > work.profile.max_footer_bytes {
        return Err(unsupported("compressed v4 footer exceeds proof profile"));
    }
    let footer_len_usize = usize::try_from(footer_len)
        .map_err(|_| unsupported("compressed v4 footer exceeds platform range"))?;
    let mut footer_bytes = Vec::new();
    scratch.reserve_vec(
        ScratchSlot::Footer,
        &mut footer_bytes,
        footer_len_usize,
        path,
    )?;
    footer_bytes.resize(footer_len_usize, 0);
    file.seek(SeekFrom::Start(footer_start))?;
    file.read_exact(&mut footer_bytes)
        .map_err(|_| corrupt(path, "compressed v4 footer truncated"))?;
    if crc32c(&footer_bytes) != footer_crc {
        return Err(corrupt(path, "compressed v4 footer checksum mismatch"));
    }
    let mut footer = BinaryReader::new(&footer_bytes, path);
    let block_count = u64::from(footer.read_u32()?);
    if block_count > (footer.remaining() / 24) as u64 {
        return Err(corrupt(path, "compressed v4 block count exceeds footer"));
    }
    if block_count > work.profile.max_blocks_file
        || pass
            .prior
            .blocks
            .checked_add(block_count)
            .is_none_or(|count| count > work.profile.max_blocks_visit)
    {
        return Err(unsupported(
            "compressed v4 block count exceeds proof profile",
        ));
    }

    file.seek(SeekFrom::Start(0))?;
    let mut reader = CompressedPassReader {
        file,
        path,
        expected_len: len,
        cursor: 0,
        hasher: blake3::Hasher::new(),
    };
    let mut header = [0_u8; SEGMENT_HEADER_BYTES];
    reader.read_hashed(&mut header)?;
    let mut header_reader = BinaryReader::new(&header, path);
    if header_reader.read_u32()? != SEGMENT_MAGIC || header_reader.read_u32()? != SEGMENT_VERSION {
        return Err(corrupt(path, "bad compressed v4 segment magic or version"));
    }
    if header_reader.read_u8()? != 1 {
        return Err(corrupt(path, "compressed v4 pass expected LZ4 tag"));
    }
    if header_reader.read_u32()? != meta.level || header_reader.read_u64()? != meta.id {
        return Err(corrupt(path, "compressed v4 header level or id mismatch"));
    }
    if meta.partitioned_bloom_filter.is_some() {
        return Err(unsupported(
            "partitioned v4 segment Bloom is not yet proven",
        ));
    }

    let mut facts = CompressedWorkFacts::default();
    let mut encoded = Vec::new();
    let mut decoded = Vec::new();
    let mut previous = Vec::new();
    let mut previous_cf_len = 0;
    let mut previous_valid = false;
    let mut first_seen = false;
    let mut last_key_matches = meta.max_key.is_empty();
    for _ in 0..block_count {
        let first_key = footer.read_len_slice()?;
        let last_key = footer.read_len_slice()?;
        let offset = footer.read_u64()?;
        let block_len = footer.read_u64()?;
        let end = offset
            .checked_add(block_len)
            .ok_or_else(|| corrupt(path, "compressed v4 block offset overflow"))?;
        if offset != reader.cursor || block_len < BLOCK_HEADER_BYTES as u64 || end > footer_start {
            return Err(corrupt(path, "compressed v4 block is not contiguous"));
        }
        let mut block_header = [0_u8; BLOCK_HEADER_BYTES];
        reader.read_hashed(&mut block_header)?;
        let encoded_len = u64::from(u32::from_le_bytes(block_header[..4].try_into().unwrap()));
        let decoded_len = u64::from(u32::from_le_bytes(block_header[4..8].try_into().unwrap()));
        let checksum = u32::from_le_bytes(block_header[8..].try_into().unwrap());
        if encoded_len
            .checked_add(BLOCK_HEADER_BYTES as u64)
            .filter(|total| *total == block_len)
            .is_none()
            || encoded_len == 0
        {
            return Err(corrupt(path, "compressed v4 block length mismatch"));
        }
        if encoded_len > work.profile.max_encoded_block_bytes {
            return Err(unsupported(
                "compressed v4 encoded block exceeds proof profile",
            ));
        }
        // Refuse forged output claims before encoded or decoded allocation.
        work.check_next_block(facts, decoded_len, pass, path)?;
        let encoded_len_usize = usize::try_from(encoded_len)
            .map_err(|_| unsupported("compressed v4 encoded block exceeds platform range"))?;
        encoded.clear();
        scratch.reserve_vec(ScratchSlot::Encoded, &mut encoded, encoded_len_usize, path)?;
        encoded.resize(encoded_len_usize, 0);
        reader.read_hashed(&mut encoded)?;
        facts = decode_bounded_block(
            BlockFrame {
                codec: Compression::Lz4,
                encoded: &encoded,
                checksum,
                decoded_len,
            },
            work,
            facts,
            pass,
            &mut decoded,
            &mut scratch,
            path,
        )?;
        let mut rows = BinaryReader::new(&decoded, path);
        let row_count = u64::from(rows.read_u32()?);
        if row_count == 0 || row_count > (rows.remaining() / 17) as u64 {
            return Err(corrupt(path, "compressed v4 row count exceeds block"));
        }
        work.check_next_rows(facts, row_count, pass, path)?;
        let mut block_first = None;
        let mut block_last: Option<(&str, &[u8])> = None;
        for row_index in 0..row_count {
            let row = borrowed_row(&mut rows, path)?;
            let prior = block_last.or_else(|| {
                previous_valid.then(|| {
                    let (cf, key) = previous.split_at(previous_cf_len);
                    (
                        std::str::from_utf8(cf).expect("previous family was validated"),
                        key,
                    )
                })
            });
            if prior.is_some_and(|(cf, key)| (row.cf.as_bytes(), row.key) < (cf.as_bytes(), key)) {
                return Err(corrupt(path, "compressed v4 rows are out of writer order"));
            }
            if !first_seen {
                first_seen = true;
                if row.key != meta.min_key.as_slice() {
                    return Err(corrupt(
                        path,
                        "compressed v4 first key disagrees with MANIFEST",
                    ));
                }
            }
            last_key_matches = row.key == meta.max_key.as_slice();
            block_first.get_or_insert(row.key);
            block_last = Some((row.cf, row.key));
            facts = work.check_next_row(facts, pass, path)?;
            let row_ordinal = u32::try_from(row_index)
                .map_err(|_| unsupported("compressed v4 row ordinal exceeds u32"))?;
            visit_bounded_owned_row(
                row,
                source,
                offset,
                row_ordinal,
                &mut scratch,
                path,
                &mut visit,
            )?;
        }
        if rows.remaining() != 0
            || block_first != Some(first_key)
            || block_last.map(|(_, key)| key) != Some(last_key)
        {
            return Err(corrupt(
                path,
                "compressed v4 block key range or framing mismatch",
            ));
        }
        let (last_cf, last_key) = block_last.expect("nonempty block was checked");
        previous_cf_len = last_cf.len();
        let previous_len = previous_cf_len
            .checked_add(last_key.len())
            .ok_or_else(|| unsupported("compressed v4 prior key length overflow"))?;
        scratch.reserve_vec(ScratchSlot::Previous, &mut previous, previous_len, path)?;
        previous.clear();
        previous.extend_from_slice(last_cf.as_bytes());
        previous.extend_from_slice(last_key);
        previous_valid = true;
    }
    if footer.remaining() != 0 || reader.cursor != footer_start {
        return Err(corrupt(path, "unconsumed compressed v4 framing bytes"));
    }
    if facts.rows != meta.entries || (!first_seen && !meta.min_key.is_empty()) || !last_key_matches
    {
        return Err(corrupt(
            path,
            "compressed v4 observed count or key range mismatch",
        ));
    }

    let mut chunk = [0_u8; HASH_CHUNK_BYTES];
    for expected in footer_bytes.chunks(HASH_CHUNK_BYTES) {
        let actual = &mut chunk[..expected.len()];
        reader.read_hashed(actual)?;
        if actual != expected {
            return Err(corrupt(path, "compressed v4 footer changed during pass"));
        }
    }
    let mut reread_trailer = [0_u8; SEGMENT_TRAILER_BYTES];
    reader.read_hashed(&mut reread_trailer)?;
    if reread_trailer != trailer || reader.cursor != len {
        return Err(corrupt(path, "compressed v4 trailer changed during pass"));
    }
    let mut extra = [0_u8; 1];
    if reader.file.read(&mut extra)? != 0
        || reader.file.metadata()?.len() != len
        || physical_id(reader.file, path)? != expected_identity
    {
        return Err(corrupt(
            path,
            "compressed v4 length or identity changed during pass",
        ));
    }
    let digest = reader.hasher.finalize();
    if digest.to_hex().as_str() != meta.file_digest.as_str() {
        return Err(corrupt(
            path,
            "compressed v4 integrated pass digest mismatch",
        ));
    }
    if first.digest != digest || first.len != len {
        return Err(corrupt(
            path,
            "compressed v4 integrated replay digest or length changed",
        ));
    }
    pass.require_exact_replay(facts, path)?;
    Ok(AuthenticatedLz4Pass {
        work: facts,
        digest,
        len,
    })
}

/// Second pass rebuilds the writer Bloom without exposing provisional rows.
pub(super) fn scan_lz4_pass2(
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    work: &WorkLedger,
    first: AuthenticatedLz4Pass,
    mut probe: impl FnMut(Lz4PassProbe),
) -> Result<AuthenticatedLz4Pass> {
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(
            path,
            "compressed v4 identity changed before replay",
        ));
    }
    let len = file.metadata()?.len();
    if len < (SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES) as u64 {
        return Err(corrupt(path, "short compressed v4 segment"));
    }
    if len != first.len {
        return Err(corrupt(path, "compressed v4 replay length changed"));
    }
    if len > work.profile.max_physical_file_bytes {
        return Err(unsupported(
            "compressed v4 physical file exceeds proof profile",
        ));
    }
    let pass = work.replay_pass(first.work)?;
    scan_compressed_opened_pass(
        &mut file,
        path,
        expected_identity,
        meta,
        work,
        pass,
        Some(first),
        len,
        Compression::Lz4,
        |event| event.dispatch_lz4(&mut probe),
    )
}

/// Private owned-row pass. Its rows remain provisional until the caller has
/// authenticated the complete stream and performed the final namespace check.
pub(super) fn scan_lz4_pass3(
    path: &Path,
    expected_identity: SegmentPhysicalId,
    meta: &SegmentMetadata,
    source: SegmentSource,
    work: &WorkLedger,
    first: AuthenticatedLz4Pass,
    visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<AuthenticatedLz4Pass> {
    if source.level != meta.level || source.id != meta.id {
        return Err(corrupt(path, "compressed v4 source and MANIFEST disagree"));
    }
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(
            path,
            "compressed v4 identity changed before owned replay",
        ));
    }
    let len = file.metadata()?.len();
    if len < (SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES) as u64 {
        return Err(corrupt(path, "short compressed v4 segment"));
    }
    if len != first.len {
        return Err(corrupt(path, "compressed v4 replay length changed"));
    }
    if len > work.profile.max_physical_file_bytes {
        return Err(unsupported(
            "compressed v4 physical file exceeds proof profile",
        ));
    }
    let pass = work.replay_pass(first.work)?;
    scan_lz4_opened_owned_pass(
        &mut file,
        path,
        expected_identity,
        meta,
        work,
        pass,
        first,
        len,
        source,
        visit,
    )
}

struct ScannedSegment {
    len: u64,
    digest: blake3::Hash,
    observed_rows: u64,
}

/// This bounded read selects a scanner; it does not authenticate the file.
/// Each selected scanner reopens the file and hashes the bytes it parses.
fn discover_segment_compression(locator: &SegmentLocator) -> Result<u8> {
    let path = &locator.path;
    let expected_identity = locator
        .identity
        .ok_or_else(|| corrupt(path, "v4 segment lacks admitted physical identity"))?;
    check_real(path)?;
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || physical_id(&file, path)? != expected_identity {
        return Err(corrupt(
            path,
            "v4 segment identity changed before discovery",
        ));
    }
    let mut header = [0_u8; SEGMENT_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|_| corrupt(path, "short v4 segment header"))?;
    let mut reader = BinaryReader::new(&header, path);
    if reader.read_u32()? != SEGMENT_MAGIC || reader.read_u32()? != SEGMENT_VERSION {
        return Err(corrupt(path, "bad v4 segment magic or version"));
    }
    let compression = reader.read_u8()?;
    if reader.read_u32()? != locator.source.level || reader.read_u64()? != locator.source.id {
        return Err(corrupt(path, "v4 segment header level or id mismatch"));
    }
    Ok(compression)
}

fn scan_literal_segment(
    locator: &SegmentLocator,
    meta: &SegmentMetadata,
    visit: &mut impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<ScannedSegment> {
    let path = &locator.path;
    let expected_identity = locator
        .identity
        .ok_or_else(|| corrupt(path, "v4 segment lacks admitted physical identity"))?;
    check_real(path)?;
    let mut file = File::open(path)?;
    if physical_id(&file, path)? != expected_identity {
        return Err(corrupt(path, "v4 segment identity changed before capture"));
    }
    let (bytes, len) = capture_literal(&mut file, path)?;
    drop(file);
    let digest = blake3::hash(&bytes);
    if digest.to_hex().as_str() != meta.file_digest.as_str() {
        return Err(corrupt(path, "v4 segment full-file digest mismatch"));
    }
    if bytes.len() < SEGMENT_HEADER_BYTES + SEGMENT_TRAILER_BYTES {
        return Err(corrupt(path, "short v4 segment header"));
    }
    let mut header = BinaryReader::new(&bytes, path);
    if header.read_u32()? != SEGMENT_MAGIC || header.read_u32()? != SEGMENT_VERSION {
        return Err(corrupt(path, "bad v4 segment magic or version"));
    }
    let compression = header.read_u8()?;
    if header.read_u32()? != locator.source.level || header.read_u64()? != locator.source.id {
        return Err(corrupt(path, "v4 segment header level or id mismatch"));
    }
    match compression {
        0 => {}
        1 | 2 => {
            return Err(unsupported(
                "compressed v4 segments need a bounded proof profile",
            ));
        }
        _ => return Err(corrupt(path, "unknown v4 segment compression tag")),
    }
    if meta.partitioned_bloom_filter.is_some() {
        return Err(unsupported(
            "partitioned v4 segment Bloom is not yet proven",
        ));
    }

    let first = walk_literal(&bytes, path, |_, _, _| Ok(()))?;
    if u64::try_from(first.rows).ok() != Some(meta.entries)
        || first.first_key.unwrap_or_default() != meta.min_key.as_slice()
        || first.last_key.unwrap_or_default() != meta.max_key.as_slice()
    {
        return Err(corrupt(
            path,
            "v4 segment observed count or key range mismatch",
        ));
    }
    let mut bloom = BloomFilter::try_with_observed_items(first.rows, MAX_LITERAL_ROWS)
        .map_err(|_| corrupt(path, "v4 segment observed Bloom allocation failed"))?;
    let mut scratch = Vec::new();
    let second = walk_literal(&bytes, path, |_, _, row| {
        bloom
            .try_insert_parts(row.cf, row.key, &mut scratch, MAX_LITERAL_SEGMENT_BYTES)
            .map_err(|_| corrupt(path, "v4 segment observed Bloom scratch exceeds cap"))
    })?;
    if second != first || bloom != meta.bloom_filter {
        return Err(corrupt(path, "v4 segment Bloom or semantic pass mismatch"));
    }

    check_real(path)?;
    let mut reopened = File::open(path)?;
    if physical_id(&reopened, path)? != expected_identity
        || hash_exact(&mut reopened, len, path)? != digest
    {
        return Err(corrupt(path, "v4 segment changed before callbacks"));
    }
    drop(reopened);
    let third = walk_literal(&bytes, path, |block_offset, row_ordinal, row| {
        visit(owned_row(
            row,
            locator.source,
            block_offset,
            row_ordinal,
            path,
        )?)
    })?;
    if third != first {
        return Err(corrupt(path, "v4 segment changed between semantic passes"));
    }
    Ok(ScannedSegment {
        len,
        digest,
        observed_rows: first.rows as u64,
    })
}

fn recheck_namespace(root: &Path, admitted: &mut SegmentInventory) -> Result<()> {
    let segment_root = DiskLayout::at(root).segment_root();
    check_real(&segment_root)?;
    if !fs::symlink_metadata(&segment_root)?.is_dir() {
        return Err(corrupt(
            &segment_root,
            "v4 segment root changed before final recheck",
        ));
    }
    for locator in &mut admitted.locators {
        locator.rechecked = false;
    }
    let mut observed = 0;
    for (levels, level_entry) in fs::read_dir(&segment_root)?.enumerate() {
        if levels == MAX_SEGMENT_LEVELS {
            return Err(corrupt(
                &segment_root,
                "v4 segment level-entry limit exceeded",
            ));
        }
        let level_path = level_entry?.path();
        check_real(&level_path)?;
        if !fs::symlink_metadata(&level_path)?.is_dir() {
            return Err(corrupt(
                &level_path,
                "v4 segment level changed before final recheck",
            ));
        }
        let level = parse_level(&level_path)?;
        for file_entry in fs::read_dir(&level_path)? {
            if observed == MAX_SEGMENT_FILES {
                return Err(corrupt(
                    &level_path,
                    "v4 segment observed-file limit exceeded",
                ));
            }
            observed += 1;
            let path = file_entry?.path();
            check_real(&path)?;
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(corrupt(
                    &path,
                    "v4 segment file changed kind before recheck",
                ));
            }
            let id = parse_segment_id(&path)?;
            let position = admitted
                .locators
                .binary_search_by_key(&(level, id), |item| (item.source.level, item.source.id))
                .map_err(|_| corrupt(&path, "unlisted v4 segment during final recheck"))?;
            let locator = &mut admitted.locators[position];
            let witness = &admitted.witnesses[position];
            if locator.rechecked || path != locator.path || witness.source != locator.source {
                return Err(corrupt(
                    &path,
                    "v4 segment identity changed before final recheck",
                ));
            }
            let mut file = File::open(&path)?;
            if Some(physical_id(&file, &path)?) != locator.identity
                || hash_exact(&mut file, witness.len, &path)? != witness.digest
            {
                return Err(corrupt(&path, "v4 segment bytes or identity changed"));
            }
            check_real(&path)?;
            let reopened = File::open(&path)?;
            if Some(physical_id(&reopened, &path)?) != locator.identity {
                return Err(corrupt(
                    &path,
                    "v4 segment path changed during final recheck",
                ));
            }
            locator.rechecked = true;
        }
    }
    if observed != admitted.locators.len() || admitted.locators.iter().any(|item| !item.rechecked) {
        return Err(corrupt(
            &segment_root,
            "v4 segment disappeared before final recheck",
        ));
    }
    Ok(())
}

fn visit_v4_segments_with_receipt(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<(Vec<SegmentFileWitness>, usize)> {
    visit_v4_segments_with_receipt_inner(
        root,
        manifest,
        budget,
        PRODUCTION_COMPRESSED_PROOF_PROFILE,
        |_| Ok(()),
        visit,
    )
}

#[cfg(test)]
pub(super) fn visit_v4_segments_with_profile_and_hook_for_test(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    profile: ProofProfile,
    on_lz4_discovered: impl FnMut(&Path) -> Result<()>,
    visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<(Vec<SegmentFileWitness>, usize)> {
    visit_v4_segments_with_receipt_inner(root, manifest, budget, profile, on_lz4_discovered, visit)
}

fn visit_v4_segments_with_receipt_inner(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    profile: ProofProfile,
    mut on_lz4_discovered: impl FnMut(&Path) -> Result<()>,
    mut visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<(Vec<SegmentFileWitness>, usize)> {
    // This guard starts before inventory. On every Err or Rust unwind, later
    // locals and their backing allocations drop before its budget refund.
    let mut attempt = WitnessAttempt::new(root, budget);
    let mut admitted = inventory(root, manifest, &mut attempt)?;
    let (locators, witnesses) = (&mut admitted.locators, &mut admitted.witnesses);
    let mut work = WorkLedger::new(profile);
    for locator in locators {
        let meta = &manifest.segments[locator.source.manifest_ordinal];
        let scanned = match discover_segment_compression(locator)? {
            0 => scan_literal_segment(locator, meta, &mut visit)?,
            1 => {
                on_lz4_discovered(&locator.path)?;
                let expected_identity = locator.identity.ok_or_else(|| {
                    corrupt(&locator.path, "v4 segment lacks admitted physical identity")
                })?;
                let first =
                    scan_lz4_pass1(&locator.path, expected_identity, meta, &mut work, |_| {})?;
                let first_pass = work.first_pass();
                work.accept_authenticated_file(first_pass, first.work, &locator.path)?;
                let second =
                    scan_lz4_pass2(&locator.path, expected_identity, meta, &work, first, |_| {})?;
                if second != first {
                    return Err(corrupt(&locator.path, "compressed v4 replay changed"));
                }
                let third = scan_lz4_pass3(
                    &locator.path,
                    expected_identity,
                    meta,
                    locator.source,
                    &work,
                    first,
                    &mut visit,
                )?;
                if third != first || third != second {
                    return Err(corrupt(&locator.path, "compressed v4 owned replay changed"));
                }
                ScannedSegment {
                    len: third.len,
                    digest: third.digest,
                    observed_rows: third.work.rows,
                }
            }
            2 => {
                return Err(unsupported(
                    "compressed v4 segments need a bounded proof profile",
                ));
            }
            _ => return Err(corrupt(&locator.path, "unknown v4 segment compression tag")),
        };
        if witnesses.len() == witnesses.capacity() {
            return Err(budget_error(&locator.path));
        }
        let path = locator
            .witness_path
            .take()
            .ok_or_else(|| corrupt(&locator.path, "v4 segment witness path was not precharged"))?;
        witnesses.push(SegmentFileWitness {
            source: locator.source,
            path,
            identity: locator.identity.ok_or_else(|| {
                corrupt(&locator.path, "v4 segment witness has no physical identity")
            })?,
            len: scanned.len,
            digest: scanned.digest,
            observed_rows: scanned.observed_rows,
        });
    }
    recheck_namespace(root, &mut admitted)?;

    let retained = admitted.retained_witness_bytes;
    let temporary = attempt
        .charged()
        .checked_sub(retained)
        .ok_or_else(|| budget_error(root))?;
    let witnesses = std::mem::take(&mut admitted.witnesses);
    drop(admitted);
    attempt.release(root, temporary)?;
    attempt.transfer_retained(retained)?;
    Ok((witnesses, retained))
}

#[cfg(test)]
pub(crate) fn visit_v4_segments(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    visit: impl FnMut(ObservedSegmentRow) -> Result<()>,
) -> Result<Vec<SegmentFileWitness>> {
    visit_v4_segments_with_receipt(root, manifest, budget, visit).map(|(witnesses, _)| witnesses)
}

#[derive(Clone, Copy)]
pub(super) struct ProtectedStageLimits {
    pub(super) max_rows: usize,
    pub(super) max_bytes: usize,
}

pub(super) const PROTECTED_STAGE_LIMITS: ProtectedStageLimits = ProtectedStageLimits {
    max_rows: 65_536,
    max_bytes: 64 * 1024 * 1024,
};

/// A candidate remains private and carries no installed or effective owner claim.
#[derive(Debug)]
#[allow(dead_code)] // Composed only after the later protected-copy and installed-owner proofs.
pub(crate) struct ProtectedSegmentCandidate {
    pub(crate) rows: Vec<ObservedSegmentRow>,
    pub(crate) witnesses: Vec<SegmentFileWitness>,
    retained_witness_bytes: usize,
}

#[allow(dead_code)] // The later owner composer consumes or discards this candidate.
impl ProtectedSegmentCandidate {
    pub(crate) fn retained_witness_bytes(&self) -> usize {
        self.retained_witness_bytes
    }

    /// Keep the WAL ledger live until the retained file witnesses have dropped.
    pub(crate) fn discard(self, root: &Path, budget: &mut PhysicalWitnessBudget) -> Result<()> {
        let Self {
            rows,
            witnesses,
            retained_witness_bytes,
        } = self;
        drop(rows);
        drop(witnesses);
        budget.release(root, retained_witness_bytes)
    }
}

fn protected_stage_limit() -> PraxisError {
    unsupported("protected segment staging exceeds the private row or byte proof profile")
}

fn protected_allocation_charge(capacity: usize) -> Result<usize> {
    if capacity == 0 {
        return Ok(0);
    }
    capacity
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or_else(protected_stage_limit)
}

fn protected_row_heap_charge(row: &ObservedSegmentRow) -> Result<usize> {
    let value_capacity = match &row.value {
        ObservedSegmentValue::Put(value)
        | ObservedSegmentValue::PutWithExpiry { value, .. }
        | ObservedSegmentValue::Merge(value) => value.capacity(),
        ObservedSegmentValue::Pointer { pointer, .. } => pointer.path.capacity(),
        ObservedSegmentValue::Delete => 0,
    };
    [row.cf.capacity(), row.key.capacity(), value_capacity]
        .into_iter()
        .try_fold(0_usize, |total, capacity| {
            total
                .checked_add(protected_allocation_charge(capacity)?)
                .ok_or_else(protected_stage_limit)
        })
}

fn protected_vector_charge(capacity: usize) -> Result<usize> {
    vector_charge::<ObservedSegmentRow>(Path::new("protected segment stage"), capacity)
        .map_err(|_| protected_stage_limit())
}

pub(super) struct ProtectedStage {
    rows: Vec<ObservedSegmentRow>,
    used_bytes: usize,
    limits: ProtectedStageLimits,
    poisoned: bool,
}

impl ProtectedStage {
    pub(super) fn new(limits: ProtectedStageLimits) -> Self {
        Self {
            rows: Vec::new(),
            used_bytes: 0,
            limits,
            poisoned: false,
        }
    }

    fn poison(&mut self) {
        self.rows = Vec::new();
        self.used_bytes = 0;
        self.poisoned = true;
    }

    fn grow(&mut self, incoming_heap: usize) -> Result<()> {
        let old_capacity = self.rows.capacity();
        let target = if old_capacity == 0 {
            1
        } else {
            old_capacity
                .checked_mul(2)
                .ok_or_else(protected_stage_limit)?
        }
        .min(self.limits.max_rows);
        if target <= old_capacity {
            return Err(protected_stage_limit());
        }
        let allowance_capacity = target.checked_mul(2).ok_or_else(protected_stage_limit)?;
        let allowance = protected_vector_charge(allowance_capacity)?;
        self.used_bytes
            .checked_add(incoming_heap)
            .and_then(|bytes| bytes.checked_add(allowance))
            .filter(|bytes| *bytes <= self.limits.max_bytes)
            .ok_or_else(protected_stage_limit)?;
        let old_vector_charge = protected_vector_charge(old_capacity)?;
        let additional = target
            .checked_sub(self.rows.len())
            .ok_or_else(protected_stage_limit)?;
        if self.rows.try_reserve_exact(additional).is_err() {
            self.poison();
            return Err(protected_stage_limit());
        }
        let actual_capacity = self.rows.capacity();
        let actual_charge = match protected_vector_charge(actual_capacity) {
            Ok(charge) => charge,
            Err(error) => {
                self.poison();
                return Err(error);
            }
        };
        let live_without_row = self
            .used_bytes
            .checked_sub(old_vector_charge)
            .and_then(|bytes| bytes.checked_add(actual_charge));
        if actual_capacity > allowance_capacity
            || actual_capacity <= old_capacity
            || actual_charge > allowance
            || live_without_row
                .and_then(|bytes| bytes.checked_add(incoming_heap))
                .is_none_or(|bytes| bytes > self.limits.max_bytes)
        {
            self.poison();
            return Err(protected_stage_limit());
        }
        self.used_bytes = live_without_row.ok_or_else(protected_stage_limit)?;
        Ok(())
    }

    pub(super) fn push(&mut self, row: ObservedSegmentRow) -> Result<()> {
        if self.poisoned || self.rows.len() >= self.limits.max_rows {
            return Err(protected_stage_limit());
        }
        let incoming_heap = protected_row_heap_charge(&row)?;
        self.used_bytes
            .checked_add(incoming_heap)
            .filter(|bytes| *bytes <= self.limits.max_bytes)
            .ok_or_else(protected_stage_limit)?;
        if self.rows.len() == self.rows.capacity() {
            self.grow(incoming_heap)?;
        }
        if self.rows.len() == self.rows.capacity() {
            self.poison();
            return Err(protected_stage_limit());
        }
        self.used_bytes = self
            .used_bytes
            .checked_add(incoming_heap)
            .ok_or_else(protected_stage_limit)?;
        self.rows.push(row);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    #[cfg(test)]
    pub(super) fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.rows.capacity()
    }

    #[cfg(test)]
    pub(super) fn set_max_bytes_for_test(&mut self, max_bytes: usize) {
        assert!(max_bytes <= PROTECTED_STAGE_LIMITS.max_bytes);
        self.limits.max_bytes = max_bytes;
    }
}

fn collect_protected_segment_candidate_inner(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    limits: ProtectedStageLimits,
    mut after_staged: impl FnMut(usize) -> Result<()>,
) -> Result<ProtectedSegmentCandidate> {
    let before = budget.remaining_bytes();
    let mut stage = ProtectedStage::new(limits);
    let (witnesses, retained_witness_bytes) =
        visit_v4_segments_with_receipt(root, manifest, budget, |row| {
            if row.classification == PhysicalRowClass::Other {
                return Ok(());
            }
            stage.push(row)?;
            after_staged(stage.rows.len())
        })?;
    if before.checked_sub(budget.remaining_bytes()) != Some(retained_witness_bytes) {
        drop(witnesses);
        budget.release(root, retained_witness_bytes)?;
        return Err(corrupt(
            root,
            "protected segment witness budget receipt mismatch",
        ));
    }
    Ok(ProtectedSegmentCandidate {
        rows: stage.rows,
        witnesses,
        retained_witness_bytes,
    })
}

#[allow(dead_code)] // Used by the next private owner-composition cut.
pub(crate) fn collect_protected_segment_candidate(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
) -> Result<ProtectedSegmentCandidate> {
    collect_protected_segment_candidate_inner(
        root,
        manifest,
        budget,
        PROTECTED_STAGE_LIMITS,
        |_| Ok(()),
    )
}

#[cfg(test)]
pub(super) fn collect_protected_segment_candidate_for_test(
    root: &Path,
    manifest: &Manifest,
    budget: &mut PhysicalWitnessBudget,
    limits: ProtectedStageLimits,
    after_staged: impl FnMut(usize) -> Result<()>,
) -> Result<ProtectedSegmentCandidate> {
    assert!(limits.max_rows <= PROTECTED_STAGE_LIMITS.max_rows);
    assert!(limits.max_bytes <= PROTECTED_STAGE_LIMITS.max_bytes);
    collect_protected_segment_candidate_inner(root, manifest, budget, limits, after_staged)
}

#[cfg(test)]
mod compressed_owned_row_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    const PATH: &str = "compressed-owned-row-test.tseg";
    const SOURCE: SegmentSource = SegmentSource {
        level: 0,
        id: 7,
        manifest_ordinal: 3,
    };

    #[test]
    fn precharges_all_three_fields_before_any_owned_row_allocation() {
        let row = BorrowedRow {
            cf: "cf",
            key: b"k",
            sequence: 7,
            value: BorrowedValue::Put(b"data"),
        };
        // (2*2+64) + (2*1+64) + (2*4+64) = 206.
        let path = Path::new(PATH);
        let mut short = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut short_encoded = Vec::new();
        short
            .reserve_vec(ScratchSlot::Encoded, &mut short_encoded, 32, path)
            .unwrap();
        let short_baseline = short.live_bytes();
        short.profile.max_parser_owned_peak_bytes = short_baseline + 205;
        let mut callbacks = 0;
        let error = visit_bounded_owned_row(row, SOURCE, 21, 0, &mut short, path, &mut |_| {
            callbacks += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature { .. }
        ));
        assert_eq!(callbacks, 0);
        assert_eq!(short.live_bytes(), short_baseline);
        assert_eq!(short.pending_owned_bytes, 0);
        short
            .release_vec(ScratchSlot::Encoded, short_encoded)
            .unwrap();
        assert_eq!(short.live_bytes(), 0);

        let mut exact = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut exact_encoded = Vec::new();
        exact
            .reserve_vec(ScratchSlot::Encoded, &mut exact_encoded, 32, path)
            .unwrap();
        let exact_baseline = exact.live_bytes();
        exact.profile.max_parser_owned_peak_bytes = exact_baseline + 206;
        visit_bounded_owned_row(row, SOURCE, 21, 0, &mut exact, path, &mut |owned| {
            assert_eq!(owned.source, SOURCE);
            assert_eq!(owned.block_offset, 21);
            assert_eq!(owned.row_ordinal, 0);
            assert_eq!(owned.cf, "cf");
            assert_eq!(owned.key, b"k");
            let value_capacity = match &owned.value {
                ObservedSegmentValue::Put(value) => {
                    assert_eq!(value, b"data");
                    value.capacity()
                }
                other => panic!("expected inline Put, got {other:?}"),
            };
            let actual = owned.cf.capacity() + owned.key.capacity() + value_capacity;
            assert!(actual <= 206);
            Ok(())
        })
        .unwrap();
        assert_eq!(exact.live_bytes(), exact_baseline);
        assert_eq!(exact.pending_owned_bytes, 0);
        exact
            .release_vec(ScratchSlot::Encoded, exact_encoded)
            .unwrap();
        assert_eq!(exact.live_bytes(), 0);
    }

    #[test]
    fn releases_owned_charge_on_other_callback_error_and_stage_rejection() {
        let path = Path::new(PATH);
        let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let other = BorrowedRow {
            cf: "ordinary",
            key: b"key",
            sequence: 4,
            value: BorrowedValue::Delete,
        };
        visit_bounded_owned_row(other, SOURCE, 21, 0, &mut scratch, path, &mut |owned| {
            assert_eq!(owned.classification, PhysicalRowClass::Other);
            assert_eq!(owned.value, ObservedSegmentValue::Delete);
            Ok(())
        })
        .unwrap();
        assert_eq!(scratch.live_bytes(), 0);
        let error = visit_bounded_owned_row(other, SOURCE, 21, 0, &mut scratch, path, &mut |_| {
            Err(unsupported("direct row callback refused"))
        })
        .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature { .. }
        ));
        assert_eq!(scratch.live_bytes(), 0);

        let mut refused = ProtectedStage::new(ProtectedStageLimits {
            max_rows: 0,
            max_bytes: 0,
        });
        let error =
            visit_bounded_owned_row(other, SOURCE, 21, 0, &mut scratch, path, &mut |owned| {
                refused.push(owned)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            PraxisError::UnsupportedCatalogFeature { .. }
        ));
        assert_eq!(refused.len(), 0);
        assert_eq!(scratch.live_bytes(), 0);
        assert_eq!(scratch.pending_owned_bytes, 0);
    }

    #[test]
    fn retains_pointer_and_expiry_tags_with_independent_owned_bytes() {
        let path = Path::new(PATH);
        let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut values = Vec::new();
        for value in [
            BorrowedValue::Pointer {
                path: "value-log/7.vlog",
                offset: 9,
                len: 11,
                checksum: 13,
                expires_at_ms: Some(17),
            },
            BorrowedValue::PutWithExpiry {
                value: b"put",
                expires_at_ms: 19,
            },
            BorrowedValue::Merge(b"merge"),
            BorrowedValue::Delete,
        ] {
            visit_bounded_owned_row(
                BorrowedRow {
                    cf: "ordinary",
                    key: b"key",
                    sequence: 4,
                    value,
                },
                SOURCE,
                21,
                0,
                &mut scratch,
                path,
                &mut |owned| {
                    values.push(owned.value);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(scratch.live_bytes(), 0);
        }
        assert_eq!(values.len(), 4);
        assert!(
            matches!(&values[0], ObservedSegmentValue::Pointer { pointer, expires_at_ms: Some(17) }
            if pointer.path == "value-log/7.vlog" && pointer.offset == 9 && pointer.len == 11 && pointer.checksum == 13)
        );
        assert_eq!(
            values[1],
            ObservedSegmentValue::PutWithExpiry {
                value: b"put".to_vec(),
                expires_at_ms: 19,
            }
        );
        assert_eq!(values[2], ObservedSegmentValue::Merge(b"merge".to_vec()));
        assert_eq!(values[3], ObservedSegmentValue::Delete);
    }

    #[test]
    fn stage_owns_transferred_row_after_parser_callback_unwinds() {
        let path = Path::new(PATH);
        let row = BorrowedRow {
            cf: "__praxor_record_meta_v1",
            key: b"key",
            sequence: 4,
            value: BorrowedValue::Put(b"value"),
        };
        let mut scratch = ScratchLedger::new(PRODUCTION_COMPRESSED_PROOF_PROFILE);
        let mut stage = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = visit_bounded_owned_row(row, SOURCE, 21, 0, &mut scratch, path, &mut |owned| {
                stage.push(owned)?;
                panic!("after protected stage transfer")
            });
        }));
        assert!(panic.is_err());
        assert_eq!(stage.len(), 1);
        assert!(stage.used_bytes() > 0);
        assert_eq!(scratch.live_bytes(), 0);
        assert_eq!(scratch.pending_owned_bytes, 0);
        drop(stage);

        let mut retry = ProtectedStage::new(PROTECTED_STAGE_LIMITS);
        visit_bounded_owned_row(row, SOURCE, 21, 0, &mut scratch, path, &mut |owned| {
            retry.push(owned)
        })
        .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(scratch.live_bytes(), 0);
    }
}
