use praxis::accel::CpuAccelerator;
use praxis::io::{BinaryWriter, crc32_ieee};
use praxis::segments::SegmentReader;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Measured;
static MEASURE: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());
unsafe impl GlobalAlloc for Measured {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if MEASURE.load(Ordering::Relaxed) {
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if MEASURE.load(Ordering::Relaxed) {
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Measured = Measured;

fn frame(codec: u8, compressed: &[u8], expected: u32) -> Vec<u8> {
    let mut out = BinaryWriter::new();
    out.write_u32(0x5453_4547);
    out.write_u32(2);
    out.write_u8(codec);
    out.write_u32(0);
    out.write_u64(1);
    let offset = out.len();
    out.write_u32(compressed.len() as u32);
    out.write_u32(expected);
    out.write_u32(crc32_ieee(compressed));
    out.write_bytes(compressed);
    let block_len = out.len() - offset;
    let mut footer = BinaryWriter::new();
    footer.write_u32(1);
    footer.write_len_bytes(b"");
    footer.write_len_bytes(b"");
    footer.write_u64(offset as u64);
    footer.write_u64(block_len as u64);
    let footer = footer.into_inner();
    out.write_bytes(&footer);
    out.write_u32(footer.len() as u32);
    out.write_u32(crc32_ieee(&footer));
    out.write_u32(0x5453_4654);
    out.into_inner()
}
fn bounded(codec: u8, compressed: Vec<u8>, expected: u32) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("malformed.tseg");
    std::fs::write(&path, frame(codec, &compressed, expected)).unwrap();
    LARGEST.store(0, Ordering::Relaxed);
    MEASURE.store(true, Ordering::SeqCst);
    let result = SegmentReader::read(&path, &CpuAccelerator, false);
    MEASURE.store(false, Ordering::SeqCst);
    assert!(result.is_err());
    assert!(
        LARGEST.load(Ordering::Relaxed) < 65_536,
        "tiny malformed frame allocated {} bytes",
        LARGEST.load(Ordering::Relaxed)
    );
}
#[test]
fn lz4_inner_claim_is_checked_before_output_allocation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut compressed = 1_048_576_u32.to_le_bytes().to_vec();
    compressed.push(0);
    bounded(1, compressed, 4);
}
#[test]
fn zstd_frame_claim_is_checked_before_output_allocation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    bounded(2, zstd::bulk::compress(&vec![0; 1_048_576], 3).unwrap(), 4);
}

#[test]
fn matching_lz4_claims_still_need_a_complete_length_proof_before_allocation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut compressed = 1_048_576_u32.to_le_bytes().to_vec();
    compressed.push(0);
    bounded(1, compressed, 1_048_576);
}

#[test]
fn unknown_size_zstd_output_stops_at_the_outer_bound() {
    use std::io::Write;
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder.write_all(&vec![0; 1_048_576]).unwrap();
    bounded(2, encoder.finish().unwrap(), 4);
}
