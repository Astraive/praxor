use praxis::io::{BinaryWriter, crc32c};
use praxis::page::RecordPage;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct MeasuringAllocator;
static MEASURE: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for MeasuringAllocator {
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
static ALLOCATOR: MeasuringAllocator = MeasuringAllocator;

fn truncated_inner_payload(claimed: u32) -> Vec<u8> {
    let mut payload = BinaryWriter::new();
    payload.write_u32(u32::MAX);
    payload.write_u64(1);
    payload.write_u8(1);
    payload.write_u32(0);
    payload.write_u32(claimed);
    let payload = payload.into_inner();
    let mut file = BinaryWriter::new();
    file.write_u32(0x5450_4147);
    file.write_u8(1);
    file.write_u32(payload.len() as u32);
    file.write_u32(crc32c(&payload));
    file.write_bytes(&payload);
    file.into_inner()
}

#[test]
fn tiny_valid_crc_page_cannot_allocate_its_missing_claimed_payload() {
    // A bounded 1 MiB claim proves the same branch without attempting 4 GiB.
    let file = truncated_inner_payload(1_048_576);
    LARGEST.store(0, Ordering::Relaxed);
    MEASURE.store(true, Ordering::SeqCst);
    let result = RecordPage::from_bytes(&file, "truncated.page");
    MEASURE.store(false, Ordering::SeqCst);
    let largest = LARGEST.load(Ordering::Relaxed);

    assert!(result.is_err());
    assert!(
        largest < 65_536,
        "tiny input requested an allocation of {largest} bytes"
    );
    // Only exercise maximum claims after the bounded allocation guard passed.
    assert!(RecordPage::from_bytes(&truncated_inner_payload(u32::MAX), "maximum.page").is_err());
    let mut excessive_slots = truncated_inner_payload(0);
    excessive_slots[26..30].copy_from_slice(&u32::MAX.to_le_bytes());
    let checksum = crc32c(&excessive_slots[13..]);
    excessive_slots[9..13].copy_from_slice(&checksum.to_le_bytes());
    assert!(RecordPage::from_bytes(&excessive_slots, "maximum-slots.page").is_err());
}
