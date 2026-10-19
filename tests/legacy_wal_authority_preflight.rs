use praxis::manifest::{CompactionJobState, CompactionJobStatus, Manifest, ManifestStore};
use praxis::wal::WalRecord;
use praxis::{PraxisConfig, PraxisEngine, PraxisError};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const LOCK: &str = ".praxor.writer.lock";
// Frozen with independent Python stdlib struct/zlib (no production encoder),
// audited SHA-256 9f350e478b8e2b906565fbb4e7af444a1cdca033127c4fb46230051cf2412065.
const RECORD_BOOTSTRAP: &[u8; 121] = include_bytes!("fixtures/tag5_bootstrap_s1.bin");
const CATALOG_BOOTSTRAP: &[u8; 563] = include_bytes!("fixtures/catalog_tag6_bootstrap_s1.bin");

struct PeakAllocator;
thread_local! {
    static PEAK: Cell<Option<usize>> = const { Cell::new(None) };
}
fn record_allocation(size: usize) {
    let _ = PEAK.try_with(|peak| {
        if let Some(previous) = peak.get() {
            peak.set(Some(previous.max(size)));
        }
    });
}
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    LockedFile(u64),
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        for child in fs::read_dir(at).unwrap() {
            let child = child.unwrap();
            let path = child.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = child.file_type().unwrap();
            assert!(!kind.is_symlink(), "test root contains alias: {path:?}");
            if kind.is_dir() {
                out.insert(relative, Entry::Directory);
                visit(root, &path, out);
            } else {
                assert!(kind.is_file(), "test root contains non-file: {path:?}");
                let value = match fs::read(&path) {
                    Ok(bytes) => Entry::File(bytes),
                    Err(error)
                        if relative == Path::new(LOCK) && error.raw_os_error() == Some(33) =>
                    {
                        Entry::LockedFile(child.metadata().unwrap().len())
                    }
                    Err(error) => panic!("cannot snapshot {path:?}: {error}"),
                };
                out.insert(relative, value);
            }
        }
    }
    let mut result = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut result);
    }
    result
}

fn frame() -> Vec<u8> {
    let bytes = RECORD_BOOTSTRAP.to_vec();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "9f350e478b8e2b906565fbb4e7af444a1cdca033127c4fb46230051cf2412065"
    );
    assert!(matches!(
        WalRecord::decode(&bytes, Path::new("literal-tag5")),
        Err(PraxisError::RecordAuthorityWalRequired { .. })
    ));
    bytes
}

fn manifest(root: &Path) -> Manifest {
    toml::from_str(&fs::read_to_string(root.join("MANIFEST")).unwrap()).unwrap()
}

fn save_manifest(root: &Path, manifest: &Manifest) {
    ManifestStore::new(root.join("MANIFEST"))
        .save(manifest)
        .unwrap();
}

fn downgrade_manifest_v1(root: &Path) {
    let mut manifest = manifest(root);
    manifest.format_version = 1;
    manifest.column_family_generations.clear();
    manifest.next_column_family_generation = 1;
    let encoded = toml::to_string_pretty(&manifest)
        .unwrap()
        .replace("next_column_family_generation = 1\n", "")
        .replace("[column_family_generations]\n", "");
    fs::write(root.join("MANIFEST"), encoded).unwrap();
    assert!(
        fs::read_to_string(root.join("MANIFEST"))
            .unwrap()
            .contains("format_version = 1")
    );
}

fn canonical_wal(root: &Path, id: u64) -> PathBuf {
    root.join("wal").join(format!("{id:020}.wal"))
}

fn append_frame(root: &Path, id: u64) {
    let path = canonical_wal(root, id);
    let existing = fs::read(&path).unwrap();
    assert_eq!(
        existing.len(),
        16,
        "fixture must start with WAL file header only"
    );
    assert_eq!(&existing[..4], &0x5457_4146u32.to_le_bytes());
    assert_eq!(u64::from_le_bytes(existing[8..16].try_into().unwrap()), id);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&frame())
        .unwrap();
}

fn seed_lock(root: &Path) {
    fs::write(root.join(LOCK), b"persistent source lease bytes").unwrap();
}

fn add_running_job(root: &Path) {
    let mut manifest = manifest(root);
    manifest.compaction_jobs.push(CompactionJobState {
        id: 1,
        strategy: praxis::CompactionStrategy::Leveled,
        status: CompactionJobStatus::Running,
        source_segment_ids: vec![],
        output_segment_id: None,
        created_at_ms: 0,
        updated_at_ms: 0,
    });
    save_manifest(root, &manifest);
}

fn assert_authority(error: PraxisError) {
    assert!(
        matches!(error, PraxisError::RecordAuthorityWalRequired { .. }),
        "expected typed Record WAL refusal, got {error:?}"
    );
}

#[test]
fn generic_v2_running_job_refuses_record_control_without_mutating_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("generic-v2");
    drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
    add_running_job(&root);
    append_frame(&root, 1);
    seed_lock(&root);
    let before = tree(&root);
    let error = match PraxisEngine::open(PraxisConfig::new(&root)) {
        Ok(_) => panic!("generic open admitted Record control"),
        Err(error) => error,
    };
    assert_authority(error);
    assert!(tree(&root) == before, "generic open reconciled Running job");
}

#[test]
fn generic_v1_running_job_refuses_record_control_without_manifest_upgrade() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("generic-v1");
    drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
    add_running_job(&root);
    downgrade_manifest_v1(&root);
    append_frame(&root, 1);
    seed_lock(&root);
    let before = tree(&root);
    let error = match PraxisEngine::open(PraxisConfig::new(&root)) {
        Ok(_) => panic!("generic v1 open admitted Record control"),
        Err(error) => error,
    };
    assert_authority(error);
    assert!(
        tree(&root) == before,
        "generic v1 open upgraded/reconciled root"
    );
}

#[test]
fn generic_open_does_not_create_missing_layout_before_record_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("missing-layout");
    drop(PraxisEngine::open(PraxisConfig::new(&root)).unwrap());
    fs::remove_dir(root.join("tmp")).unwrap();
    append_frame(&root, 1);
    seed_lock(&root);
    let before = tree(&root);
    let error = match PraxisEngine::open(PraxisConfig::new(&root)) {
        Ok(_) => panic!("generic open admitted Record control"),
        Err(error) => error,
    };
    assert_authority(error);
    assert!(tree(&root) == before, "generic open recreated layout");
    assert!(!root.join("tmp").exists());
}

fn prepared_backup(temp: &Path, v1: bool) -> PathBuf {
    let source_root = temp.join("source");
    let backup_root = temp.join(if v1 { "bundle-v1" } else { "bundle-v2" });
    let source = PraxisEngine::open(PraxisConfig::new(&source_root)).unwrap();
    source.backup_to(&backup_root).unwrap();
    drop(source);
    let mut saved = manifest(&backup_root);
    assert_eq!(saved.format_version, 2);
    assert_eq!(saved.last_sequence, 0);
    assert_eq!(saved.flushed_sequence, 0);
    assert_eq!(saved.flushed_wal_id, 0);
    assert_eq!(saved.active_wal_id, 1);
    assert_eq!(saved.next_wal_id, 2);
    assert!(saved.latest_checkpoint.is_some());
    append_frame(&backup_root, 1);
    saved.last_sequence = 1;
    save_manifest(&backup_root, &saved);
    if v1 {
        downgrade_manifest_v1(&backup_root);
    }
    seed_lock(&backup_root);
    backup_root
}

#[test]
fn offline_v2_record_source_refuses_before_absent_destination_acquisition() {
    let temp = tempfile::tempdir().unwrap();
    let backup = prepared_backup(temp.path(), false);
    let destination = temp.path().join("absent-v2-target");
    let before = tree(&backup);
    assert!(!destination.exists());
    let error = PraxisEngine::restore_from_backup(&backup, &destination).unwrap_err();
    assert_authority(error);
    assert!(tree(&backup) == before, "restore changed source");
    assert!(
        !destination.exists(),
        "restore acquired absent target before WAL classification"
    );
}

#[test]
fn offline_v1_record_source_refuses_before_absent_destination_acquisition() {
    let temp = tempfile::tempdir().unwrap();
    let backup = prepared_backup(temp.path(), true);
    let destination = temp.path().join("absent-v1-target");
    let before = tree(&backup);
    assert!(!destination.exists());
    let error = PraxisEngine::restore_from_backup(&backup, &destination).unwrap_err();
    assert_authority(error);
    assert!(tree(&backup) == before, "restore changed v1 source");
    assert!(
        !destination.exists(),
        "restore acquired absent target before WAL classification"
    );
}

#[test]
fn live_backup_refuses_record_source_before_absent_destination_acquisition() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("live-generic");
    fs::create_dir_all(&source_root).unwrap();
    seed_lock(&source_root);
    let source = PraxisEngine::open(PraxisConfig::new(&source_root)).unwrap();
    source.put("record", "retained").unwrap();
    source.flush().unwrap();
    let saved = manifest(&source_root);
    assert_eq!(saved.flushed_sequence, 1);
    assert_eq!(saved.flushed_wal_id, 1);
    assert_eq!(saved.active_wal_id, 2);
    append_frame(&source_root, 2);
    let destination = temp.path().join("absent-live-target");
    let before = tree(&source_root);
    assert!(!destination.exists());
    let error = source.backup_to(&destination).unwrap_err();
    assert_authority(error);
    assert!(
        !destination.exists(),
        "live backup acquired target before WAL classification"
    );
    assert!(tree(&source_root) == before, "live backup changed source");
    drop(source);
    assert_eq!(
        fs::read(source_root.join(LOCK)).unwrap(),
        b"persistent source lease bytes"
    );
}

#[test]
fn retired_generic_wal_control_refuses_before_restore_creates_destination() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    let backup_root = temp.path().join("backup");
    let source = PraxisEngine::open(PraxisConfig::new(&source_root)).unwrap();
    source.put("ordinary", "row").unwrap();
    source.flush().unwrap();
    source.backup_to(&backup_root).unwrap();
    drop(source);
    let saved = manifest(&backup_root);
    assert_eq!(saved.flushed_sequence, 1);
    assert_eq!(saved.flushed_wal_id, 1);
    assert_eq!(saved.active_wal_id, 2);

    // A backup copies only WAL 2; add a canonical retained WAL 1 whose
    // complete control would otherwise be omitted from Capture::wals.
    let mut retired = fs::read(canonical_wal(&backup_root, 2)).unwrap()[..16].to_vec();
    retired[8..16].copy_from_slice(&1u64.to_le_bytes());
    retired.extend(frame());
    fs::write(canonical_wal(&backup_root, 1), retired).unwrap();
    seed_lock(&backup_root);
    let before = tree(&backup_root);
    let destination = temp.path().join("absent-retired-target");
    let error = PraxisEngine::restore_from_backup(&backup_root, &destination).unwrap_err();
    assert_authority(error);
    assert!(
        !destination.exists(),
        "retired WAL bypass created restore target"
    );
    assert!(tree(&backup_root) == before, "retired source changed");
}

#[test]
fn retired_partial_header_is_tolerated_but_active_partial_header_is_not() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    let backup_root = temp.path().join("backup");
    let source = PraxisEngine::open(PraxisConfig::new(&source_root)).unwrap();
    source.put("kept", "row").unwrap();
    source.flush().unwrap();
    source.backup_to(&backup_root).unwrap();
    drop(source);
    let mut retired_header = fs::read(canonical_wal(&backup_root, 2)).unwrap()[..16].to_vec();
    retired_header[8..16].copy_from_slice(&1u64.to_le_bytes());
    for cut in [3, 12] {
        fs::write(canonical_wal(&backup_root, 1), &retired_header[..cut]).unwrap();
        let target = temp.path().join(format!("restored-{cut}"));
        PraxisEngine::restore_from_backup(&backup_root, &target).unwrap();
        let restored = PraxisEngine::open(PraxisConfig::new(&target)).unwrap();
        assert_eq!(restored.get("kept").unwrap().unwrap().as_ref(), b"row");
    }

    let broken_active = temp.path().join("broken-active");
    fs::write(
        canonical_wal(&backup_root, 2),
        &fs::read(canonical_wal(&backup_root, 2)).unwrap()[..12],
    )
    .unwrap();
    let error = PraxisEngine::restore_from_backup(&backup_root, &broken_active).unwrap_err();
    assert!(matches!(error, PraxisError::Corrupt { .. }), "{error:?}");
    assert!(!broken_active.exists());
}

#[test]
fn large_legacy_retired_frames_and_huge_advertised_torn_length_keep_compatibility() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    let valid_backup = temp.path().join("valid-large");
    let torn_backup = temp.path().join("torn-huge-length");
    let source = PraxisEngine::open(PraxisConfig::new(&source_root)).unwrap();
    source.put("kept", "row").unwrap();
    source.flush().unwrap();
    source.backup_to(&valid_backup).unwrap();
    source.backup_to(&torn_backup).unwrap();
    drop(source);

    let mut payload = Vec::new();
    payload.extend(1u64.to_le_bytes());
    payload.extend(1u32.to_le_bytes());
    payload.push(1); // v1 Put
    payload.extend(7u32.to_le_bytes());
    payload.extend(b"default");
    payload.extend((9 * 1024 * 1024u32).to_le_bytes());
    payload.extend(vec![b'K'; 9 * 1024 * 1024]);
    payload.extend(1u32.to_le_bytes());
    payload.push(b'V');
    let mut frame = 0x5457_414cu32.to_le_bytes().to_vec();
    frame.extend((payload.len() as u32).to_le_bytes());
    frame.extend(crc32fast::hash(&payload).to_le_bytes());
    frame.extend(payload);
    let mut retained = fs::read(canonical_wal(&valid_backup, 2)).unwrap()[..16].to_vec();
    retained[8..16].copy_from_slice(&1u64.to_le_bytes());
    retained.extend(frame);
    fs::write(canonical_wal(&valid_backup, 1), retained).unwrap();
    let valid_target = temp.path().join("valid-large-target");
    PEAK.with(|peak| peak.set(Some(0)));
    let restored = PraxisEngine::restore_from_backup(&valid_backup, &valid_target);
    let peak = PEAK.with(|peak| peak.replace(None)).unwrap();
    assert!(
        peak < 2 * 1024 * 1024,
        "large valid v1 frame requested {peak} bytes"
    );
    restored.unwrap();
    let valid = PraxisEngine::open(PraxisConfig::new(&valid_target)).unwrap();
    assert_eq!(valid.get("kept").unwrap().unwrap().as_ref(), b"row");
    drop(valid);

    let mut torn_payload = 1u64.to_le_bytes().to_vec();
    torn_payload.extend(0u32.to_le_bytes());
    torn_payload.extend(vec![0u8; 9 * 1024 * 1024]);
    let wrong_crc = crc32fast::hash(&torn_payload[..12]) ^ 1;
    let mut torn_frame = 0x5457_414cu32.to_le_bytes().to_vec();
    torn_frame.extend(u32::MAX.to_le_bytes());
    torn_frame.extend(wrong_crc.to_le_bytes());
    torn_frame.extend(torn_payload);
    let mut retired = fs::read(canonical_wal(&torn_backup, 2)).unwrap()[..16].to_vec();
    retired[8..16].copy_from_slice(&1u64.to_le_bytes());
    retired.extend(torn_frame);
    fs::write(canonical_wal(&torn_backup, 1), retired).unwrap();
    let torn_target = temp.path().join("torn-large-target");
    PEAK.with(|peak| peak.set(Some(0)));
    let restored = PraxisEngine::restore_from_backup(&torn_backup, &torn_target);
    let peak = PEAK.with(|peak| peak.replace(None)).unwrap();
    assert!(
        peak < 2 * 1024 * 1024,
        "huge v1 length requested {peak} bytes"
    );
    restored.unwrap();
    let torn = PraxisEngine::open(PraxisConfig::new(&torn_target)).unwrap();
    assert_eq!(torn.get("kept").unwrap().unwrap().as_ref(), b"row");
}

#[test]
fn record_control_refusal_preserves_existing_restore_destination() {
    let temp = tempfile::tempdir().unwrap();
    let backup = prepared_backup(temp.path(), false);
    let destination = temp.path().join("existing-target");
    let existing = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
    existing.put("kept", "old").unwrap();
    drop(existing);
    let before_source = tree(&backup);
    let before_destination = tree(&destination);
    let error = PraxisEngine::restore_from_backup(&backup, &destination).unwrap_err();
    assert_authority(error);
    assert!(tree(&backup) == before_source, "restore changed source");
    assert!(
        tree(&destination) == before_destination,
        "restore changed existing target"
    );
}

fn sized_catalog_frame(total_len: usize) -> Vec<u8> {
    let value_len = total_len - 168;
    let mut payload = 1u64.to_le_bytes().to_vec();
    payload.extend(2u32.to_le_bytes());
    payload.push(6);
    payload.extend(120u32.to_le_bytes());
    payload.extend(&CATALOG_BOOTSTRAP[33..153]);
    payload.push(1); // Put
    payload.extend(1u32.to_le_bytes());
    payload.push(b'x');
    payload.extend(1u32.to_le_bytes());
    payload.push(b'k');
    payload.extend((value_len as u32).to_le_bytes());
    payload.resize(payload.len() + value_len, b'v');
    let mut frame = 0x5457_4132u32.to_le_bytes().to_vec();
    frame.extend((payload.len() as u32).to_le_bytes());
    frame.extend(crc32fast::hash(&payload).to_le_bytes());
    frame.extend(crc32fast::hash(&frame).to_le_bytes());
    frame.extend(payload);
    assert_eq!(frame.len(), total_len);
    frame
}

#[test]
fn catalog_backup_preflight_streams_overlimit_before_whole_frame_allocation() {
    let exact = sized_catalog_frame(1_048_576);
    assert_eq!(
        u32::from_le_bytes(exact[8..12].try_into().unwrap()),
        0xef4d_77c6
    );
    let oversized = sized_catalog_frame(1_048_577);
    let mut bad_crc = oversized.clone();
    bad_crc[40] ^= 1;
    for retired in [false, true] {
        for (case, frame) in [
            ("exact", exact.as_slice()),
            ("oversized", oversized.as_slice()),
            ("bad-crc", bad_crc.as_slice()),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let source = PraxisEngine::open(PraxisConfig::new(temp.path().join("source"))).unwrap();
            if retired {
                source.put("kept", "row").unwrap();
                source.flush().unwrap();
            }
            let bundle = temp.path().join("bundle");
            source.backup_to(&bundle).unwrap();
            drop(source);
            if retired {
                let mut bytes = fs::read(canonical_wal(&bundle, 2)).unwrap()[..16].to_vec();
                bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
                bytes.extend_from_slice(frame);
                fs::write(canonical_wal(&bundle, 1), bytes).unwrap();
            } else {
                OpenOptions::new()
                    .append(true)
                    .open(canonical_wal(&bundle, 1))
                    .unwrap()
                    .write_all(frame)
                    .unwrap();
            }
            let destination = temp.path().join("absent-target");
            let before = tree(&bundle);
            PEAK.with(|peak| peak.set(Some(0)));
            let result = PraxisEngine::restore_from_backup(&bundle, &destination);
            let peak = PEAK.with(|peak| peak.replace(None)).unwrap();
            let error = result.unwrap_err();
            match case {
                "exact" => assert!(
                    matches!(error, PraxisError::CatalogAuthorityWalRequired { .. }),
                    "{error:?}"
                ),
                "oversized" => assert!(
                    error
                        .to_string()
                        .contains("catalog WAL frame exceeds 1 MiB limit"),
                    "{error:?}"
                ),
                "bad-crc" => assert!(
                    error.to_string().contains("WAL checksum mismatch"),
                    "{error:?}"
                ),
                _ => unreachable!(),
            }
            let limit = if case == "exact" {
                2 * 1024 * 1024
            } else {
                512 * 1024
            };
            assert!(
                peak < limit,
                "{case} retired={retired} requested {peak} bytes"
            );
            assert!(!destination.exists(), "preflight acquired destination");
            assert_eq!(tree(&bundle), before, "preflight changed source");
        }
    }
}

#[test]
fn live_catalog_backup_preflight_streams_active_and_retired_frames() {
    let exact = sized_catalog_frame(1_048_576);
    let oversized = sized_catalog_frame(1_048_577);
    let mut bad_crc = oversized.clone();
    bad_crc[40] ^= 1;
    for retired in [false, true] {
        for (case, frame) in [
            ("exact", exact.as_slice()),
            ("oversized", oversized.as_slice()),
            ("bad-crc", bad_crc.as_slice()),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("source");
            let source = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
            if retired {
                source.put("kept", "row").unwrap();
                source.flush().unwrap();
                let mut retired_header = fs::read(canonical_wal(&root, 2)).unwrap()[..16].to_vec();
                retired_header[8..16].copy_from_slice(&1u64.to_le_bytes());
                fs::write(canonical_wal(&root, 1), retired_header).unwrap();
            }
            OpenOptions::new()
                .append(true)
                .open(canonical_wal(&root, 1))
                .unwrap()
                .write_all(frame)
                .unwrap();
            let destination = temp.path().join("absent-target");
            let before = tree(&root);
            PEAK.with(|peak| peak.set(Some(0)));
            let result = source.backup_to(&destination);
            let peak = PEAK.with(|peak| peak.replace(None)).unwrap();
            let error = result.unwrap_err();
            match case {
                "exact" => assert!(
                    matches!(error, PraxisError::CatalogAuthorityWalRequired { .. }),
                    "{error:?}"
                ),
                "oversized" => assert!(
                    error
                        .to_string()
                        .contains("catalog WAL frame exceeds 1 MiB limit"),
                    "{error:?}"
                ),
                "bad-crc" => assert!(
                    error.to_string().contains("WAL checksum mismatch"),
                    "{error:?}"
                ),
                _ => unreachable!(),
            }
            let limit = if case == "exact" {
                2 * 1024 * 1024
            } else {
                512 * 1024
            };
            assert!(
                peak < limit,
                "{case} retired={retired} requested {peak} bytes"
            );
            assert!(!destination.exists(), "live preflight acquired target");
            assert_eq!(tree(&root), before, "live preflight changed source");
        }
    }
}

#[test]
fn ordinary_v2_frame_above_catalog_limit_remains_backup_and_restore_compatible() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("source");
    let bundle = temp.path().join("bundle");
    let destination = temp.path().join("restored");
    let source = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
    let value = vec![b'U'; 1_200_000];
    source.put("large-user", value.clone()).unwrap();
    let wal = fs::read(canonical_wal(&root, 1)).unwrap();
    assert!(wal.len() > 1_048_576 + 16);
    assert_eq!(
        u32::from_le_bytes(wal[16..20].try_into().unwrap()),
        0x5457_4132
    );
    assert_eq!(wal[44], 1, "frame must begin with an ordinary Put");
    source.backup_to(&bundle).unwrap();
    drop(source);
    PraxisEngine::restore_from_backup(&bundle, &destination).unwrap();
    let restored = PraxisEngine::open(PraxisConfig::new(&destination)).unwrap();
    assert_eq!(restored.get("large-user").unwrap().unwrap().as_ref(), value);
}

#[test]
fn healthy_v1_v2_reopen_and_torn_active_tail_remain_recoverable() {
    for legacy_v1 in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy");
        let original = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
        original.put("kept", "value").unwrap();
        drop(original);
        if legacy_v1 {
            downgrade_manifest_v1(&root);
        }
        let path = canonical_wal(&root, 1);
        let complete_len = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&0x5457_4132u32.to_le_bytes()[..3])
            .unwrap();
        let reopened = PraxisEngine::open(PraxisConfig::new(&root)).unwrap();
        assert_eq!(reopened.get("kept").unwrap().unwrap().as_ref(), b"value");
        assert_eq!(fs::metadata(&path).unwrap().len(), complete_len);
    }
}
