use praxis::io::{read_file_with_policy, write_file_with_policy};
use tempfile::tempdir;

#[test]
fn write_policies_replace_truncate_and_reopen_files() {
    let dir = tempdir().unwrap();
    for requested_direct_io in [false, true] {
        let path = dir
            .path()
            .join(format!("replacement-{requested_direct_io}.bin"));
        for bytes in [
            vec![19; 8192],
            vec![0, 127, 255],
            Vec::new(),
            vec![42; 4096],
        ] {
            let execution = write_file_with_policy(&path, &bytes, requested_direct_io).unwrap();
            assert_eq!(execution.requested_direct_io, requested_direct_io);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
            assert_eq!(read_file_with_policy(&path, false).unwrap().0, bytes);
        }
    }
}

#[test]
fn write_policies_propagate_file_creation_errors() {
    let dir = tempdir().unwrap();
    for requested_direct_io in [false, true] {
        let absent_parent = dir.path().join("absent").join("data.bin");
        assert!(write_file_with_policy(&absent_parent, b"data", requested_direct_io).is_err());
        assert!(!absent_parent.exists());
        assert!(write_file_with_policy(dir.path(), b"data", requested_direct_io).is_err());
        assert!(dir.path().is_dir());
    }
}
