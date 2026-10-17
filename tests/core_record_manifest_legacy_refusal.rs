use praxis::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for item in std::fs::read_dir(path).unwrap() {
            let item = item.unwrap();
            if item.file_name() == ".praxor.writer.lock" {
                continue;
            }
            let path = item.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if item.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                visit(root, &path, result);
            } else {
                result.insert(relative, Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn legacy_manifest_never_silently_ignores_attempted_record_authority() {
    for attempted in [
        "\n[record_authority]\n",
        "\n[record_authority]\nkind = 'core_records'\n",
        "\nrecord_authority = false\n",
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let config = PraxisConfig::new(temporary.path());
        drop(PraxisEngine::open(config.clone()).unwrap());
        let path = temporary.path().join("MANIFEST");
        let mut manifest = std::fs::read_to_string(&path).unwrap();
        // Keep scalar evidence at the TOML root rather than inside a prior table.
        if attempted.contains("= false") {
            manifest = format!("{attempted}\n{manifest}");
        } else {
            manifest.push_str(attempted);
        }
        std::fs::write(path, manifest).unwrap();
        let before = tree(temporary.path());
        assert!(
            PraxisEngine::open(config).is_err(),
            "legacy open accepted {attempted:?}"
        );
        assert_eq!(
            tree(temporary.path()),
            before,
            "refusal mutated legacy authority"
        );
    }
}
