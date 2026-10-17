use praxis::store::{RecordId, RecordStore, StorageEngine};
use praxis::{PraxisConfig, PraxisEngine};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) const LOCK_NAME: &str = ".praxor.writer.lock";

#[derive(Clone, Copy, Debug)]
pub(super) enum Kind {
    Core,
    Pointer,
    Record,
}

pub(super) enum Owner {
    Core(PraxisEngine),
    Pointer(Box<StorageEngine>),
    Record(RecordStore),
}

impl Kind {
    pub(super) fn open(self, root: &Path) -> praxis::Result<Owner> {
        Ok(match self {
            Self::Core => Owner::Core(PraxisEngine::open(PraxisConfig::new(root))?),
            Self::Pointer => Owner::Pointer(Box::new(StorageEngine::open(root, 1024)?)),
            Self::Record => Owner::Record(RecordStore::open(root)?),
        })
    }
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Pointer => "pointer",
            Self::Record => "record",
        }
    }
}

impl Owner {
    pub(super) fn write_marker(&mut self) {
        match self {
            Self::Core(engine) => {
                engine.put("marker", "acknowledged").unwrap();
                engine.flush().unwrap();
            }
            Self::Pointer(engine) => {
                assert_eq!(engine.put(b"acknowledged", &[]).unwrap(), RecordId(1));
                engine.flush().unwrap();
            }
            Self::Record(store) => {
                assert_eq!(store.put(b"acknowledged").unwrap(), RecordId(1));
                store.flush().unwrap();
            }
        }
    }
    pub(super) fn assert_marker(&self) {
        let bytes = match self {
            Self::Core(engine) => engine.get("marker").unwrap().unwrap().to_vec(),
            Self::Pointer(engine) => engine.fetch(RecordId(1)).unwrap(),
            Self::Record(store) => store.get(RecordId(1)).unwrap(),
        };
        assert_eq!(bytes, b"acknowledged");
    }
}

pub(super) fn denied<T>(result: praxis::Result<T>) {
    match result {
        Err(praxis::PraxisError::AlreadyOpen { .. }) => {}
        Err(error) => panic!("expected typed AlreadyOpen, received {error}"),
        Ok(_) => panic!("a second independent writer was admitted"),
    }
}

pub(super) fn contents(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == LOCK_NAME {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                visit(base, &entry.path(), out);
            } else {
                out.insert(
                    entry.path().strip_prefix(base).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
