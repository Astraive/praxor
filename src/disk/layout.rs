use crate::errors::Result;
use crate::io::create_dir_all_durable;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct DiskLayout {
    root: PathBuf,
}

impl DiskLayout {
    pub fn create(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for dir in [
            "wal",
            "segments/0",
            "segments/1",
            "values",
            "checkpoints",
            "tmp",
        ] {
            create_dir_all_durable(&root.join(dir))?;
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("MANIFEST")
    }

    pub fn wal_path(&self, id: u64) -> PathBuf {
        self.root.join("wal").join(format!("{id:020}.wal"))
    }

    pub fn wal_root(&self) -> PathBuf {
        self.root.join("wal")
    }

    pub fn segment_path(&self, level: u32, id: u64) -> PathBuf {
        self.root
            .join("segments")
            .join(level.to_string())
            .join(format!("{id:020}.tseg"))
    }

    pub fn value_log_path(&self, id: u64) -> PathBuf {
        self.root.join("values").join(format!("{id:020}.tval"))
    }

    pub fn checkpoint_path(&self, id: u64) -> PathBuf {
        self.root.join("checkpoints").join(format!("{id:020}.chk"))
    }

    pub fn segment_root(&self) -> PathBuf {
        self.root.join("segments")
    }

    pub fn value_root(&self) -> PathBuf {
        self.root.join("values")
    }

    pub fn tmp_path(&self, name: &str) -> PathBuf {
        self.root.join("tmp").join(name)
    }
}
