use crate::config::PraxisConfig;
use crate::errors::Result;
use crate::io::{read_file_with_policy, write_file_with_policy};
use crate::manifest::model::Manifest;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::fs::File;

#[derive(Clone, Debug)]
pub struct ManifestStore {
    path: PathBuf,
}

impl ManifestStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load_or_create(&self, config: &PraxisConfig) -> Result<Manifest> {
        if self.path.exists() {
            let (bytes, _) = read_file_with_policy(&self.path, config.direct_io)?;
            Manifest::decode(&bytes, &self.path)
        } else {
            let manifest = Manifest::fresh(config);
            self.save_with_policy(&manifest, config.direct_io)?;
            Ok(manifest)
        }
    }

    pub fn save(&self, manifest: &Manifest) -> Result<()> {
        self.save_with_policy(manifest, false)
    }

    pub fn save_with_policy(&self, manifest: &Manifest, requested_direct_io: bool) -> Result<()> {
        let mut manifest = manifest.clone();
        manifest.validate_and_upgrade(&self.path)?;
        let tmp = self.path.with_extension("tmp");
        let bytes = toml::to_string_pretty(&manifest)?;
        write_file_with_policy(&tmp, bytes.as_bytes(), requested_direct_io)?;
        fs::rename(tmp, &self.path)?;
        sync_parent_dir(&self.path)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}
