use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PraxisError {
    #[error("storage handle requires recovery; close and reopen it before continuing")]
    RecoveryRequired,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("toml error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("corrupt data in {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("stored engine config does not match requested config: {0}")]
    ConfigMismatch(String),
    #[error("key not found")]
    KeyNotFound,
    #[error("compare-and-swap failed")]
    CompareAndSwapFailed,
    #[error("transaction conflict on key in column family {cf}: {key}")]
    TransactionConflict { cf: String, key: String },
    #[error("unknown column family: {0}")]
    UnknownColumnFamily(String),
    #[error("column family already exists: {0}")]
    ColumnFamilyExists(String),
    #[error("cannot drop the default column family")]
    CannotDropDefaultColumnFamily,
    #[error("write stalled: {reason}")]
    WriteStalled { reason: String },
    #[error("unsupported accelerator backend: {0}")]
    UnsupportedAccelerator(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("background task failed: {0}")]
    TaskJoin(String),
    #[error("maintenance runtime is already running")]
    MaintenanceRuntimeRunning,
    #[error("maintenance runtime is not running")]
    MaintenanceRuntimeNotRunning,
    #[error("maintenance job not found: {0}")]
    MaintenanceJobNotFound(u64),
    #[error("query error: {0}")]
    Query(String),
    #[error("catalog error: {0}")]
    Catalog(String),
    #[error("replication error: {0}")]
    Replication(String),
}

pub type Result<T> = std::result::Result<T, PraxisError>;

impl PraxisError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::WriteStalled { .. } | Self::TaskJoin(_) | Self::Server(_)
        )
    }
}
