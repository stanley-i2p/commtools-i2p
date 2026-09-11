use crate::constants::{DEFAULT_SAM_HOST, DEFAULT_SAM_PORT};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreConfig {
    pub sam: SamConfig,
    pub storage: StorageConfig,
}

impl CoreConfig {
    pub fn new(storage_root: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        Ok(Self {
            sam: SamConfig::default(),
            storage: StorageConfig::new(storage_root)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamConfig {
    pub endpoint: SamEndpoint,
}

impl Default for SamConfig {
    fn default() -> Self {
        Self {
            endpoint: SamEndpoint {
                host: DEFAULT_SAM_HOST.to_string(),
                port: DEFAULT_SAM_PORT,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamEndpoint {
    host: String,
    port: u16,
}

impl SamEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ConfigError> {
        let host = host.into();
        let host = host.trim();

        if host.is_empty() {
            return Err(ConfigError::EmptySamHost);
        }
        if host.chars().any(char::is_whitespace) {
            return Err(ConfigError::InvalidSamHost);
        }
        if port == 0 {
            return Err(ConfigError::InvalidSamPort);
        }

        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Default for SamEndpoint {
    fn default() -> Self {
        SamConfig::default().endpoint
    }
}

impl fmt::Display for SamEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(formatter, "[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

impl FromStr for SamEndpoint {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
            let (host, suffix) = bracketed
                .split_once(']')
                .ok_or_else(|| ConfigError::InvalidSamEndpoint(value.to_string()))?;
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| ConfigError::InvalidSamEndpoint(value.to_string()))?;
            (host, port)
        } else {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| ConfigError::InvalidSamEndpoint(value.to_string()))?;
            if host.contains(':') {
                return Err(ConfigError::InvalidSamEndpoint(value.to_string()));
            }
            (host, port)
        };

        let port = port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidSamEndpoint(value.to_string()))?;
        Self::new(host, port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    root: PathBuf,
}

impl StorageConfig {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(ConfigError::EmptyStorageRoot);
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("SAM host must not be empty")]
    EmptySamHost,
    #[error("SAM host must not contain whitespace")]
    InvalidSamHost,
    #[error("SAM port must be between 1 and 65535")]
    InvalidSamPort,
    #[error("invalid SAM endpoint: {0}")]
    InvalidSamEndpoint(String),
    #[error("storage root must not be empty")]
    EmptyStorageRoot,
}
