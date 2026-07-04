//! Configuration loading for the Bitwarden API key (device auth).
//!
//! The API key (`client_id` / `client_secret`) only authenticates the *device*
//! with Bitwarden — it does NOT unlock the vault. Unlocking always requires the
//! master password, which is handled separately (systemd credential or an
//! interactive `systemd-ask-password` prompt) and is **never** stored here.
//!
//! Sources, in order of precedence:
//!   1. Environment variables `BW_CLIENTID` / `BW_CLIENTSECRET` (e.g. provided
//!      via a systemd `EnvironmentFile=`). These take precedence.
//!   2. A TOML file at `~/.config/bitwarden-ssh-agent/config.toml`.
//!
//! The config file must not be group/world readable (mode <= 0600), otherwise
//! we refuse to start.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use secrecy::SecretString;
use serde::Deserialize;

/// Bitwarden device API credentials (personal API key).
pub struct ApiKey {
    pub client_id: String,
    pub client_secret: SecretString,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    /// Bitwarden personal API key client id (`user.<uuid>`).
    client_id: Option<String>,
    /// Bitwarden personal API key client secret.
    client_secret: Option<String>,
    /// Optional override for the Bitwarden server base URL (self-hosted).
    #[serde(default)]
    server: Option<String>,
}

/// Fully resolved configuration for the daemon.
pub struct Config {
    /// Bitwarden device API key, if it could be resolved from any source.
    pub api_key: Option<ApiKey>,
    /// Optional self-hosted server URL (`bw config server ...`).
    pub server: Option<String>,
}

impl Config {
    /// Load configuration from the environment and the default config path.
    pub fn load() -> Result<Self> {
        Self::load_from(default_config_path())
    }

    /// Load configuration, reading the TOML file from `path` if it exists.
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let file = read_config_file(path.as_ref())?;

        // Environment variables win over the file.
        let env_id = non_empty_env("BW_CLIENTID");
        let env_secret = non_empty_env("BW_CLIENTSECRET");

        let client_id = env_id.or_else(|| file.as_ref().and_then(|f| f.client_id.clone()));
        let client_secret =
            env_secret.or_else(|| file.as_ref().and_then(|f| f.client_secret.clone()));

        let api_key = match (client_id, client_secret) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => Some(ApiKey {
                client_id: id,
                client_secret: SecretString::from(secret),
            }),
            (Some(_), None) | (None, Some(_)) => {
                bail!(
                    "incomplete Bitwarden API key: both client_id and client_secret \
                     must be set (via BW_CLIENTID/BW_CLIENTSECRET or the config file)"
                );
            }
            _ => None,
        };

        let server = std::env::var("BW_SERVER")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| file.and_then(|f| f.server));

        Ok(Config { api_key, server })
    }
}

/// `~/.config/bitwarden-ssh-agent/config.toml`, honouring `$XDG_CONFIG_HOME`.
pub fn default_config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            home.join(".config")
        });
    base.join("bitwarden-ssh-agent").join("config.toml")
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn read_config_file(path: &Path) -> Result<Option<ConfigFile>> {
    if !path.exists() {
        return Ok(None);
    }

    check_permissions(path)?;

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let parsed: ConfigFile = toml::from_str(&contents)
        .with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(Some(parsed))
}

/// Refuse to read a config file that is readable by group or other, since it may
/// contain the API secret.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat config file {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "config file {} has insecure permissions {:#o}; it may contain your \
             Bitwarden API secret. Run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
