//! Vault unlock state machine.
//!
//! The daemon starts either already unlocked (if a systemd credential with the
//! master password was provisioned) or locked. When locked, the first client
//! request triggers an interactive `systemd-ask-password` prompt. A shared async
//! mutex guards the state so that if several SSH connections race in during the
//! locked window, only one prompt fires and the rest wait on it.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use secrecy::SecretString;
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::agent::VaultKey;
use crate::bitwarden::{BitwardenCli, Session};
use crate::config::ApiKey;

/// Filename of the systemd credential holding the master password.
const MASTER_PW_CREDENTIAL: &str = "bw_master_password";

/// How long the on-demand `systemd-ask-password` prompt waits for an answer.
///
/// The default (~90s, or the ~45s seen in practice) makes a *headless* daemon —
/// where usually nothing is watching the ask-password queue — hang every client
/// request for a long time before failing. The reliable interactive path is now
/// the `unlock` subcommand; this prompt is only a bonus for users who run their
/// own ask-password agent, so a short window is plenty and fails fast otherwise.
const ASK_PASSWORD_TIMEOUT_SECS: u32 = 10;

/// Result of a successful manual unlock via the control channel.
pub enum UnlockOutcome {
    /// The vault was locked and is now unlocked; carries the SSH key count.
    Unlocked(usize),
    /// The vault was already unlocked; carries the currently-served key count.
    AlreadyUnlocked(usize),
}

/// Result of a manual refresh request via the control channel.
pub enum RefreshOutcome {
    /// The vault was already unlocked and its keys were re-synced/reloaded.
    Refreshed(usize),
    /// The vault is still locked; there is nothing to refresh yet.
    StillLocked,
}

/// Why a manual unlock failed, so the caller can report a specific reason.
pub enum UnlockError {
    /// `bw unlock` rejected the master password.
    WrongPassword(String),
    /// Anything else (e.g. `bw` unreachable, device not logged in, load error).
    Other(anyhow::Error),
}

enum State {
    Locked,
    Unlocked {
        /// The live `bw` session key, kept so we can re-sync and reload keys
        /// (e.g. on SIGHUP) without re-prompting for the master password.
        session: Arc<Session>,
        keys: Arc<Vec<VaultKey>>,
    },
}

struct Inner {
    cli: BitwardenCli,
    api_key: Option<ApiKey>,
    state: Mutex<State>,
}

/// Shared, clonable handle to the unlock state and cached keys.
#[derive(Clone)]
pub struct UnlockManager {
    inner: Arc<Inner>,
}

impl UnlockManager {
    pub fn new(cli: BitwardenCli, api_key: Option<ApiKey>) -> Self {
        Self {
            inner: Arc::new(Inner {
                cli,
                api_key,
                state: Mutex::new(State::Locked),
            }),
        }
    }

    /// Return the cached keys, unlocking the vault on first use if necessary.
    ///
    /// Holding the mutex across the (potentially interactive) unlock serializes
    /// concurrent callers: the first does the work, the rest observe the
    /// resulting `Unlocked` state and return immediately.
    pub async fn keys(&self) -> Result<Arc<Vec<VaultKey>>> {
        let mut state = self.inner.state.lock().await;
        if let State::Unlocked { keys, .. } = &*state {
            return Ok(Arc::clone(keys));
        }

        log::info!(
            "vault locked; trying systemd-ask-password (best-effort). If this times \
             out, unlock the daemon directly with `bitwarden-ssh-agent unlock`"
        );
        let password = ask_password().await?;
        let (session, keys) = self.unlock_and_load(&password).await?;
        *state = State::Unlocked {
            session,
            keys: Arc::clone(&keys),
        };
        Ok(keys)
    }

    /// Re-sync the vault and reload SSH keys using the existing session.
    ///
    /// Triggered by SIGHUP, or by the `import`/`unlock` commands over the
    /// control socket, so newly-added vault items can be picked up without
    /// restarting the daemon. Reuses the already-unlocked session, so the master
    /// password is never re-prompted. If the vault is still locked (never
    /// unlocked yet), there is nothing to refresh — the next client request will
    /// prompt as usual.
    pub async fn refresh(&self) -> Result<RefreshOutcome> {
        let mut state = self.inner.state.lock().await;
        let session = match &*state {
            State::Locked => {
                log::info!("refresh requested but vault is locked; nothing to do yet");
                return Ok(RefreshOutcome::StillLocked);
            }
            State::Unlocked { session, .. } => Arc::clone(session),
        };

        log::info!("refreshing vault: re-syncing and reloading SSH keys");
        match self.load_keys(&session).await {
            Ok(keys) => {
                let count = keys.len();
                *state = State::Unlocked { session, keys };
                Ok(RefreshOutcome::Refreshed(count))
            }
            Err(e) => {
                // `bw` has a known quirk (and, on some setups, an actual vault
                // timeout policy) where a previously-valid session starts being
                // rejected by commands like `list items` after a while, even
                // though sync and other calls with the same session still work.
                // If a systemd credential is provisioned, silently re-derive a
                // fresh session from it rather than surfacing a cryptic "Vault
                // is locked" — this is exactly the auto-unlock path already used
                // at startup, just triggered here instead of on boot.
                log::warn!(
                    "refresh with the existing session failed ({e:#}); trying the \
                     systemd credential for a silent re-unlock before giving up"
                );
                match read_master_password_credential() {
                    Ok(Some(password)) => match self.unlock_and_load(&password).await {
                        Ok((session, keys)) => {
                            let count = keys.len();
                            log::info!(
                                "silently re-unlocked via systemd credential; now serving \
                                 {count} SSH key(s)"
                            );
                            *state = State::Unlocked { session, keys };
                            Ok(RefreshOutcome::Refreshed(count))
                        }
                        Err(_) => {
                            // Leave `state` untouched: the stale session's already-cached
                            // keys still work fine for signing, only the refresh failed.
                            Err(e).context(
                                "listing SSH keys from vault (re-unlock via systemd \
                                 credential also failed; existing cached keys are still \
                                 served, but run `bitwarden-ssh-agent unlock` to refresh)",
                            )
                        }
                    },
                    _ => Err(e).context(
                        "listing SSH keys from vault (no systemd credential to silently \
                         retry with; run `bitwarden-ssh-agent unlock` to refresh)",
                    ),
                }
            }
        }
    }

    /// At startup, try to unlock non-interactively using a systemd credential.
    ///
    /// Returns `Ok(true)` if the vault was unlocked and keys cached, `Ok(false)`
    /// if no credential was provisioned (daemon stays locked and will prompt
    /// on first use). Errors only on an actual unlock failure with a credential
    /// that *was* present.
    pub async fn try_startup_unlock(&self) -> Result<bool> {
        let Some(password) = read_master_password_credential()? else {
            return Ok(false);
        };

        log::info!("found master password credential; unlocking vault at startup");
        let (session, keys) = self.unlock_and_load(&password).await?;
        let count = keys.len();
        let mut state = self.inner.state.lock().await;
        *state = State::Unlocked { session, keys };
        log::info!("vault unlocked at startup; cached {count} SSH key(s)");
        Ok(true)
    }

    /// Manually unlock the vault with a password supplied over the control
    /// channel (the `unlock` subcommand).
    ///
    /// Takes the same state mutex as [`Self::keys`], so a manual unlock racing
    /// with an in-flight on-demand `systemd-ask-password` attempt (or another
    /// concurrent `unlock`) is serialized by the same single-flight guarantee:
    /// whoever gets the lock first does the work, and a caller that finds the
    /// vault already unlocked returns immediately.
    pub async fn unlock_with_password(
        &self,
        password: &SecretString,
    ) -> std::result::Result<UnlockOutcome, UnlockError> {
        let mut state = self.inner.state.lock().await;
        if let State::Unlocked { keys, .. } = &*state {
            return Ok(UnlockOutcome::AlreadyUnlocked(keys.len()));
        }

        self.ensure_logged_in().await.map_err(UnlockError::Other)?;
        // A failure here, after a successful login, is overwhelmingly a wrong
        // master password, so surface it as such for a clear client message.
        let session = Arc::new(
            self.inner
                .cli
                .unlock(password)
                .await
                .map_err(|e| UnlockError::WrongPassword(format!("{e:#}")))?,
        );
        let keys = self
            .load_keys(&session)
            .await
            .map_err(UnlockError::Other)?;
        let count = keys.len();
        *state = State::Unlocked { session, keys };
        log::info!("vault unlocked via control channel; cached {count} SSH key(s)");
        Ok(UnlockOutcome::Unlocked(count))
    }

    /// Ensure the `bw` device is logged in: via the API key if configured, else
    /// require that a prior `bw login` already authenticated the device.
    async fn ensure_logged_in(&self) -> Result<()> {
        match &self.inner.api_key {
            Some(api_key) => self.inner.cli.login_with_api_key(api_key).await,
            None => {
                // No API key configured: the device must already be logged in
                // (e.g. a prior `bw login`), otherwise we cannot proceed.
                let status = self.inner.cli.status().await?;
                if status.status == "unauthenticated" {
                    bail!(
                        "no Bitwarden API key configured and the CLI is not logged in; \
                         set BW_CLIENTID/BW_CLIENTSECRET or run `bw login` once"
                    );
                }
                Ok(())
            }
        }
    }

    /// Perform the full login + unlock + load-keys flow for a given password,
    /// returning the live session (retained for later refreshes) and the keys.
    async fn unlock_and_load(
        &self,
        password: &SecretString,
    ) -> Result<(Arc<Session>, Arc<Vec<VaultKey>>)> {
        self.ensure_logged_in().await?;
        let session = Arc::new(self.inner.cli.unlock(password).await?);
        let keys = self.load_keys(&session).await?;
        Ok((session, keys))
    }

    /// Sync the vault and (re)load its SSH Key items using an existing session.
    async fn load_keys(&self, session: &Session) -> Result<Arc<Vec<VaultKey>>> {
        // Best-effort sync so freshly-added keys are visible.
        if let Err(e) = self.inner.cli.sync(session).await {
            log::warn!("vault sync failed (continuing with cached data): {e:#}");
        }

        let items = self
            .inner
            .cli
            .list_ssh_keys(session)
            .await
            .context("listing SSH keys from vault")?;

        let mut keys = Vec::with_capacity(items.len());
        for item in &items {
            match VaultKey::from_item(item) {
                Ok(key) => keys.push(key),
                Err(e) => log::warn!("skipping vault SSH key '{}': {e:#}", item.name),
            }
        }

        if keys.is_empty() {
            log::warn!(
                "vault unlocked but contains no usable SSH Key items \
                 (create one in Bitwarden of type 'SSH Key')"
            );
        } else {
            log::info!("loaded {} SSH key(s) into the agent", keys.len());
        }

        Ok(Arc::new(keys))
    }
}

/// Location of a systemd-provided credential, if running under `LoadCredential=`.
fn credential_path(name: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join(name))
}

/// Read the master password from the systemd credential, if present.
fn read_master_password_credential() -> Result<Option<SecretString>> {
    let Some(path) = credential_path(MASTER_PW_CREDENTIAL) else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let mut contents = std::fs::read_to_string(&path)
        .with_context(|| format!("reading master password credential {}", path.display()))?;
    // systemd-creds may or may not include a trailing newline.
    let password = contents.trim_end_matches(['\n', '\r']).to_string();
    contents.zeroize();
    if password.is_empty() {
        bail!(
            "master password credential {} is empty",
            path.display()
        );
    }
    Ok(Some(SecretString::from(password)))
}

/// Prompt for the master password interactively via `systemd-ask-password`,
/// which handles TTY / SSH askpass / plymouth / wall agents transparently.
async fn ask_password() -> Result<SecretString> {
    let output = Command::new("systemd-ask-password")
        .arg("--icon=dialog-password")
        .arg("--id=bitwarden-ssh-agent")
        // Short timeout: on a headless --user service nothing is usually
        // watching the ask-password queue, so without this the query hangs the
        // client for the full default (~90s) before failing. Fail fast instead
        // and let the user run `bitwarden-ssh-agent unlock`.
        .arg(format!("--timeout={ASK_PASSWORD_TIMEOUT_SECS}"))
        .arg("Bitwarden master password (to unlock SSH agent):")
        .stdin(Stdio::null())
        .output()
        .await
        .context("spawning systemd-ask-password (is systemd installed?)")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "systemd-ask-password failed ({}); no ask-password agent answered. \
             Unlock the daemon directly with `bitwarden-ssh-agent unlock`",
            err.trim()
        ));
    }

    let mut raw = String::from_utf8(output.stdout)
        .context("systemd-ask-password returned non-UTF8 output")?;
    let password = raw.trim_end_matches(['\n', '\r']).to_string();
    raw.zeroize();
    if password.is_empty() {
        bail!("no master password was entered");
    }
    Ok(SecretString::from(password))
}
