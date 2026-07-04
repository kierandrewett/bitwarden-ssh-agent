//! Thin wrapper around the official Bitwarden `bw` CLI.
//!
//! There is no usable Rust SDK for the personal vault, so we shell out to the
//! Node-based `bw` CLI (`npm install -g @bitwarden/cli`). Secrets (API secret,
//! master password, session key) are passed to the subprocess through *its own*
//! environment, never process-wide env and never on the command line where they
//! would be visible in `ps`.

use std::process::Stdio;

use anyhow::{anyhow, bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroize;

use crate::config::ApiKey;

/// A Bitwarden vault session key (the value of `BW_SESSION`).
///
/// This decrypts vault items. It is held in memory for the daemon's lifetime and
/// zeroized on drop.
pub struct Session(SecretString);

impl Session {
    fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

/// A single SSH Key item from the vault (Bitwarden cipher type 5).
#[derive(Debug, Deserialize)]
pub struct SshKeyItem {
    /// Vault item UUID (kept for logging/diagnostics).
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
    #[serde(rename = "sshKey")]
    pub ssh_key: SshKeyData,
}

/// The `sshKey` object attached to an SSH Key cipher.
///
/// Only `private_key` is required for signing; `public_key` and
/// `key_fingerprint` are captured for completeness and diagnostics.
#[derive(Debug, Deserialize)]
pub struct SshKeyData {
    #[serde(rename = "privateKey")]
    pub private_key: String,
    #[allow(dead_code)]
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[allow(dead_code)]
    #[serde(rename = "keyFingerprint", default)]
    pub key_fingerprint: Option<String>,
}

/// Minimal shape used only to filter the `list items` output down to SSH keys.
#[derive(Debug, Deserialize)]
struct RawItem {
    #[serde(rename = "type")]
    item_type: i64,
}

/// `type` value for SSH Key ciphers.
const CIPHER_TYPE_SSH_KEY: i64 = 5;

/// Handle to the `bw` CLI. Locates the binary once.
#[derive(Clone)]
pub struct BitwardenCli {
    program: String,
    server: Option<String>,
}

impl BitwardenCli {
    pub fn new(server: Option<String>) -> Self {
        // Allow overriding the binary name/path for unusual installs.
        let program =
            std::env::var("BW_CLI_PATH").unwrap_or_else(|_| "bw".to_string());
        Self { program, server }
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        // Never let an inherited BW_SESSION or interactive prompts interfere.
        cmd.env_remove("BW_SESSION")
            .env("BW_NOINTERACTION", "true")
            .stdin(Stdio::null());
        cmd
    }

    /// Verify the `bw` CLI is actually invokable, returning its version string.
    pub async fn version(&self) -> Result<String> {
        let out = self
            .base_command()
            .arg("--version")
            .output()
            .await
            .with_context(|| {
                format!(
                    "failed to run `{}` — is the Bitwarden CLI installed? \
                     (`npm install -g @bitwarden/cli`)",
                    self.program
                )
            })?;
        if !out.status.success() {
            bail!("`{} --version` failed: {}", self.program, stderr(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Point the CLI at a self-hosted server, if configured. Idempotent.
    async fn configure_server(&self) -> Result<()> {
        let Some(server) = &self.server else {
            return Ok(());
        };
        let out = self
            .base_command()
            .args(["config", "server", server])
            .output()
            .await
            .context("running `bw config server`")?;
        if !out.status.success() {
            bail!(
                "`bw config server {}` failed: {}",
                server,
                stderr(&out.stderr)
            );
        }
        Ok(())
    }

    /// Current auth/lock status as reported by `bw status`.
    pub async fn status(&self) -> Result<Status> {
        let out = self
            .base_command()
            .arg("status")
            .output()
            .await
            .context("running `bw status`")?;
        if !out.status.success() {
            bail!("`bw status` failed: {}", stderr(&out.stderr));
        }
        let status: Status = serde_json::from_slice(&out.stdout)
            .context("parsing `bw status` output")?;
        Ok(status)
    }

    /// Ensure the device is logged in via the API key. No-op if already logged
    /// in. The API secret is passed through the subprocess env only.
    pub async fn login_with_api_key(&self, api_key: &ApiKey) -> Result<()> {
        // Short-circuit before touching the server config: `bw config server`
        // is rejected while the device is logged in ("Logout required before
        // server config update"), so running it unconditionally broke every
        // unlock on an already-logged-in self-hosted device.
        let status = self.status().await?;
        if status.is_logged_in() {
            log::debug!("bw already logged in (status: {})", status.status);
            return Ok(());
        }

        // Only now (logged out) is it valid to point the CLI at a self-hosted
        // server, which must happen before `bw login`.
        self.configure_server().await?;

        log::info!("logging in to Bitwarden with API key");
        let out = self
            .base_command()
            .args(["login", "--apikey"])
            .env("BW_CLIENTID", &api_key.client_id)
            .env("BW_CLIENTSECRET", api_key.client_secret.expose_secret())
            .output()
            .await
            .context("running `bw login --apikey`")?;
        if !out.status.success() {
            bail!("`bw login --apikey` failed: {}", stderr(&out.stderr));
        }
        Ok(())
    }

    /// Log the device out, if it is logged in. Used by `setup` to force a
    /// clean `bw login --apikey` so freshly-entered credentials are actually
    /// validated rather than silently accepted because a prior session existed.
    pub async fn logout(&self) -> Result<()> {
        let out = self
            .base_command()
            .arg("logout")
            .output()
            .await
            .context("running `bw logout`")?;
        // `bw logout` exits non-zero if already logged out; that's fine.
        if !out.status.success() {
            log::debug!("`bw logout` returned non-zero (likely already logged out)");
        }
        Ok(())
    }

    /// Unlock the vault with the master password and return a session key.
    ///
    /// The password is written to the subprocess environment under a private
    /// variable name and consumed via `--passwordenv`, so it never appears on
    /// the command line.
    pub async fn unlock(&self, master_password: &SecretString) -> Result<Session> {
        const PW_VAR: &str = "BW_SSH_AGENT_MASTER_PW";

        let out = self
            .base_command()
            .args(["unlock", "--passwordenv", PW_VAR, "--raw"])
            .env(PW_VAR, master_password.expose_secret())
            .output()
            .await
            .context("running `bw unlock`")?;
        if !out.status.success() {
            bail!(
                "`bw unlock` failed (wrong master password?): {}",
                stderr(&out.stderr)
            );
        }

        let mut raw = String::from_utf8(out.stdout)
            .context("`bw unlock --raw` returned non-UTF8 session key")?;
        let session = raw.trim().to_string();
        raw.zeroize();
        if session.is_empty() {
            bail!("`bw unlock --raw` returned an empty session key");
        }
        Ok(Session(SecretString::from(session)))
    }

    /// Force a sync of the local vault cache. Best-effort.
    pub async fn sync(&self, session: &Session) -> Result<()> {
        let out = self
            .base_command()
            .arg("sync")
            .env("BW_SESSION", session.expose())
            .output()
            .await
            .context("running `bw sync`")?;
        if !out.status.success() {
            bail!("`bw sync` failed: {}", stderr(&out.stderr));
        }
        Ok(())
    }

    /// List all SSH Key items in the vault (cipher type 5).
    pub async fn list_ssh_keys(&self, session: &Session) -> Result<Vec<SshKeyItem>> {
        let out = self
            .base_command()
            .args(["list", "items"])
            .env("BW_SESSION", session.expose())
            .output()
            .await
            .context("running `bw list items`")?;
        if !out.status.success() {
            bail!("`bw list items` failed: {}", stderr(&out.stderr));
        }

        // First pass: figure out which array entries are SSH keys, so a schema
        // change on unrelated cipher types can't break the whole listing.
        let raw_items: Vec<RawItem> = serde_json::from_slice(&out.stdout)
            .context("parsing `bw list items` output")?;
        let ssh_indices: Vec<usize> = raw_items
            .iter()
            .enumerate()
            .filter(|(_, it)| it.item_type == CIPHER_TYPE_SSH_KEY)
            .map(|(i, _)| i)
            .collect();

        if ssh_indices.is_empty() {
            return Ok(Vec::new());
        }

        // Second pass: deserialize just the SSH-key entries into typed structs.
        let all: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)
            .context("re-parsing `bw list items` output")?;
        let mut keys = Vec::with_capacity(ssh_indices.len());
        for i in ssh_indices {
            let value = all
                .get(i)
                .ok_or_else(|| anyhow!("item index {i} out of range"))?;
            match serde_json::from_value::<SshKeyItem>(value.clone()) {
                Ok(item) => keys.push(item),
                Err(e) => log::warn!("skipping malformed SSH key item at index {i}: {e}"),
            }
        }
        Ok(keys)
    }

    /// Fetch the JSON template for a new vault item (`bw get template item`).
    ///
    /// Used as the base object for a freshly-created SSH Key item so every field
    /// the CLI expects is present. Templates need no session, but one is passed
    /// for consistency with the surrounding create/edit calls.
    pub async fn item_template(&self) -> Result<serde_json::Value> {
        let out = self
            .base_command()
            .args(["get", "template", "item"])
            .output()
            .await
            .context("running `bw get template item`")?;
        if !out.status.success() {
            bail!("`bw get template item` failed: {}", stderr(&out.stderr));
        }
        serde_json::from_slice(&out.stdout).context("parsing `bw get template item` output")
    }

    /// Fetch a single vault item by id (`bw get item <id>`), as raw JSON.
    ///
    /// Used before an overwrite so the existing item's other fields (folder,
    /// favorite, ...) are preserved when we replace only its key material.
    pub async fn get_item(&self, session: &Session, id: &str) -> Result<serde_json::Value> {
        let out = self
            .base_command()
            .args(["get", "item", id])
            .env("BW_SESSION", session.expose())
            .output()
            .await
            .context("running `bw get item`")?;
        if !out.status.success() {
            bail!("`bw get item {id}` failed: {}", stderr(&out.stderr));
        }
        serde_json::from_slice(&out.stdout).context("parsing `bw get item` output")
    }

    /// Create a new vault item from a JSON value (`bw create item`).
    ///
    /// The item JSON is base64-encoded via `bw encode` and both stages are fed
    /// through stdin, so the private key never appears in argv (where `ps` could
    /// see it). Returns the new item's id.
    pub async fn create_item(
        &self,
        session: &Session,
        item: &serde_json::Value,
    ) -> Result<String> {
        let encoded = self.encode_item(item).await?;
        let out = self
            .run_capturing_stdin(&["create", "item"], Some(session), &encoded)
            .await
            .context("running `bw create item`")?;
        parse_item_id(&out)
    }

    /// Replace an existing vault item in place (`bw edit item <id>`). Same
    /// stdin/encoding hygiene as [`Self::create_item`].
    pub async fn edit_item(
        &self,
        session: &Session,
        id: &str,
        item: &serde_json::Value,
    ) -> Result<String> {
        let encoded = self.encode_item(item).await?;
        let out = self
            .run_capturing_stdin(&["edit", "item", id], Some(session), &encoded)
            .await
            .context("running `bw edit item`")?;
        parse_item_id(&out)
    }

    /// Serialize `item` to JSON and base64-encode it via `bw encode` (fed on
    /// stdin). The intermediate JSON bytes are zeroized once encoded.
    async fn encode_item(&self, item: &serde_json::Value) -> Result<Vec<u8>> {
        let mut json = serde_json::to_vec(item).context("serializing item JSON")?;
        let result = self.run_capturing_stdin(&["encode"], None, &json).await;
        json.zeroize();
        let mut encoded = result.context("running `bw encode`")?;
        // `bw encode` appends a trailing newline; trim it so the value passed on
        // to `create`/`edit` is a clean base64 string.
        while matches!(encoded.last(), Some(b'\n' | b'\r')) {
            encoded.pop();
        }
        Ok(encoded)
    }

    /// Run `bw <args...>` feeding `input` on stdin (never argv), optionally with
    /// a session, returning captured stdout on success.
    async fn run_capturing_stdin(
        &self,
        args: &[&str],
        session: Option<&Session>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let mut cmd = self.base_command();
        cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(session) = session {
            cmd.env("BW_SESSION", session.expose());
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning `bw {}`", args.join(" ")))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .context("failed to open stdin for `bw`")?;
            stdin
                .write_all(input)
                .await
                .context("writing to `bw` stdin")?;
            stdin.flush().await.ok();
            // Dropping stdin closes it, signalling EOF.
        }

        let out = child
            .wait_with_output()
            .await
            .with_context(|| format!("waiting for `bw {}`", args.join(" ")))?;
        if !out.status.success() {
            bail!("`bw {}` failed: {}", args.join(" "), stderr(&out.stderr));
        }
        Ok(out.stdout)
    }
}

/// Extract the `id` field from a `bw create/edit item` JSON response.
fn parse_item_id(stdout: &[u8]) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_slice(stdout).context("parsing `bw create/edit item` output")?;
    value
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("`bw` response did not contain an item id"))
}

/// Output of `bw status`.
#[derive(Debug, Deserialize)]
pub struct Status {
    /// One of: `unauthenticated`, `locked`, `unlocked`.
    pub status: String,
}

impl Status {
    fn is_logged_in(&self) -> bool {
        // Anything other than `unauthenticated` means the device is authed.
        self.status != "unauthenticated"
    }
}

fn stderr(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let trimmed = s.trim();
    if trimmed.is_empty() {
        "(no stderr)".to_string()
    } else {
        trimmed.to_string()
    }
}
