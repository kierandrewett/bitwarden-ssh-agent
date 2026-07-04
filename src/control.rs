//! Local control channel for the `unlock` subcommand.
//!
//! Alongside the SSH-agent protocol socket, the daemon binds a second, tiny Unix
//! socket at `$XDG_RUNTIME_DIR/bitwarden-ssh-agent.ctl` (0600). The `unlock` CLI
//! subcommand connects to it, hands over the master password typed into the
//! user's own terminal, and the daemon runs the exact same unlock flow used by
//! the credential / on-demand paths — reusing [`UnlockManager`]'s single-flight
//! state machine.
//!
//! This exists because `systemd-ask-password`, the daemon's built-in on-demand
//! prompt, only works when some ask-password *agent* is watching the query
//! queue. On a headless `systemd --user` service that is usually nobody, so that
//! prompt just times out. Typing the password into your own terminal and pushing
//! it over this socket has no such dependency and always works.
//!
//! ## Wire protocol (deliberately minimal — this is not the SSH agent protocol)
//!
//! Request (client → daemon): `[u8 command][body]`.
//! - [`CMD_UNLOCK`]: body is `[u32 BE length][password bytes]`, capped at
//!   [`MAX_PASSWORD_LEN`] to reject anything absurd.
//! - [`CMD_REFRESH`]: no body — re-syncs the vault and reloads keys using the
//!   session already unlocked (e.g. by `import`, after adding new vault items,
//!   without needing `systemctl kill -HUP` or the master password again).
//! - [`CMD_LIST`]: no body — returns a summary of the keys currently served
//!   (algorithm, fingerprint, comment), the same thing `ssh-add -l` shows, but
//!   without needing `$SSH_AUTH_SOCK` set or `ssh-add` installed. Like the SSH
//!   agent protocol itself, this triggers on-demand unlock if the vault is
//!   currently locked.
//!
//! Response (daemon → client): `[u8 status][UTF-8 message]`, read to EOF.
//! `status` is one of [`STATUS_OK`], [`STATUS_WRONG_PASSWORD`], [`STATUS_ERROR`].

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

use crate::unlock::{RefreshOutcome, UnlockError, UnlockManager, UnlockOutcome};

/// Control-socket filename inside `$XDG_RUNTIME_DIR`.
pub const CONTROL_SOCKET_NAME: &str = "bitwarden-ssh-agent.ctl";

/// Request command bytes.
const CMD_UNLOCK: u8 = 0;
const CMD_REFRESH: u8 = 1;
const CMD_LIST: u8 = 2;

/// Reject password frames larger than this (a sane master password is tiny;
/// this only guards against a confused or malicious local sender).
const MAX_PASSWORD_LEN: u32 = 8 * 1024;

/// Vault unlocked (or already unlocked). Message is human-readable detail.
pub const STATUS_OK: u8 = 0;
/// The master password was rejected by `bw unlock`.
pub const STATUS_WRONG_PASSWORD: u8 = 1;
/// Some other failure (e.g. `bw` not reachable, not logged in).
pub const STATUS_ERROR: u8 = 2;

/// Resolve the control-socket path: explicit override, else
/// `$XDG_RUNTIME_DIR/<name>`.
pub fn resolve_control_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .context(
            "XDG_RUNTIME_DIR is not set; pass --control-socket to choose a path explicitly",
        )?;
    Ok(PathBuf::from(dir).join(CONTROL_SOCKET_NAME))
}

/// A connection that sends nothing (or trickles bytes) must not be allowed to
/// pin a task/fd/buffer forever — this is the ceiling for an entire request
/// (read command byte, read any body, run the operation, write the response).
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Daemon side: accept control connections forever, unlocking the vault via
/// `unlock` on request. One connection = one unlock attempt.
pub async fn serve_control(listener: UnixListener, unlock: UnlockManager) {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                log::error!("control socket accept failed: {e:#}");
                // Avoid a tight spin if the socket is somehow wedged.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };

        // Only the same local user may use this socket — belt-and-braces on
        // top of the 0600 file mode, in case of a permissions misconfiguration.
        if let Err(e) = check_peer_is_self(&stream) {
            log::warn!("rejecting control connection: {e:#}");
            continue;
        }

        let unlock = unlock.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                CONNECTION_TIMEOUT,
                handle_control_connection(stream, unlock),
            )
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => log::warn!("control connection error: {e:#}"),
                Err(_) => log::warn!(
                    "control connection timed out after {CONNECTION_TIMEOUT:?} \
                     (client sent no/partial data); dropped"
                ),
            }
        });
    }
}

/// Reject a connection from any UID other than our own, on top of the socket's
/// 0600 mode — defense in depth against a permissions misconfiguration (e.g. a
/// misconfigured `$XDG_RUNTIME_DIR` shared across users).
#[cfg(unix)]
fn check_peer_is_self(stream: &UnixStream) -> Result<()> {
    let peer_uid = stream
        .peer_cred()
        .context("reading control socket peer credentials")?
        .uid();
    let our_uid = current_uid();
    if peer_uid != our_uid {
        bail!("peer uid {peer_uid} does not match our own uid {our_uid}");
    }
    Ok(())
}

/// Minimal FFI to libc `getuid`, matching the existing `umask` FFI pattern in
/// `main.rs` rather than pulling in the whole `libc` crate for one call.
#[cfg(unix)]
fn current_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

/// Handle a single control connection: dispatch on the leading command byte,
/// then write back a status + message.
async fn handle_control_connection(
    mut stream: UnixStream,
    unlock: UnlockManager,
) -> Result<()> {
    let mut cmd_buf = [0u8; 1];
    if let Err(e) = stream.read_exact(&mut cmd_buf).await {
        let _ = write_response(&mut stream, STATUS_ERROR, &format!("bad request: {e}")).await;
        return Err(e).context("reading command byte");
    }

    match cmd_buf[0] {
        CMD_UNLOCK => handle_unlock(&mut stream, unlock).await,
        CMD_REFRESH => handle_refresh(&mut stream, unlock).await,
        CMD_LIST => handle_list(&mut stream, unlock).await,
        other => {
            let msg = format!("unknown command byte {other}");
            let _ = write_response(&mut stream, STATUS_ERROR, &msg).await;
            bail!(msg)
        }
    }
}

/// `CMD_UNLOCK`: read the password frame, run the unlock, respond.
async fn handle_unlock(stream: &mut UnixStream, unlock: UnlockManager) -> Result<()> {
    let password = match read_password_frame(stream).await {
        // Wrapped in SecretString so the plaintext is zeroized on drop.
        Ok(pw) => SecretString::from(pw),
        Err(e) => {
            // Malformed request: tell the client rather than hanging.
            let _ = write_response(stream, STATUS_ERROR, &format!("bad request: {e:#}")).await;
            return Err(e);
        }
    };

    log::info!("control channel: unlock requested via `unlock` subcommand");
    let outcome = unlock.unlock_with_password(&password).await;
    drop(password);

    let (status, message) = match outcome {
        Ok(UnlockOutcome::Unlocked(n)) => (
            STATUS_OK,
            format!("vault unlocked; {n} SSH key(s) now served by the agent"),
        ),
        Ok(UnlockOutcome::AlreadyUnlocked(n)) => (
            STATUS_OK,
            format!("vault was already unlocked; {n} SSH key(s) served"),
        ),
        Err(UnlockError::WrongPassword(detail)) => {
            log::info!("control channel: unlock rejected (wrong master password)");
            (STATUS_WRONG_PASSWORD, format!("wrong master password: {detail}"))
        }
        Err(UnlockError::Other(e)) => {
            log::warn!("control channel: unlock failed: {e:#}");
            (STATUS_ERROR, format!("unlock failed: {e:#}"))
        }
    };
    write_response(stream, status, &message).await
}

/// `CMD_REFRESH`: re-sync the vault and reload keys using the existing session
/// (no password involved; if the vault is locked there's simply nothing to do).
async fn handle_refresh(stream: &mut UnixStream, unlock: UnlockManager) -> Result<()> {
    log::info!("control channel: refresh requested via `import` (or manually)");
    let (status, message) = match unlock.refresh().await {
        Ok(RefreshOutcome::Refreshed(n)) => (
            STATUS_OK,
            format!("vault refreshed; {n} SSH key(s) now served by the agent"),
        ),
        Ok(RefreshOutcome::StillLocked) => (
            STATUS_OK,
            "vault is still locked; nothing to refresh yet (run `unlock` first)".to_string(),
        ),
        Err(e) => {
            log::warn!("control channel: refresh failed: {e:#}");
            (STATUS_ERROR, format!("refresh failed: {e:#}"))
        }
    };
    write_response(stream, status, &message).await
}

/// `CMD_LIST`: report the keys currently served, unlocking on demand first if
/// the vault is locked (same semantics as the SSH agent protocol itself).
async fn handle_list(stream: &mut UnixStream, unlock: UnlockManager) -> Result<()> {
    log::info!("control channel: list requested via `list` subcommand");
    let (status, message) = match unlock.keys().await {
        Ok(keys) if keys.is_empty() => (STATUS_OK, "The agent has no identities.".to_string()),
        Ok(keys) => {
            let lines: Vec<String> = keys
                .iter()
                .map(|k| {
                    let s = k.summary();
                    format!("{}  {}  {}", s.algorithm, s.fingerprint, s.comment)
                })
                .collect();
            (STATUS_OK, lines.join("\n"))
        }
        Err(e) => {
            log::warn!("control channel: list failed: {e:#}");
            (STATUS_ERROR, format!("could not list keys: {e:#}"))
        }
    };
    write_response(stream, status, &message).await
}

/// Read one `[u32 BE length][password bytes]` request frame.
async fn read_password_frame(stream: &mut UnixStream) -> Result<String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("reading password length prefix")?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        bail!("empty password");
    }
    if len > MAX_PASSWORD_LEN {
        bail!("password frame too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading password body")?;
    let password = String::from_utf8(buf.clone())
        .map_err(|_| anyhow::anyhow!("password was not valid UTF-8"))?;
    buf.zeroize();
    Ok(password)
}

/// Write a `[u8 status][UTF-8 message]` response frame.
async fn write_response(stream: &mut UnixStream, status: u8, message: &str) -> Result<()> {
    stream
        .write_all(&[status])
        .await
        .context("writing response status")?;
    stream
        .write_all(message.as_bytes())
        .await
        .context("writing response message")?;
    stream.flush().await.context("flushing response")?;
    // Signal EOF so the client's read-to-end returns promptly.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Client side: connect to the control socket first (fail fast with a clear
/// message if the daemon isn't running — no point prompting for a password we
/// can't deliver), then obtain the password via `prompt`, send it, and print
/// the daemon's response. Returns the process exit code to use.
pub async fn run_unlock_client(
    control_path: &Path,
    prompt: impl FnOnce() -> Result<SecretString>,
) -> Result<i32> {
    let mut stream = UnixStream::connect(control_path).await.map_err(|e| {
        anyhow::anyhow!(
            "could not connect to the daemon control socket at {} ({e}).\n\
             Is the service running?  Start it with:\n    \
             systemctl --user start bitwarden-ssh-agent.service",
            control_path.display()
        )
    })?;

    // Daemon is reachable: now prompt for the password.
    let password = prompt()?;

    // Send the command byte, then the length-prefixed password, then scrub our copy.
    let mut body = password.expose_secret().as_bytes().to_vec();
    let len = body.len();
    if len == 0 {
        bail!("refusing to send an empty password");
    }
    if len > MAX_PASSWORD_LEN as usize {
        bail!("password is implausibly long ({len} bytes); refusing to send");
    }
    let send = async {
        stream.write_all(&[CMD_UNLOCK]).await?;
        stream.write_all(&(len as u32).to_be_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;
        stream.shutdown().await
    };
    let sent = send.await;
    body.zeroize();
    drop(password);
    sent.context("sending password to the daemon")?;

    read_response(&mut stream).await
}

/// Client side: connect to the control socket and ask the already-running
/// daemon to re-sync the vault and reload keys, without touching the master
/// password at all. Used by `import` after adding new vault items, and
/// available as a standalone `refresh` action. Fails fast (no-op, not an
/// error) if the daemon isn't running — the caller decides what that means.
pub async fn run_refresh_client(control_path: &Path) -> Result<i32> {
    let mut stream = UnixStream::connect(control_path).await.map_err(|e| {
        anyhow::anyhow!(
            "could not connect to the daemon control socket at {} ({e}). \
             Is the service running?",
            control_path.display()
        )
    })?;

    stream
        .write_all(&[CMD_REFRESH])
        .await
        .context("sending refresh request to the daemon")?;
    stream.flush().await.context("flushing refresh request")?;
    stream.shutdown().await.context("closing write side")?;

    read_response(&mut stream).await
}

/// Client side: connect to the control socket and ask the daemon for the keys
/// it's currently serving — the `list` subcommand. Equivalent to `ssh-add -l`,
/// but works without `$SSH_AUTH_SOCK` set or `ssh-add` installed, since it
/// talks to the daemon directly. Like the SSH agent protocol, this triggers
/// on-demand unlock if the vault is locked.
pub async fn run_list_client(control_path: &Path) -> Result<i32> {
    let mut stream = UnixStream::connect(control_path).await.map_err(|e| {
        anyhow::anyhow!(
            "could not connect to the daemon control socket at {} ({e}). \
             Is the service running?",
            control_path.display()
        )
    })?;

    stream
        .write_all(&[CMD_LIST])
        .await
        .context("sending list request to the daemon")?;
    stream.flush().await.context("flushing list request")?;
    stream.shutdown().await.context("closing write side")?;

    read_response(&mut stream).await
}

/// Read a `[u8 status][UTF-8 message]` response, print it, and map it to a
/// process exit code. Shared by the `unlock`, `refresh`, and `list` clients.
async fn read_response(stream: &mut UnixStream) -> Result<i32> {
    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .await
        .context("reading response from the daemon")?;
    let (status, message) = match resp.split_first() {
        Some((s, rest)) => (*s, String::from_utf8_lossy(rest).into_owned()),
        None => bail!("the daemon closed the connection without responding"),
    };

    match status {
        STATUS_OK => {
            println!("{message}");
            Ok(0)
        }
        STATUS_WRONG_PASSWORD => {
            eprintln!("{message}");
            Ok(2)
        }
        _ => {
            eprintln!("{message}");
            Ok(1)
        }
    }
}
