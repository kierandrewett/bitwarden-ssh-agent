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
//! Request (client → daemon): a single frame `[u32 BE length][password bytes]`.
//! There is only one request type (unlock), so no command byte is needed. The
//! length is capped at [`MAX_PASSWORD_LEN`] to reject anything absurd.
//!
//! Response (daemon → client): `[u8 status][UTF-8 message]`, read to EOF.
//! `status` is one of [`STATUS_OK`], [`STATUS_WRONG_PASSWORD`], [`STATUS_ERROR`].

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

use crate::unlock::{UnlockError, UnlockManager, UnlockOutcome};

/// Control-socket filename inside `$XDG_RUNTIME_DIR`.
pub const CONTROL_SOCKET_NAME: &str = "bitwarden-ssh-agent.ctl";

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
        let unlock = unlock.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control_connection(stream, unlock).await {
                log::warn!("control connection error: {e:#}");
            }
        });
    }
}

/// Handle a single control connection: read the password frame, run the unlock,
/// write back a status + message.
async fn handle_control_connection(
    mut stream: UnixStream,
    unlock: UnlockManager,
) -> Result<()> {
    let password = match read_password_frame(&mut stream).await {
        // Wrapped in SecretString so the plaintext is zeroized on drop.
        Ok(pw) => SecretString::from(pw),
        Err(e) => {
            // Malformed request: tell the client rather than hanging.
            let _ = write_response(&mut stream, STATUS_ERROR, &format!("bad request: {e:#}")).await;
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
    write_response(&mut stream, status, &message).await
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

/// Client side: connect to the control socket, send `password`, print the
/// daemon's response. Returns the process exit code to use.
pub async fn run_unlock_client(control_path: &Path, password: SecretString) -> Result<i32> {
    let mut stream = UnixStream::connect(control_path).await.map_err(|e| {
        anyhow::anyhow!(
            "could not connect to the daemon control socket at {} ({e}).\n\
             Is the service running?  Start it with:\n    \
             systemctl --user start bitwarden-ssh-agent.service",
            control_path.display()
        )
    })?;

    // Send the length-prefixed password, then scrub our copy.
    let mut body = password.expose_secret().as_bytes().to_vec();
    let len = body.len();
    if len == 0 {
        bail!("refusing to send an empty password");
    }
    if len > MAX_PASSWORD_LEN as usize {
        bail!("password is implausibly long ({len} bytes); refusing to send");
    }
    let send = async {
        stream.write_all(&(len as u32).to_be_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;
        stream.shutdown().await
    };
    let sent = send.await;
    body.zeroize();
    drop(password);
    sent.context("sending password to the daemon")?;

    // Read the daemon's response: [status][message...].
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
