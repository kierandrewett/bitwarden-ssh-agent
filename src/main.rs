//! bitwarden-ssh-agent: a headless SSH agent backed by a Bitwarden vault.
//!
//! Private keys are fetched from the vault via the official `bw` CLI, parsed,
//! and kept only in this process's memory. All signing happens in-process, so
//! this behaves like a normal `ssh-agent` (agent-forwarding works) while never
//! writing key material to disk.

mod agent;
mod bitwarden;
mod config;
mod unlock;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ssh_agent_lib::agent::listen;

use crate::agent::VaultAgent;
use crate::bitwarden::BitwardenCli;
use crate::config::Config;
use crate::unlock::UnlockManager;

/// Default socket filename inside `$XDG_RUNTIME_DIR`.
const SOCKET_NAME: &str = "bitwarden-ssh-agent.sock";

#[derive(Parser)]
#[command(
    name = "bitwarden-ssh-agent",
    version,
    about = "A headless SSH agent daemon backed by your Bitwarden vault",
    long_about = "Serves the SSH agent protocol on a Unix socket. SSH private keys are \
fetched from your Bitwarden vault via the `bw` CLI and held only in memory; \
signing happens in-process, so agent-forwarding works like a normal ssh-agent."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent daemon (this is what systemd runs). Also the default.
    Serve(ServeArgs),
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Path to the Unix socket to listen on.
    /// Defaults to `$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Path to the config file (Bitwarden API key).
    /// Defaults to `~/.config/bitwarden-ssh-agent/config.toml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format_timestamp_secs()
    .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Serve(args)) => serve(args).await,
        None => serve(ServeArgs { socket: None, config: None }).await,
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    // Load the API key (env vars > config file). Absent is allowed if the
    // device was already logged in out-of-band.
    let cfg = match &args.config {
        Some(path) => Config::load_from(path)?,
        None => Config::load()?,
    };
    if cfg.api_key.is_none() {
        log::warn!(
            "no Bitwarden API key found (BW_CLIENTID/BW_CLIENTSECRET or config.toml); \
             the `bw` CLI must already be logged in for unlocking to work"
        );
    }

    let cli = BitwardenCli::new(cfg.server.clone());
    match cli.version().await {
        Ok(v) => log::info!("using Bitwarden CLI version {v}"),
        Err(e) => {
            // Almost always a setup error (bw not installed); make it loud but
            // let the daemon keep running so the socket is still available.
            log::error!("Bitwarden CLI check failed: {e:#}");
        }
    }

    let unlock = UnlockManager::new(cli, cfg.api_key);

    // Try a non-interactive startup unlock via systemd credential. If it isn't
    // provisioned, stay locked and prompt on first client request.
    match unlock.try_startup_unlock().await {
        Ok(true) => {}
        Ok(false) => log::info!(
            "no master password credential provisioned; \
             will prompt via systemd-ask-password on first use"
        ),
        Err(e) => log::error!("startup unlock failed: {e:#}"),
    }

    let socket_path = resolve_socket_path(args.socket)?;
    let listener = bind_socket(&socket_path)?;
    log::info!("listening on {}", socket_path.display());
    log::info!(
        "point SSH at it with: export SSH_AUTH_SOCK={}",
        socket_path.display()
    );

    let agent = VaultAgent::new(unlock);
    listen(listener, agent)
        .await
        .context("SSH agent listener terminated")?;
    Ok(())
}

/// Determine the socket path: explicit flag, else `$XDG_RUNTIME_DIR/<name>`.
fn resolve_socket_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .context(
            "XDG_RUNTIME_DIR is not set; pass --socket to choose a socket path explicitly",
        )?;
    Ok(PathBuf::from(dir).join(SOCKET_NAME))
}

/// Bind the Unix socket with 0600 permissions, removing any stale socket first.
fn bind_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    // Remove a stale socket from a previous run (or crash).
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    anyhow::bail!(
                        "refusing to remove {}: exists and is not a socket",
                        path.display()
                    );
                }
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("stat {}", path.display()));
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {}", parent.display()))?;
    }

    // Ensure the socket is created with tight permissions from the outset.
    #[cfg(unix)]
    let old_umask = unsafe { set_umask(0o177) };

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("binding socket {}", path.display()));

    #[cfg(unix)]
    unsafe {
        set_umask(old_umask);
    }

    let listener = listener?;

    // Belt-and-braces: explicitly enforce 0600 in case the umask was ignored.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }

    Ok(listener)
}

#[cfg(unix)]
unsafe fn set_umask(mask: u32) -> u32 {
    // Minimal FFI to libc `umask` to avoid depending on the whole libc crate.
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    umask(mask)
}
