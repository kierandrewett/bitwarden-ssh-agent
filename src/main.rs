//! bitwarden-ssh-agent: a headless SSH agent backed by a Bitwarden vault.
//!
//! Private keys are fetched from the vault via the official `bw` CLI, parsed,
//! and kept only in this process's memory. All signing happens in-process, so
//! this behaves like a normal `ssh-agent` (agent-forwarding works) while never
//! writing key material to disk.

mod agent;
mod bitwarden;
mod config;
mod control;
mod setup;
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
signing happens in-process, so agent-forwarding works like a normal ssh-agent.",
    // No default subcommand: running bare prints help and exits cleanly rather
    // than silently starting the daemon.
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent daemon (this is what systemd runs).
    Serve(ServeArgs),

    /// Interactively configure everything: `bw` CLI, API key, config file,
    /// master-password unlock strategy, and the systemd user service.
    Setup(SetupArgs),

    /// Unlock the running daemon by typing your master password into this
    /// terminal (the reliable interactive path — no systemd-ask-password agent
    /// required). Prompts for the password and hands it to the daemon over its
    /// local control socket.
    Unlock(UnlockArgs),
}

#[derive(clap::Args)]
struct UnlockArgs {
    /// Path to the daemon's control socket.
    /// Defaults to `$XDG_RUNTIME_DIR/bitwarden-ssh-agent.ctl`.
    #[arg(long, value_name = "PATH")]
    control_socket: Option<PathBuf>,
}

#[derive(clap::Args)]
struct SetupArgs {
    /// Path to the config file to write.
    /// Defaults to `~/.config/bitwarden-ssh-agent/config.toml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
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
        Command::Serve(args) => serve(args).await,
        Command::Setup(args) => setup::run(args.config).await,
        Command::Unlock(args) => unlock_cli(args).await,
    }
}

/// `unlock` subcommand: prompt (masked) for the master password and hand it to
/// the running daemon over its control socket.
async fn unlock_cli(args: UnlockArgs) -> Result<()> {
    let control_path = control::resolve_control_path(args.control_socket)?;

    // Connect first (inside run_unlock_client); only prompt once the daemon is
    // known reachable, so a stopped daemon fails fast without asking for input.
    let prompt = || {
        let password = inquire::Password::new("Bitwarden master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .without_confirmation()
            .with_help_message("Sent directly to the running daemon; never stored or echoed.")
            .prompt()
            .map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;
        Ok(secrecy::SecretString::from(password))
    };

    let code = control::run_unlock_client(&control_path, prompt).await?;
    std::process::exit(code);
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

    // Bind the small control socket for the `unlock` subcommand (same 0600 +
    // stale-socket handling as the agent socket above), and serve it in the
    // background so the user can always unlock interactively via their terminal.
    match control::resolve_control_path(None) {
        Ok(control_path) => match bind_socket(&control_path) {
            Ok(control_listener) => {
                log::info!("control socket listening on {}", control_path.display());
                log::info!(
                    "unlock the vault interactively with: bitwarden-ssh-agent unlock"
                );
                tokio::spawn(control::serve_control(control_listener, unlock.clone()));
            }
            Err(e) => log::error!(
                "failed to bind control socket {}: {e:#}; the `unlock` subcommand \
                 will not work this run",
                control_path.display()
            ),
        },
        Err(e) => log::error!(
            "cannot determine control socket path: {e:#}; the `unlock` subcommand \
             will not work this run"
        ),
    }

    // Refresh keys on SIGHUP so newly-added vault items can be picked up without
    // restarting the daemon (re-`bw sync` + reload, reusing the unlocked session).
    #[cfg(unix)]
    spawn_sighup_refresh(unlock.clone());

    let agent = VaultAgent::new(unlock);
    listen(listener, agent)
        .await
        .context("SSH agent listener terminated")?;
    Ok(())
}

/// Spawn a task that re-fetches vault keys each time the daemon receives SIGHUP.
///
/// `kill -HUP <pid>` (or `systemctl --user reload` with `ExecReload=`) then
/// picks up keys added to the vault after the daemon started, without a restart.
#[cfg(unix)]
fn spawn_sighup_refresh(unlock: UnlockManager) {
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                log::error!("failed to install SIGHUP handler: {e:#}");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            log::info!("received SIGHUP; refreshing vault keys");
            if let Err(e) = unlock.refresh().await {
                log::error!("SIGHUP key refresh failed: {e:#}");
            }
        }
    });
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
