//! Interactive `setup` subcommand.
//!
//! Automates everything the README otherwise asks a fresh user to do by hand:
//! check for the `bw` CLI, collect and validate the Bitwarden API key, write the
//! config file, choose a master-password unlock strategy, install and start the
//! systemd user service, and print the `SSH_AUTH_SOCK` line to export.
//!
//! Every destructive step (overwriting the config, the unit file, or an existing
//! credential) prompts first, so re-running `setup` is safe and idempotent.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use tokio::process::Command;

use crate::bitwarden::BitwardenCli;
use crate::config::ApiKey;

/// Bitwarden API key collected (and validated) during setup.
struct ApiKeyInput {
    client_id: String,
    client_secret: SecretString,
    server: Option<String>,
}

/// Entry point for `bitwarden-ssh-agent setup`.
pub async fn run(config_override: Option<PathBuf>) -> Result<()> {
    let _ = config_override;
    println!("bitwarden-ssh-agent setup");
    println!("=========================\n");
    println!("This will walk you through configuring the agent end-to-end.");
    println!("Every step that would overwrite something asks first, so it is");
    println!("safe to re-run.\n");

    ensure_bw_cli().await?;
    let _api_key = collect_and_validate_api_key().await?;

    Ok(())
}

// --- step 1: Bitwarden CLI ---------------------------------------------------

/// Ensure the `bw` CLI is available, offering to install it via npm if not.
async fn ensure_bw_cli() -> Result<()> {
    step(1, "Bitwarden CLI (`bw`)");

    // Reuse the daemon's own CLI wrapper so we honour BW_CLI_PATH etc.
    let cli = BitwardenCli::new(None);
    match cli.version().await {
        Ok(v) => {
            println!("Found Bitwarden CLI (version {v}).");
            return Ok(());
        }
        Err(_) => {
            println!("The `bw` CLI was not found on your PATH.");
        }
    }

    // The `bw` CLI is a Node package; we need npm to install it.
    if !program_runs("npm", &["--version"]).await {
        anyhow::bail!(
            "`bw` is not installed and `npm` is not available to install it.\n\
             Install Node.js (which provides npm) from https://nodejs.org, then\n\
             run `npm install -g @bitwarden/cli`, and re-run `setup`."
        );
    }

    if !prompt_yes_no(
        "Install it now with `npm install -g @bitwarden/cli`?",
        true,
    )? {
        anyhow::bail!(
            "Bitwarden CLI is required. Install it with\n\
             `npm install -g @bitwarden/cli` and re-run `setup`."
        );
    }

    println!("Running `npm install -g @bitwarden/cli` (this may take a moment)...");
    let status = Command::new("npm")
        .args(["install", "-g", "@bitwarden/cli"])
        .status()
        .await
        .context("spawning `npm install -g @bitwarden/cli`")?;
    if !status.success() {
        anyhow::bail!(
            "`npm install -g @bitwarden/cli` failed. Install `bw` manually and \
             re-run `setup`."
        );
    }

    // Confirm the freshly-installed binary is actually reachable now.
    match cli.version().await {
        Ok(v) => {
            println!("Installed Bitwarden CLI (version {v}).");
            Ok(())
        }
        Err(_) => anyhow::bail!(
            "`bw` was installed but is still not on your PATH. The npm global bin \
             directory (`npm config get prefix`/bin) may not be on PATH. Add it, \
             or set BW_CLI_PATH, then re-run `setup`."
        ),
    }
}

// --- step 2: API key ---------------------------------------------------------

/// Prompt for the Bitwarden API key (and optional self-hosted server), then
/// validate it by actually attempting `bw login --apikey`. Loops on failure so
/// the user can retry or abort.
async fn collect_and_validate_api_key() -> Result<ApiKeyInput> {
    step(2, "Bitwarden API key");
    println!("Find this in the web vault under");
    println!("  Account settings -> Security -> Keys -> API key -> View API Key.");
    println!("(This only authenticates the device; it cannot unlock the vault.)\n");

    loop {
        let client_id = prompt("client_id (starts with `user.`)", None)?;
        let client_secret = SecretString::from(prompt("client_secret", None)?);
        println!("\nSelf-hosted Bitwarden/Vaultwarden only. Leave blank for the");
        println!("official Bitwarden cloud (bitwarden.com).");
        let server_raw = prompt("server URL (optional)", Some(""))?;
        let server = if server_raw.is_empty() {
            None
        } else {
            Some(server_raw)
        };

        let api_key = ApiKey {
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
        };

        println!("\nValidating with `bw login --apikey`...");
        match validate_api_key(&api_key, server.as_deref()).await {
            Ok(()) => {
                println!("API key accepted; device is now logged in to Bitwarden.");
                return Ok(ApiKeyInput {
                    client_id,
                    client_secret,
                    server,
                });
            }
            Err(e) => {
                println!("\nLogin failed:\n{e:#}\n");
                if !prompt_yes_no("Try again with different credentials?", true)? {
                    anyhow::bail!("aborted: API key not validated");
                }
            }
        }
    }
}

/// Force a clean `bw login --apikey` with the given credentials so they are
/// genuinely validated (logging out first if a prior session exists).
async fn validate_api_key(api_key: &ApiKey, server: Option<&str>) -> Result<()> {
    let cli = BitwardenCli::new(server.map(str::to_string));
    // Log out any existing session so login actually exercises these creds.
    cli.logout().await?;
    cli.login_with_api_key(api_key).await
}

/// Return true if `<program> <args...>` runs and exits successfully.
async fn program_runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

// --- terminal helpers -------------------------------------------------------

/// Print a step header so the user can follow along.
fn step(n: u8, title: &str) {
    println!("\n[{n}/7] {title}");
    println!("{}", "-".repeat(title.len() + 6));
}

/// Read a line of input, returning it trimmed. `None` on EOF.
fn read_line() -> Result<Option<String>> {
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

/// Prompt for a free-form line of text (optionally with a default).
fn prompt(question: &str, default: Option<&str>) -> Result<String> {
    loop {
        match default {
            Some(d) if !d.is_empty() => print!("{question} [{d}]: "),
            _ => print!("{question}: "),
        }
        io::stdout().flush()?;
        match read_line()? {
            None => anyhow::bail!("aborted (end of input)"),
            Some(s) if s.is_empty() => {
                if let Some(d) = default {
                    return Ok(d.to_string());
                }
                // Required field: re-ask.
                continue;
            }
            Some(s) => return Ok(s),
        }
    }
}

/// Prompt for a yes/no answer with a default.
fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("{question} {hint} ");
        io::stdout().flush()?;
        match read_line()? {
            None => anyhow::bail!("aborted (end of input)"),
            Some(s) if s.is_empty() => return Ok(default_yes),
            Some(s) => match s.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => {
                    println!("Please answer 'y' or 'n'.");
                    continue;
                }
            },
        }
    }
}
