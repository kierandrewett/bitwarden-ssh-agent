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
use serde::Serialize;
use tokio::process::Command;
use zeroize::Zeroize;

use crate::bitwarden::BitwardenCli;
use crate::config::{self, ApiKey};

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

    let config_path = match config_override {
        Some(p) => p,
        None => config::default_config_path(),
    };

    ensure_bw_cli().await?;
    let api_key = collect_and_validate_api_key().await?;
    write_config(&config_path, &api_key)?;
    let _strategy = provision_master_password(&config_path, &api_key).await?;

    Ok(())
}

/// Which master-password unlock strategy the user chose.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockStrategy {
    /// Auto-unlock at startup from an encrypted systemd credential.
    Credential,
    /// No credential; prompt via systemd-ask-password on first use.
    OnDemand,
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

// --- step 3: config file -----------------------------------------------------

/// Shape of the config file we serialize. Mirrors `config::ConfigFile`.
#[derive(Serialize)]
struct ConfigFileOut<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
}

/// Write `config.toml` (0600), prompting before overwriting an existing one.
fn write_config(path: &std::path::Path, api_key: &ApiKeyInput) -> Result<()> {
    step(3, "Config file");
    println!("Config path: {}", path.display());

    if path.exists() {
        println!("A config file already exists here.");
        match prompt_choice(
            "What would you like to do?",
            &[
                ("overwrite", "replace it with the values just entered"),
                ("reuse", "keep the existing file untouched"),
                ("abort", "stop setup"),
            ],
        )? {
            "reuse" => {
                println!("Keeping existing config file.");
                return Ok(());
            }
            "abort" => anyhow::bail!("aborted at config-file step"),
            _ => {} // overwrite
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }

    let out = ConfigFileOut {
        client_id: &api_key.client_id,
        client_secret: api_key.client_secret.expose_secret(),
        server: api_key.server.as_deref(),
    };
    let body = toml::to_string(&out).context("serializing config file")?;
    let mut contents = format!(
        "# Managed by `bitwarden-ssh-agent setup`.\n\
         # Holds ONLY the Bitwarden API key (device auth). Never put your\n\
         # master password here.\n\n{body}"
    );

    write_private_file(path, contents.as_bytes())
        .with_context(|| format!("writing config file {}", path.display()))?;
    // The serialized body contains the API secret; scrub our copy.
    contents.zeroize();

    println!("Wrote config file with 0600 permissions.");
    Ok(())
}

// --- step 4: master password / unlock strategy -------------------------------

/// Filename of the encrypted master-password credential (matches the daemon's
/// `LoadCredentialEncrypted=` name and what unlock.rs reads).
const CREDENTIAL_FILENAME: &str = "bw_master_password.cred";

/// Let the user choose how the vault gets unlocked, provisioning the encrypted
/// systemd credential if they pick auto-unlock. The plaintext master password
/// is never written to disk: it is piped straight into `systemd-creds encrypt`.
async fn provision_master_password(
    config_path: &std::path::Path,
    api_key: &ApiKeyInput,
) -> Result<UnlockStrategy> {
    step(4, "Master password / unlock strategy");
    println!("The master password is what actually unlocks your vault. It is");
    println!("never stored in plaintext. Choose how the daemon should obtain it:\n");

    let choice = prompt_choice(
        "Unlock strategy?",
        &[
            (
                "credential",
                "auto-unlock at startup from an encrypted systemd credential (recommended)",
            ),
            (
                "on-demand",
                "prompt via systemd-ask-password the first time SSH uses the agent",
            ),
        ],
    )?;

    if choice == "on-demand" {
        println!("\nNo credential will be provisioned; the daemon will prompt on");
        println!("first use. You can re-run `setup` later to switch to auto-unlock.");
        return Ok(UnlockStrategy::OnDemand);
    }

    let cred_path = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(CREDENTIAL_FILENAME);

    if cred_path.exists() {
        println!("\nAn encrypted credential already exists at {}.", cred_path.display());
        match prompt_choice(
            "What would you like to do?",
            &[
                ("overwrite", "re-encrypt with a newly-entered master password"),
                ("reuse", "keep the existing credential"),
                ("abort", "stop setup"),
            ],
        )? {
            "reuse" => {
                println!("Keeping existing credential.");
                return Ok(UnlockStrategy::Credential);
            }
            "abort" => anyhow::bail!("aborted at master-password step"),
            _ => {} // overwrite
        }
    }

    // Collect the password (masked), verifying it actually unlocks the vault
    // before we bother encrypting it, so a typo doesn't get baked into the cred.
    let password = prompt_master_password_verified(api_key).await?;

    encrypt_master_password_credential(&password, &cred_path).await?;
    println!("Wrote encrypted credential to {} (0600).", cred_path.display());
    Ok(UnlockStrategy::Credential)
}

/// Prompt (masked) for the master password and confirm it unlocks the vault.
/// Loops until a working password is entered or the user aborts.
async fn prompt_master_password_verified(api_key: &ApiKeyInput) -> Result<SecretString> {
    let cli = BitwardenCli::new(api_key.server.clone());
    loop {
        let entered = rpassword::prompt_password("Bitwarden master password: ")
            .context("reading master password")?;
        if entered.is_empty() {
            println!("Password was empty; please try again.");
            continue;
        }
        let password = SecretString::from(entered);

        println!("Verifying with `bw unlock`...");
        match cli.unlock(&password).await {
            // The returned session is dropped (zeroized) immediately; we only
            // needed to confirm the password works.
            Ok(_session) => return Ok(password),
            Err(e) => {
                println!("\nUnlock failed:\n{e:#}\n");
                if !prompt_yes_no("Try a different password?", true)? {
                    anyhow::bail!("aborted: master password not verified");
                }
            }
        }
    }
}

/// Pipe the master password into `systemd-creds encrypt`, writing the opaque
/// blob to `cred_path`. The plaintext never touches a file, argv, or the shell.
async fn encrypt_master_password_credential(
    password: &SecretString,
    cred_path: &std::path::Path,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = cred_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating credential directory {}", parent.display()))?;
    }

    let mut child = Command::new("systemd-creds")
        .args(["encrypt", "--name=bw_master_password", "-"])
        .arg(cred_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `systemd-creds encrypt` (is systemd installed?)")?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("failed to open stdin for systemd-creds")?;
        stdin
            .write_all(password.expose_secret().as_bytes())
            .await
            .context("writing master password to systemd-creds")?;
        stdin.flush().await.ok();
        // Dropping stdin closes it, signalling EOF to systemd-creds.
    }

    let out = child
        .wait_with_output()
        .await
        .context("waiting for `systemd-creds encrypt`")?;
    if !out.status.success() {
        anyhow::bail!(
            "`systemd-creds encrypt` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // Enforce 0600 on the credential blob (systemd-creds already does, but be
    // explicit and consistent with the rest of the codebase).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cred_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", cred_path.display()))?;
    }
    Ok(())
}

/// Write `data` to `path` as a fresh file with 0600 permissions.
fn write_private_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.flush()?;

    // Belt-and-braces: enforce 0600 even if the file pre-existed with laxer bits.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

/// Prompt the user to pick one of several named options. Returns the chosen
/// option's key. Matching is case-insensitive and accepts the option number.
fn prompt_choice<'a>(question: &str, options: &[(&'a str, &str)]) -> Result<&'a str> {
    println!("{question}");
    for (i, (key, desc)) in options.iter().enumerate() {
        println!("  {}) {key} - {desc}", i + 1);
    }
    let default_key = options[0].0;
    loop {
        print!("Choice [{default_key}]: ");
        io::stdout().flush()?;
        let answer = match read_line()? {
            None => anyhow::bail!("aborted (end of input)"),
            Some(s) => s,
        };
        if answer.is_empty() {
            return Ok(default_key);
        }
        // Accept a 1-based index.
        if let Ok(n) = answer.parse::<usize>() {
            if n >= 1 && n <= options.len() {
                return Ok(options[n - 1].0);
            }
        }
        // Or the option key (case-insensitive).
        let lower = answer.to_ascii_lowercase();
        if let Some((key, _)) = options.iter().find(|(k, _)| k.eq_ignore_ascii_case(&lower)) {
            return Ok(key);
        }
        println!("Please choose one of the listed options.");
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
