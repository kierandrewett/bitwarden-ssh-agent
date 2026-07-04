//! Interactive `setup` subcommand.
//!
//! Automates everything the README otherwise asks a fresh user to do by hand:
//! check for the `bw` CLI, collect and validate the Bitwarden API key, write the
//! config file, choose a master-password unlock strategy, install and start the
//! systemd user service, and print the `SSH_AUTH_SOCK` line to export.
//!
//! Every destructive step (overwriting the config, the unit file, or an existing
//! credential) prompts first, so re-running `setup` is safe and idempotent.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tokio::process::Command;
use zeroize::Zeroize;

use crate::bitwarden::BitwardenCli;
use crate::config::{self, ApiKey};
use crate::ui::{done_banner, ok_mark, step_banner, with_spinner};

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
    let strategy = provision_master_password(&config_path, &api_key).await?;
    install_systemd_unit(&config_path, strategy)?;
    enable_and_start().await?;
    print_ssh_auth_sock();

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
            println!("{} Found Bitwarden CLI (version {v}).", ok_mark());
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
            println!("{} Installed Bitwarden CLI (version {v}).", ok_mark());
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
        let client_secret = SecretString::from(prompt_secret_once("client_secret")?);
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

        let validation = with_spinner(
            "Validating with `bw login --apikey`...",
            validate_api_key(&api_key, server.as_deref()),
        )
        .await;
        match validation {
            Ok(()) => {
                println!("{} API key accepted; device is now logged in to Bitwarden.", ok_mark());
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

    println!("{} Wrote config file with 0600 permissions.", ok_mark());
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
    step(4, "Master password unlock");
    println!("The master password is what actually unlocks your vault. It is");
    println!("never stored in plaintext.\n");
    println!("Whenever the daemon starts locked (no credential, or the credential");
    println!("fails), you unlock it interactively by running:\n");
    println!("    bitwarden-ssh-agent unlock\n");
    println!("which prompts for the master password in your own terminal and hands");
    println!("it to the running daemon — this always works, headless or not.\n");
    println!("(The daemon also makes a best-effort systemd-ask-password prompt on");
    println!("first use, but that only succeeds if you separately run an");
    println!("ask-password agent, so treat `unlock` as the primary path.)\n");
    println!("Optionally, you can also provision an encrypted systemd credential so");
    println!("the vault unlocks automatically at startup with no prompt.\n");

    if !prompt_yes_no("Set up auto-unlock at startup? (recommended)", true)? {
        println!("\nNo credential will be provisioned. The daemon will start locked;");
        println!("unlock it after each boot by running `bitwarden-ssh-agent unlock`.");
        println!("You can re-run `setup` later to switch to auto-unlock.");
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
    println!("{} Wrote encrypted credential to {} (0600).", ok_mark(), cred_path.display());
    Ok(UnlockStrategy::Credential)
}

/// Prompt (masked) for the master password and confirm it unlocks the vault.
/// Loops until a working password is entered or the user aborts.
async fn prompt_master_password_verified(api_key: &ApiKeyInput) -> Result<SecretString> {
    let cli = BitwardenCli::new(api_key.server.clone());
    loop {
        let password = SecretString::from(prompt_new_password("Bitwarden master password:")?);

        let unlocked = with_spinner("Verifying with `bw unlock`...", cli.unlock(&password)).await;
        match unlocked {
            // The returned session is dropped (zeroized) immediately; we only
            // needed to confirm the password works.
            Ok(_session) => {
                println!("{} Master password verified.", ok_mark());
                return Ok(password);
            }
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

    // `--user` encrypts a *user-scoped* credential (implying `--uid=self`), so a
    // `systemd --user` instance's `LoadCredentialEncrypted=` can decrypt it. The
    // default is *system*-scoped, tied to the PID1 manager, which a `--user`
    // service cannot decrypt — that produces the "Scope mismatch" error and the
    // credential is silently skipped. See systemd-creds(1) `--user`/`--uid=`.
    let mut child = Command::new("systemd-creds")
        .args(["encrypt", "--user", "--name=bw_master_password", "-"])
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

// --- step 5: systemd user unit -----------------------------------------------

/// Filename of the installed systemd user unit.
const UNIT_FILENAME: &str = "bitwarden-ssh-agent.service";

/// Render and install the `systemd --user` unit, pointing `ExecStart=` at the
/// currently-running binary and wiring `LoadCredentialEncrypted=` only when the
/// user chose the credential unlock strategy. Prompts before overwriting.
fn install_systemd_unit(
    config_path: &std::path::Path,
    strategy: UnlockStrategy,
) -> Result<PathBuf> {
    step(5, "systemd user service");

    let unit_dir = systemd_user_dir();
    let unit_path = unit_dir.join(UNIT_FILENAME);
    println!("Unit path: {}", unit_path.display());

    if unit_path.exists()
        && !prompt_yes_no(
            "A unit file already exists here. Overwrite it?",
            true,
        )?
    {
        println!("Keeping existing unit file (its ExecStart/credential settings are unchanged).");
        return Ok(unit_path);
    }

    let exe = std::env::current_exe()
        .context("resolving the path of the current executable")?;
    let cred_path = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(CREDENTIAL_FILENAME);

    let unit = render_unit(&exe, strategy, &cred_path);

    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("creating {}", unit_dir.display()))?;
    std::fs::write(&unit_path, unit)
        .with_context(|| format!("writing unit file {}", unit_path.display()))?;

    println!("{} Installed unit with ExecStart={} serve", ok_mark(), exe.display());
    Ok(unit_path)
}

/// Build the unit file text.
fn render_unit(
    exe: &std::path::Path,
    strategy: UnlockStrategy,
    cred_path: &std::path::Path,
) -> String {
    // Embed the current PATH so the `bw`/`node` binaries found during setup are
    // reachable by the (otherwise minimal-PATH) user service.
    let path = std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());

    let credential_line = match strategy {
        UnlockStrategy::Credential => format!(
            "LoadCredentialEncrypted=bw_master_password:{}\n",
            cred_path.display()
        ),
        UnlockStrategy::OnDemand => String::new(),
    };

    format!(
        "[Unit]\n\
         Description=Bitwarden-backed SSH agent\n\
         Documentation=https://github.com/kierandrewett/bitwarden-ssh-agent\n\
         After=default.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         # Generated by `bitwarden-ssh-agent setup`; points at the installed binary.\n\
         ExecStart={exe} serve\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         # PATH captured at setup time so `bw` (and its node) are reachable.\n\
         Environment=PATH={path}\n\
         {credential_line}\
         # Modest hardening. Do not add ProtectHome — `bw` needs ~/.config.\n\
         NoNewPrivileges=true\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe = exe.display(),
    )
}

// --- step 7: point SSH at the agent ------------------------------------------

/// Print the `SSH_AUTH_SOCK` export line the user must add to their shell rc.
/// We deliberately do NOT edit their rc file; we just show the exact line.
fn print_ssh_auth_sock() {
    done_banner("Point SSH at the agent");

    println!("Setup is complete and the daemon is running. The final step is");
    println!("yours: tell SSH to use this agent, then open a new terminal.\n");

    match shell_rc_hint() {
        ShellHint::Known { rc_file, line } => {
            println!("Add the line below to your shell startup file ({rc_file}):\n");
            println!("    {line}\n");
        }
        ShellHint::Ksh => {
            println!(
                "Add the line below to your shell startup file (~/.kshrc,\n\
                 sourced only if `ENV=~/.kshrc` is set):\n"
            );
            println!("    export SSH_AUTH_SOCK=\"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"\n");
        }
        ShellHint::Unknown => {
            println!("Add the appropriate line to your shell's startup file. The syntax");
            println!("to set an environment variable varies by shell:\n");
            println!("  POSIX-style shells (bash, zsh, sh, ksh):");
            println!("    export SSH_AUTH_SOCK=\"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"\n");
            println!("  csh / tcsh:");
            println!("    setenv SSH_AUTH_SOCK \"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"\n");
            println!("  For anything else (nushell, elvish, ...) check your shell's docs.\n");
        }
    }

    println!("Then verify with:  ssh-add -l");
    println!();
    println!("If the agent has no keys yet, the vault is locked. Unlock it with:");
    println!("    bitwarden-ssh-agent unlock");
    println!("(needed after every reboot unless you provisioned auto-unlock above).");
}

/// A shell-specific hint for setting `SSH_AUTH_SOCK`, derived from `$SHELL`.
enum ShellHint {
    /// A recognized shell with a known rc file and a single env-var line.
    Known {
        rc_file: &'static str,
        line: &'static str,
    },
    /// ksh needs a note that `~/.kshrc` is only sourced when `ENV` points at it.
    Ksh,
    /// Unrecognized shell: show the common syntaxes and defer to its docs.
    Unknown,
}

/// Pick a shell rc file and the matching env-var syntax from `$SHELL`.
fn shell_rc_hint() -> ShellHint {
    const POSIX: &str = "export SSH_AUTH_SOCK=\"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"";
    const CSH: &str = "setenv SSH_AUTH_SOCK \"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"";

    let shell = std::env::var("SHELL").unwrap_or_default();
    let name = std::path::Path::new(&shell)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let known = |rc_file, line| ShellHint::Known { rc_file, line };

    match name.as_str() {
        "bash" => known("~/.bashrc", POSIX),
        "zsh" => known("~/.zshrc", POSIX),
        "fish" => known(
            "~/.config/fish/config.fish",
            "set -gx SSH_AUTH_SOCK \"$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock\"",
        ),
        "ksh" => ShellHint::Ksh,
        "dash" | "sh" => known("~/.profile", POSIX),
        "csh" => known("~/.cshrc", CSH),
        "tcsh" => known("~/.tcshrc", CSH),
        "nu" => known(
            "~/.config/nushell/env.nu",
            "$env.SSH_AUTH_SOCK = ($env.XDG_RUNTIME_DIR | path join \"bitwarden-ssh-agent.sock\")",
        ),
        _ => ShellHint::Unknown,
    }
}

// --- step 6: enable and start ------------------------------------------------

/// Reload systemd, enable+start the service, and report whether it came up.
async fn enable_and_start() -> Result<()> {
    step(6, "Enable and start the service");

    with_spinner("Reloading systemd and (re)starting the service...", async {
        run_systemctl(&["daemon-reload"]).await?;
        // `enable` (no `--now`) creates the boot symlink; `restart` then always
        // (re)starts the unit. Using `enable --now` would NOT restart a service
        // that was already running from a previous `setup` run, silently leaving
        // it on stale config/credential — so restart unconditionally instead.
        run_systemctl(&["enable", UNIT_FILENAME]).await?;
        run_systemctl(&["restart", UNIT_FILENAME]).await
    })
    .await?;

    // `is-active` exits non-zero when not active, so inspect stdout directly.
    let out = Command::new("systemctl")
        .args(["--user", "is-active", UNIT_FILENAME])
        .stdin(Stdio::null())
        .output()
        .await
        .context("running `systemctl --user is-active`")?;
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();

    if state == "active" {
        println!("{} Service is active and running.", ok_mark());
    } else {
        println!(
            "\nThe service is not active (state: {}).\n\
             Inspect the logs with:\n  \
             journalctl --user -u {} -e",
            if state.is_empty() { "unknown" } else { &state },
            UNIT_FILENAME
        );
        anyhow::bail!("service failed to start; see the logs above");
    }
    Ok(())
}

/// Run `systemctl --user <args...>`, failing loudly on a non-zero exit.
async fn run_systemctl(args: &[&str]) -> Result<()> {
    let mut full = vec!["--user"];
    full.extend_from_slice(args);
    let out = Command::new("systemctl")
        .args(&full)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("running `systemctl {}`", full.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`systemctl {}` failed: {}",
            full.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `$XDG_CONFIG_HOME/systemd/user` (or `~/.config/systemd/user`).
fn systemd_user_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            home.join(".config")
        });
    base.join("systemd").join("user")
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

/// Total number of numbered steps in the wizard (the final "point SSH at the
/// agent" hint is a closing note, not a numbered action step).
const TOTAL_STEPS: u8 = 6;

/// Print a colored, progress-numbered step banner so the user can follow along.
/// Thin wrapper over [`crate::ui::step_banner`] that fills in setup's step total.
fn step(n: u8, title: &str) {
    step_banner(n, TOTAL_STEPS, title);
}

/// Prompt for a free-form line of text. With a default, an empty submission
/// returns it; without one, the field is required (inquire re-asks on empty).
fn prompt(question: &str, default: Option<&str>) -> Result<String> {
    let text = inquire::Text::new(question);
    let text = match default {
        Some(d) => text.with_default(d),
        None => text.with_validator(inquire::required!("this field is required")),
    };
    text.prompt().map(|s| s.trim().to_string()).map_err(map_inquire_err)
}

/// Prompt once (masked) for a secret, with no confirmation retype. Suitable for
/// values that are validated immediately afterwards (e.g. the API client_secret).
fn prompt_secret_once(question: &str) -> Result<String> {
    inquire::Password::new(question)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(map_inquire_err)
}

/// Prompt (masked) for a new secret the user is entering fresh, requiring a
/// confirmation retype so an unnoticed typo can't get baked in. Used for the
/// master password, where a typo is expensive to debug later.
fn prompt_new_password(question: &str) -> Result<String> {
    inquire::Password::new(question)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm — retype to catch typos:")
        .with_validator(inquire::required!("password must not be empty"))
        .prompt()
        .map_err(map_inquire_err)
}

/// Prompt the user to pick one of several named options via an arrow-key menu.
/// Returns the chosen option's key. The first option is the default selection.
fn prompt_choice<'a>(question: &str, options: &[(&'a str, &str)]) -> Result<&'a str> {
    let display: Vec<String> = options
        .iter()
        .map(|(key, desc)| format!("{key} — {desc}"))
        .collect();
    let chosen = inquire::Select::new(question, display)
        .raw_prompt()
        .map_err(map_inquire_err)?;
    Ok(options[chosen.index].0)
}

/// Prompt for a yes/no answer with a default, using an interactive confirm.
fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    inquire::Confirm::new(question)
        .with_default(default_yes)
        .prompt()
        .map_err(map_inquire_err)
}

/// Map an `inquire` error into an `anyhow` error, treating Ctrl-C / Esc
/// cancellation as a clean "aborted" rather than a noisy failure.
fn map_inquire_err(err: inquire::InquireError) -> anyhow::Error {
    use inquire::InquireError::{OperationCanceled, OperationInterrupted};
    match err {
        OperationCanceled | OperationInterrupted => anyhow!("aborted by user"),
        other => anyhow!(other),
    }
}
