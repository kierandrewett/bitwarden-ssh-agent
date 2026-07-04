//! Interactive `import` subcommand.
//!
//! Brings existing SSH private keys from `~/.ssh` into the Bitwarden vault as
//! "SSH Key" items (cipher type 5), so the daemon can serve them. This is a
//! standalone one-off invocation: it runs its own `bw` login/unlock rather than
//! talking to the running daemon, then walks the user through a wizard so they
//! can be picky and keep full visibility over exactly what gets uploaded.
//!
//! Security: the master password and any decrypted passphrase are wrapped in
//! `secrecy`/`zeroize` and never logged or written to disk. The vault item JSON
//! (which contains the private key) is piped to `bw` through stdin, never argv.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use secrecy::SecretString;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroize;

use crate::bitwarden::{BitwardenCli, Session, SshKeyItem};
use crate::config::Config;
use crate::ui::{ok_mark, step_banner, with_spinner};

/// Total number of numbered steps in the import wizard.
const TOTAL_STEPS: u8 = 4;

/// Print a progress-numbered step banner, matching `setup`'s style.
fn step(n: u8, title: &str) {
    step_banner(n, TOTAL_STEPS, title);
}

/// A private key file discovered in the SSH directory, with everything the
/// wizard needs to display it and (later) import it.
struct Candidate {
    /// Absolute path to the private key file.
    path: PathBuf,
    /// Key algorithm as OpenSSH names it (`ssh-ed25519`, `ssh-rsa`, ...).
    algorithm: String,
    /// `SHA256:...` fingerprint, computed from the public half.
    fingerprint: String,
    /// Human-readable comment (from the `.pub` file if present, else the key).
    comment: String,
    /// The OpenSSH public-key line (`ssh-ed25519 AAAA... comment`).
    public_openssh: String,
    /// Raw contents of the private key file (an OpenSSH PEM block). For an
    /// encrypted key this is the still-encrypted blob.
    private_pem: String,
    /// Whether the private key is passphrase-encrypted at rest.
    encrypted: bool,
}

impl Candidate {
    /// A short label for the algorithm/encryption, e.g. `ssh-ed25519`.
    fn algo_label(&self) -> &str {
        &self.algorithm
    }
}

/// Filenames in `~/.ssh` that are never private keys and should be skipped
/// outright (before even attempting to parse them).
fn is_non_key_filename(name: &str) -> bool {
    // `.pub` files are public halves; the rest are SSH housekeeping files.
    name.ends_with(".pub")
        || name == "config"
        || name == "authorized_keys"
        || name == "environment"
        || name.starts_with("known_hosts")
}

/// Scan `dir` for private key files, returning a [`Candidate`] for each file
/// that parses as an OpenSSH private key. Files that do not parse (including
/// `.pub`, `known_hosts`, `config`, directories, unreadable files) are skipped
/// silently — this is discovery, not validation, so one odd file must not abort
/// the whole scan.
fn scan_dir(dir: &Path) -> Result<Vec<Candidate>> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading SSH directory {}", dir.display()))?;

    let mut candidates = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log::debug!("skipping unreadable directory entry: {e}");
                continue;
            }
        };
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if is_non_key_filename(&name) {
            continue;
        }
        if !path.is_file() {
            continue;
        }

        match analyze_file(&path) {
            Ok(Some(candidate)) => candidates.push(candidate),
            Ok(None) => {} // not a private key; skip quietly
            Err(e) => log::debug!("skipping {}: {e:#}", path.display()),
        }
    }

    // Stable, predictable ordering by path so the wizard list is deterministic.
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(candidates)
}

/// OpenSSH private keys are at most a few KB (even a 4096-bit RSA key is under
/// 4 KB of base64). Anything bigger is definitely not a key, so skip it before
/// reading — without this, pointing `--ssh-dir` at an arbitrary directory (e.g.
/// `~/Documents`) would read every large file (videos, PDFs, ...) fully into
/// memory just to reject it, which can take a very long time.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Try to interpret a single file as an OpenSSH private key. Returns `Ok(None)`
/// if the file simply is not a private key (so the caller skips it), and only
/// errors on an unexpected I/O problem worth logging.
fn analyze_file(path: &Path) -> Result<Option<Candidate>> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_KEY_FILE_BYTES => return Ok(None),
        Ok(_) => {}
        Err(_) => return Ok(None),
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        // Binary or unreadable file: definitely not an OpenSSH PEM key.
        Err(_) => return Ok(None),
    };

    let key = match PrivateKey::from_openssh(contents.as_bytes()) {
        Ok(k) => k,
        Err(_) => return Ok(None), // not a private key
    };

    Ok(Some(build_candidate(path, contents, &key)?))
}

/// Build a [`Candidate`] from a parsed key plus the raw file contents and an
/// optional sibling `.pub` file (used for the comment when present). Split out
/// from I/O so it can be unit-tested directly.
fn build_candidate(path: &Path, contents: String, key: &PrivateKey) -> Result<Candidate> {
    // The public half is always in cleartext in the OpenSSH private key format,
    // so fingerprint/algorithm/public-key work even for an encrypted key.
    let public = key.public_key();
    let algorithm = public.algorithm().as_str().to_string();
    let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
    let public_openssh = public
        .to_openssh()
        .with_context(|| format!("serializing public key for {}", path.display()))?;

    // Prefer the comment from a sibling `<name>.pub` (that's what the user sees
    // in their `.pub`), falling back to the comment embedded in the key itself.
    let comment = read_pub_comment(path)
        .filter(|c| !c.is_empty())
        .or_else(|| {
            let c = public.comment().trim();
            (!c.is_empty()).then(|| c.to_string())
        })
        .unwrap_or_default();

    Ok(Candidate {
        path: path.to_path_buf(),
        algorithm,
        fingerprint,
        comment,
        public_openssh,
        private_pem: contents,
        encrypted: key.is_encrypted(),
    })
}

/// Read the comment field (everything after the base64 blob) from a sibling
/// `<name>.pub` file, if it exists and is well-formed.
fn read_pub_comment(private_path: &Path) -> Option<String> {
    let pub_path = pub_path_for(private_path);
    let line = std::fs::read_to_string(&pub_path).ok()?;
    comment_from_pub_line(&line)
}

/// `~/.ssh/id_ed25519` -> `~/.ssh/id_ed25519.pub`.
fn pub_path_for(private_path: &Path) -> PathBuf {
    let mut name = private_path.as_os_str().to_os_string();
    name.push(".pub");
    PathBuf::from(name)
}

/// Extract the trailing comment from an OpenSSH public-key line
/// (`<type> <base64> <comment...>`). Returns `None` if there is no comment.
fn comment_from_pub_line(line: &str) -> Option<String> {
    let mut parts = line.trim().splitn(3, char::is_whitespace);
    let _type = parts.next()?;
    let _blob = parts.next()?;
    let comment = parts.next()?.trim();
    (!comment.is_empty()).then(|| comment.to_string())
}

/// A pointer to an SSH Key item already in the vault, indexed by its computed
/// fingerprint so freshly-scanned candidates can be deduped against it.
struct VaultKeyRef {
    /// Vault item UUID (needed to overwrite/edit it in place).
    id: String,
    /// The vault item's display name (shown when a duplicate is detected).
    name: String,
    /// `SHA256:...` fingerprint of the item's public key.
    fingerprint: String,
}

/// Compute the SHA256 fingerprint of an OpenSSH public-key line, matching the
/// `SHA256:...` format used for the local candidates so the two can be compared.
fn fingerprint_of_public(public_openssh: &str) -> Option<String> {
    let public = PublicKey::from_openssh(public_openssh).ok()?;
    Some(public.fingerprint(HashAlg::Sha256).to_string())
}

/// Build a fingerprint index of the SSH Key items already in the vault.
///
/// The fingerprint is recomputed from each item's public key (authoritative and
/// in our exact format), falling back to the item's stored `keyFingerprint`
/// only if the public key can't be parsed. Items we cannot fingerprint at all
/// are dropped from the index (they simply won't dedupe).
fn index_vault_keys(items: &[SshKeyItem]) -> Vec<VaultKeyRef> {
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let fingerprint = fingerprint_of_public(&item.ssh_key.public_key)
            .or_else(|| item.ssh_key.key_fingerprint.clone());
        match fingerprint {
            Some(fingerprint) => refs.push(VaultKeyRef {
                id: item.id.clone(),
                name: item.name.clone(),
                fingerprint,
            }),
            None => log::debug!(
                "vault item '{}' has no usable public key/fingerprint; not deduping against it",
                item.name
            ),
        }
    }
    refs
}

/// Find an existing vault key with the same fingerprint as `candidate`.
fn find_vault_match<'a>(
    index: &'a [VaultKeyRef],
    fingerprint: &str,
) -> Option<&'a VaultKeyRef> {
    index.iter().find(|r| r.fingerprint == fingerprint)
}

/// Resolve the SSH directory to scan: explicit override, else `~/.ssh`.
fn resolve_ssh_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .context("HOME is not set; pass --ssh-dir to choose a directory to scan")?;
    Ok(PathBuf::from(home).join(".ssh"))
}

/// The `sshKey` payload for a vault SSH Key item. `private_key` is sensitive and
/// is zeroized once the item has been created.
struct SshKeyPayload {
    private_key: String,
    public_key: String,
    fingerprint: String,
}

impl Drop for SshKeyPayload {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// What the wizard decided to do with a single selected candidate.
enum KeyPlan {
    /// Create a brand-new vault item.
    Create {
        name: String,
        notes: Option<String>,
        payload: SshKeyPayload,
    },
    /// Overwrite an existing vault item (fingerprint already present).
    Overwrite {
        id: String,
        name: String,
        notes: Option<String>,
        payload: SshKeyPayload,
    },
    /// Skip this key, recording why for the closing summary.
    Skip { name: String, reason: String },
}

/// Entry point for `bitwarden-ssh-agent import`.
pub async fn run(
    ssh_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
    control_socket: Option<PathBuf>,
) -> Result<()> {
    println!("bitwarden-ssh-agent import");
    println!("==========================\n");
    if dry_run {
        println!("(dry run: no vault items will be created or modified)\n");
    }

    // --- Step 1: scan for keys ---------------------------------------------
    step(1, "Scan for SSH keys");
    let dir = resolve_ssh_dir(ssh_dir)?;
    println!("Scanning {} for SSH private keys...", dir.display());
    let mut candidates = scan_dir(&dir)?;

    if candidates.is_empty() {
        println!("No SSH private keys found in {}.", dir.display());
        return Ok(());
    }
    println!("{} Found {} candidate key(s):\n", ok_mark(), candidates.len());
    // Show the discovered keys in full *before* asking for the master password,
    // so the user can sanity-check the scan (wrong --ssh-dir, unexpected file)
    // before authenticating to anything. Vault-dedup status isn't known yet, so
    // pass `None` — the wizard re-lists them later annotated with vault status.
    for candidate in candidates.iter() {
        println!("  {}", candidate_label(candidate, None));
    }

    // --- Step 2: unlock the vault ------------------------------------------
    step(2, "Unlock your Bitwarden vault");
    // Unlock our own `bw` session (independent of the running daemon) and read
    // the SSH Key items already in the vault, so duplicates can be flagged.
    let (cli, session) = open_vault_session(config).await?;
    let existing = with_spinner(
        "Reading existing SSH Key items from your vault...",
        cli.list_ssh_keys(&session),
    )
    .await
    .context("listing existing SSH Key items from the vault")?;
    let vault_index = index_vault_keys(&existing);
    println!(
        "{} Vault currently holds {} SSH Key item(s).",
        ok_mark(),
        vault_index.len()
    );

    // Let the user pick which keys to import, then decide per-key what to do.
    let result = run_wizard(
        &mut candidates,
        &vault_index,
        &cli,
        &session,
        dry_run,
        control_socket.as_deref(),
    )
    .await;

    // Scrub the raw private-key material we read off disk regardless of outcome.
    for c in &mut candidates {
        c.private_pem.zeroize();
    }
    result
}

/// Run the selection + per-key decisions + execution + summary.
async fn run_wizard(
    candidates: &mut [Candidate],
    vault_index: &[VaultKeyRef],
    cli: &BitwardenCli,
    session: &Session,
    dry_run: bool,
    control_socket: Option<&Path>,
) -> Result<()> {
    // Precompute, for each candidate, whether it is already in the vault.
    let matches: Vec<Option<&VaultKeyRef>> = candidates
        .iter()
        .map(|c| find_vault_match(vault_index, &c.fingerprint))
        .collect();

    step(3, "Choose what to import");

    // Build the MultiSelect list. Default-select keys that are neither already
    // in the vault nor passphrase-protected (the safe, ready-to-use ones).
    let labels: Vec<String> = candidates
        .iter()
        .zip(&matches)
        .map(|(c, m)| candidate_label(c, *m))
        .collect();
    let defaults: Vec<usize> = candidates
        .iter()
        .zip(&matches)
        .enumerate()
        .filter(|(_, (c, m))| m.is_none() && !c.encrypted)
        .map(|(i, _)| i)
        .collect();

    let chosen = inquire::MultiSelect::new(
        "Select the keys to import (space toggles, enter confirms):",
        labels,
    )
    .with_default(&defaults)
    .with_help_message(
        "Pre-selected: keys not already in your vault and not passphrase-protected.",
    )
    .raw_prompt()
    .map_err(map_inquire_err)?;
    let selected_indices: Vec<usize> = chosen.iter().map(|o| o.index).collect();

    if selected_indices.is_empty() {
        println!("\nNothing selected; nothing to do.");
        return Ok(());
    }

    // Decide what to do with each selected key (may prompt for passphrases,
    // names, and skip/overwrite decisions).
    let mut plans = Vec::new();
    for idx in selected_indices {
        let candidate = &candidates[idx];
        let existing = matches[idx];
        plans.push(decide_for_key(candidate, existing)?);
    }

    step(4, "Import");
    let changes = execute_plans(plans, cli, session, dry_run).await?;

    // If we actually changed the vault and the daemon is running, offer to nudge
    // it so the new keys are served immediately without a restart.
    if !dry_run && changes > 0 {
        if let Err(e) = offer_daemon_refresh(control_socket).await {
            // Best-effort: a failed refresh must not fail the import itself.
            println!("Could not refresh the running daemon: {e:#}");
            println!("The new keys will be picked up next time it (re)starts.");
        }
    }
    Ok(())
}

/// If the running daemon's control socket is reachable, offer to ask it to
/// re-sync the vault and pick up the newly-imported keys right away — over the
/// same local IPC channel the `unlock` command already uses, not a process
/// signal. No-op (not an error) if the daemon isn't running.
async fn offer_daemon_refresh(control_socket: Option<&Path>) -> Result<()> {
    let control_path = match crate::control::resolve_control_path(control_socket.map(Path::to_path_buf)) {
        Ok(p) => p,
        Err(_) => return Ok(()), // e.g. no XDG_RUNTIME_DIR; nothing to offer.
    };
    if tokio::net::UnixStream::connect(&control_path).await.is_err() {
        // Daemon not running (or not listening yet); nothing to refresh.
        return Ok(());
    }

    println!();
    if !prompt_yes_no(
        "The agent daemon is running. Ask it to refresh now so the new keys are \
         served immediately?",
        true,
    )? {
        println!(
            "Skipped. Refresh later with `bitwarden-ssh-agent refresh` \
             (or just re-run your SSH command; a restart also picks them up)."
        );
        return Ok(());
    }

    crate::control::run_refresh_client(&control_path).await?;
    Ok(())
}

/// Interactively decide what to do with one selected candidate.
fn decide_for_key(candidate: &Candidate, existing: Option<&VaultKeyRef>) -> Result<KeyPlan> {
    let default_name = default_item_name(candidate);
    println!("\n{}", separator());
    println!("Key: {}", candidate.path.display());
    println!("  type:        {}", candidate.algorithm);
    println!("  fingerprint: {}", candidate.fingerprint);
    if !candidate.comment.is_empty() {
        println!("  comment:     {}", candidate.comment);
    }

    // 1. If it already exists in the vault, ask skip vs overwrite up front so we
    //    don't bother prompting for a passphrase on a key we'll skip.
    let overwrite_id = if let Some(existing) = existing {
        println!(
            "  This key is already in your vault as \"{}\".",
            existing.name
        );
        match prompt_choice(
            "It is already in the vault. What do you want to do?",
            &[
                ("skip", "leave the existing item untouched"),
                ("overwrite", "replace the existing item's key material"),
            ],
        )? {
            "overwrite" => Some(existing.id.clone()),
            _ => {
                return Ok(KeyPlan::Skip {
                    name: existing.name.clone(),
                    reason: "already in vault (kept existing item)".to_string(),
                });
            }
        }
    } else {
        None
    };

    // 2. Resolve the private-key material, handling passphrase-encrypted keys.
    let private_key = if candidate.encrypted {
        println!(
            "  This key is passphrase-protected. Note: the agent cannot yet sign\n\
             \x20 with encrypted keys, so an encrypted blob is stored for backup only."
        );
        match prompt_choice(
            "How should this passphrase-protected key be handled?",
            &[
                (
                    "decrypt",
                    "enter the passphrase; store the DECRYPTED key so the agent can use it",
                ),
                (
                    "encrypted",
                    "store the encrypted blob as-is (backup only; unusable until decrypted)",
                ),
                ("skip", "do not import this key"),
            ],
        )? {
            "decrypt" => decrypt_candidate(candidate)?,
            "encrypted" => candidate.private_pem.clone(),
            _ => {
                return Ok(KeyPlan::Skip {
                    name: default_name,
                    reason: "passphrase-protected (skipped by choice)".to_string(),
                });
            }
        }
    } else {
        candidate.private_pem.clone()
    };

    // 3. Confirm the item name and optionally add a note (e.g. what this key is
    //    for). Left blank, the item's notes are cleared rather than left as
    //    whatever placeholder text `bw get template item` happens to ship
    //    (e.g. "Some notes about this item.") — that text is template filler,
    //    not something that should end up on a real vault item.
    let name = prompt_text("Vault item name:", &default_name)?;
    let notes = prompt_text("Notes (optional, e.g. what this key is for):", "")?;
    let notes = (!notes.is_empty()).then_some(notes);

    let payload = SshKeyPayload {
        private_key,
        public_key: candidate.public_openssh.clone(),
        fingerprint: candidate.fingerprint.clone(),
    };

    Ok(match overwrite_id {
        Some(id) => KeyPlan::Overwrite {
            id,
            name,
            notes,
            payload,
        },
        None => KeyPlan::Create {
            name,
            notes,
            payload,
        },
    })
}

/// Decrypt a passphrase-protected candidate in memory, prompting (masked) for
/// the passphrase, and return the DECRYPTED OpenSSH private-key text. The
/// passphrase is zeroized on drop; nothing touches disk.
fn decrypt_candidate(candidate: &Candidate) -> Result<String> {
    println!(
        "  (Heads up: the decrypted key is stored unencrypted inside the vault —\n\
         \x20 the same trust model as every other key already there; Bitwarden's\n\
         \x20 own encryption is the protection, not the passphrase.)"
    );
    let encrypted = PrivateKey::from_openssh(candidate.private_pem.as_bytes())
        .context("re-parsing the encrypted private key")?;

    loop {
        let passphrase = SecretString::from(prompt_secret("Passphrase for this key:")?);
        match encrypted.decrypt(secrecy::ExposeSecret::expose_secret(&passphrase).as_bytes()) {
            Ok(decrypted) => {
                let pem = decrypted
                    .to_openssh(LineEnding::LF)
                    .context("serializing the decrypted private key")?;
                return Ok(pem.to_string());
            }
            Err(_) => {
                println!("  Wrong passphrase.");
                if !prompt_yes_no("Try the passphrase again?", true)? {
                    anyhow::bail!("aborted: could not decrypt {}", candidate.path.display());
                }
            }
        }
    }
}

/// Execute the plans (or, in dry-run mode, describe them), then print a summary.
async fn execute_plans(
    plans: Vec<KeyPlan>,
    cli: &BitwardenCli,
    session: &Session,
    dry_run: bool,
) -> Result<usize> {
    // Fetch the new-item template once, only if we will actually create anything.
    let will_create = !dry_run
        && plans
            .iter()
            .any(|p| matches!(p, KeyPlan::Create { .. }));
    let template = if will_create {
        Some(
            with_spinner("Fetching the `bw` item template...", cli.item_template(session))
                .await
                .context("fetching the `bw` item template")?,
        )
    } else {
        None
    };

    let mut created = Vec::new();
    let mut overwritten = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    println!("\n{}", separator());
    for plan in &plans {
        match plan {
            KeyPlan::Create { name, notes, payload } => {
                if dry_run {
                    println!("would create:    {name}");
                    created.push(name.clone());
                    continue;
                }
                let base = template.clone().expect("template fetched when creating");
                let item = build_item_value(base, name, notes.as_deref(), payload);
                match with_spinner(
                    &format!("Creating vault item \"{name}\"..."),
                    cli.create_item(session, &item),
                )
                .await
                {
                    Ok(id) => {
                        println!("created:         {name}  (id {id})");
                        created.push(name.clone());
                    }
                    Err(e) => {
                        println!("FAILED to create {name}: {e:#}");
                        failed.push(format!("{name}: {e:#}"));
                    }
                }
            }
            KeyPlan::Overwrite { id, name, notes, payload } => {
                if dry_run {
                    println!("would overwrite: {name}  (id {id})");
                    overwritten.push(name.clone());
                    continue;
                }
                match with_spinner(
                    &format!("Overwriting vault item \"{name}\"..."),
                    overwrite_item(cli, session, id, name, notes.as_deref(), payload),
                )
                .await
                {
                    Ok(()) => {
                        println!("overwritten:     {name}  (id {id})");
                        overwritten.push(name.clone());
                    }
                    Err(e) => {
                        println!("FAILED to overwrite {name}: {e:#}");
                        failed.push(format!("{name}: {e:#}"));
                    }
                }
            }
            KeyPlan::Skip { name, reason } => {
                println!("skipped:         {name} ({reason})");
                skipped.push(name.clone());
            }
        }
    }

    println!("\n{}", separator());
    let verb = if dry_run { "would import" } else { "imported" };
    println!(
        "Done. {verb}: {} created, {} overwritten; {} skipped; {} failed.",
        created.len(),
        overwritten.len(),
        skipped.len(),
        failed.len(),
    );
    if !failed.is_empty() {
        println!("\nFailures:");
        for f in &failed {
            println!("  - {f}");
        }
    }

    Ok(created.len() + overwritten.len())
}

/// Overwrite an existing vault item's key material, preserving its other fields.
async fn overwrite_item(
    cli: &BitwardenCli,
    session: &Session,
    id: &str,
    name: &str,
    notes: Option<&str>,
    payload: &SshKeyPayload,
) -> Result<()> {
    let existing = cli
        .get_item(session, id)
        .await
        .context("fetching the existing vault item to overwrite")?;
    // Leaving the notes prompt blank on an overwrite means "keep whatever note
    // is already there", not "clear it" — only override if the user typed one.
    let kept_notes = existing.get("notes").and_then(|v| v.as_str()).map(str::to_string);
    let notes = notes.map(str::to_string).or(kept_notes);
    let item = build_item_value(existing, name, notes.as_deref(), payload);
    cli.edit_item(session, id, &item).await?;
    Ok(())
}

/// Merge an SSH Key payload into a base object (an item template for a new item,
/// or the existing item for an overwrite), producing a valid type-5 item.
fn build_item_value(
    base: serde_json::Value,
    name: &str,
    notes: Option<&str>,
    payload: &SshKeyPayload,
) -> serde_json::Value {
    use serde_json::{json, Map, Value};

    let mut map = match base {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    map.insert("type".to_string(), json!(5));
    map.insert("name".to_string(), json!(name));
    // Always set explicitly (never left as the template's placeholder text,
    // e.g. "Some notes about this item.") — `None` clears it to `null`.
    map.insert("notes".to_string(), json!(notes));
    map.insert(
        "sshKey".to_string(),
        json!({
            "privateKey": payload.private_key,
            "publicKey": payload.public_key,
            "keyFingerprint": payload.fingerprint,
        }),
    );
    // A type-5 item carries none of the other type-specific payloads; null them
    // so a template (or a converted item) can't smuggle a stale login/card in.
    for key in ["login", "secureNote", "card", "identity"] {
        map.insert(key.to_string(), Value::Null);
    }
    Value::Object(map)
}

/// Log in (via the configured API key, or a prior `bw login`) and unlock the
/// vault with a freshly-prompted master password, returning a live session.
async fn open_vault_session(config: Option<PathBuf>) -> Result<(BitwardenCli, Session)> {
    let cfg = match &config {
        Some(path) => Config::load_from(path)?,
        None => Config::load()?,
    };
    let cli = BitwardenCli::new(cfg.server.clone());

    println!("To check your vault for duplicates and import the keys you pick, this");
    println!("needs to log in and unlock your Bitwarden vault next.\n");

    // Ensure the device is logged in.
    match &cfg.api_key {
        Some(api_key) => with_spinner(
            "Logging in to Bitwarden with the configured API key...",
            cli.login_with_api_key(api_key),
        )
        .await
        .context("logging in to Bitwarden with the configured API key")?,
        None => {
            let status = with_spinner("Checking Bitwarden login status...", cli.status()).await?;
            if status.status == "unauthenticated" {
                anyhow::bail!(
                    "no Bitwarden API key configured and the `bw` CLI is not logged in; \
                     run `bitwarden-ssh-agent setup` (or `bw login`) first"
                );
            }
        }
    }

    // Unlock with the master password typed here (masked). Loop on a wrong one.
    println!("Enter your Bitwarden master password below (typed directly here, masked,");
    println!("and never written to disk or logged) to unlock the vault:\n");
    loop {
        let password = SecretString::from(prompt_secret("Bitwarden master password:")?);
        match with_spinner("Unlocking your vault...", cli.unlock(&password)).await {
            Ok(session) => {
                println!("{} Vault unlocked.", ok_mark());
                return Ok((cli, session));
            }
            Err(e) => {
                println!("Unlock failed: {e:#}");
                if !prompt_yes_no("Try a different master password?", true)? {
                    anyhow::bail!("aborted: vault not unlocked");
                }
            }
        }
    }
}

/// A sensible default vault item name derived from the file name and comment,
/// e.g. `id_ed25519 (user@host)`.
fn default_item_name(candidate: &Candidate) -> String {
    let file = candidate
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ssh key".to_string());
    if candidate.comment.is_empty() {
        file
    } else {
        format!("{file} ({})", candidate.comment)
    }
}

/// One-line summary of a candidate for the MultiSelect list.
fn candidate_label(candidate: &Candidate, existing: Option<&VaultKeyRef>) -> String {
    let name = candidate
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut flags = Vec::new();
    if candidate.encrypted {
        flags.push("passphrase-protected".to_string());
    }
    if let Some(existing) = existing {
        flags.push(format!("already in vault as \"{}\"", existing.name));
    }
    let suffix = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join("; "))
    };
    format!(
        "{name}  ({}, {}){suffix}",
        candidate.algo_label(),
        candidate.fingerprint
    )
}

fn separator() -> &'static str {
    "----------------------------------------------------------------"
}

// --- inquire helpers (mirroring the style used in setup.rs) ------------------

fn prompt_text(question: &str, default: &str) -> Result<String> {
    inquire::Text::new(question)
        .with_default(default)
        .prompt()
        .map(|s| s.trim().to_string())
        .map_err(map_inquire_err)
}

fn prompt_secret(question: &str) -> Result<String> {
    inquire::Password::new(question)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
        .map_err(map_inquire_err)
}

fn prompt_yes_no(question: &str, default_yes: bool) -> Result<bool> {
    inquire::Confirm::new(question)
        .with_default(default_yes)
        .prompt()
        .map_err(map_inquire_err)
}

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

fn map_inquire_err(err: inquire::InquireError) -> anyhow::Error {
    use inquire::InquireError::{OperationCanceled, OperationInterrupted};
    match err {
        OperationCanceled | OperationInterrupted => anyhow!("aborted by user"),
        other => anyhow!(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding};

    fn write(dir: &Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    fn gen_ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn comment_parsing_from_pub_line() {
        assert_eq!(
            comment_from_pub_line("ssh-ed25519 AAAAC3Nz user@host"),
            Some("user@host".to_string())
        );
        // Comment with spaces is kept whole.
        assert_eq!(
            comment_from_pub_line("ssh-rsa AAAAB3 my laptop key"),
            Some("my laptop key".to_string())
        );
        // No comment -> None.
        assert_eq!(comment_from_pub_line("ssh-ed25519 AAAAC3Nz"), None);
    }

    #[test]
    fn non_key_filenames_are_skipped() {
        assert!(is_non_key_filename("config"));
        assert!(is_non_key_filename("known_hosts"));
        assert!(is_non_key_filename("known_hosts.old"));
        assert!(is_non_key_filename("authorized_keys"));
        assert!(is_non_key_filename("id_ed25519.pub"));
        assert!(!is_non_key_filename("id_ed25519"));
    }

    #[test]
    fn scan_discovers_keys_and_skips_noise() {
        let tmp = tempdir();
        let dir = tmp.path();

        // A plain unencrypted key with a sibling .pub carrying a comment.
        let key = gen_ed25519();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        write(dir, "id_ed25519", &pem);
        let pub_line = format!(
            "{} laptop@home\n",
            key.public_key().to_openssh().unwrap()
        );
        write(dir, "id_ed25519.pub", &pub_line);

        // Noise that must be ignored.
        write(dir, "known_hosts", "host ssh-ed25519 AAAA\n");
        write(dir, "config", "Host *\n  User me\n");
        write(dir, "random.txt", "not a key at all\n");

        let found = scan_dir(dir).unwrap();
        assert_eq!(found.len(), 1, "only the one private key should be found");
        let c = &found[0];
        assert_eq!(c.algorithm, "ssh-ed25519");
        assert!(c.fingerprint.starts_with("SHA256:"));
        assert_eq!(c.comment, "laptop@home");
        assert!(!c.encrypted);
    }

    #[test]
    fn encrypted_key_is_flagged_not_rejected() {
        let tmp = tempdir();
        let dir = tmp.path();

        let key = gen_ed25519();
        let encrypted = key.encrypt(&mut OsRng, "correct horse").unwrap();
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap();
        write(dir, "id_secure", &pem);

        let found = scan_dir(dir).unwrap();
        assert_eq!(found.len(), 1);
        let c = &found[0];
        assert!(c.encrypted, "the encrypted key must be flagged");
        assert_eq!(c.algorithm, "ssh-ed25519");
        // Fingerprint/public key are still available from the cleartext half.
        assert!(c.fingerprint.starts_with("SHA256:"));
        assert!(c.public_openssh.starts_with("ssh-ed25519 "));
    }

    fn vault_item(id: &str, name: &str, public_openssh: &str, fp: Option<&str>) -> SshKeyItem {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": name,
            "sshKey": {
                "privateKey": "PRIVATE-PLACEHOLDER",
                "publicKey": public_openssh,
                "keyFingerprint": fp,
            },
        }))
        .unwrap()
    }

    #[test]
    fn dedup_matches_candidate_against_vault_by_fingerprint() {
        let key = gen_ed25519();
        let public_openssh = key.public_key().to_openssh().unwrap();
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();

        // Vault has this key (under a different item name) plus an unrelated one.
        let other = gen_ed25519();
        let items = vec![
            vault_item("id-1", "Laptop key", &public_openssh, None),
            vault_item(
                "id-2",
                "Some other key",
                &other.public_key().to_openssh().unwrap(),
                None,
            ),
        ];
        let index = index_vault_keys(&items);
        assert_eq!(index.len(), 2);

        let hit = find_vault_match(&index, &fingerprint).expect("should find a match");
        assert_eq!(hit.id, "id-1");
        assert_eq!(hit.name, "Laptop key");

        // A key not in the vault does not match.
        let stranger = gen_ed25519();
        let stranger_fp = stranger.public_key().fingerprint(HashAlg::Sha256).to_string();
        assert!(find_vault_match(&index, &stranger_fp).is_none());
    }

    #[test]
    fn dedup_falls_back_to_stored_fingerprint_when_public_key_unparseable() {
        let items = vec![vault_item("id-x", "Odd key", "not-a-valid-public-key", Some("SHA256:stored"))];
        let index = index_vault_keys(&items);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].fingerprint, "SHA256:stored");
    }

    #[test]
    fn build_item_value_produces_type5_ssh_key_shape() {
        let template = serde_json::json!({
            "type": 1,
            "name": "",
            "notes": "Some notes about this item.",
            "favorite": false,
            "login": { "username": "leftover" },
            "sshKey": null,
        });
        let payload = SshKeyPayload {
            private_key: "PRIV".to_string(),
            public_key: "ssh-ed25519 AAAA comment".to_string(),
            fingerprint: "SHA256:abc".to_string(),
        };
        let item = build_item_value(template, "my key", None, &payload);

        assert_eq!(item["type"], serde_json::json!(5));
        assert_eq!(item["name"], serde_json::json!("my key"));
        // The template's placeholder notes text must never survive into a real
        // item — `None` clears it rather than leaving "Some notes about this
        // item." sitting in the vault.
        assert_eq!(item["notes"], serde_json::Value::Null);
        assert_eq!(item["sshKey"]["privateKey"], serde_json::json!("PRIV"));
        assert_eq!(
            item["sshKey"]["publicKey"],
            serde_json::json!("ssh-ed25519 AAAA comment")
        );
        assert_eq!(item["sshKey"]["keyFingerprint"], serde_json::json!("SHA256:abc"));
        // Preserved unrelated field, cleared the stale login payload.
        assert_eq!(item["favorite"], serde_json::json!(false));
        assert_eq!(item["login"], serde_json::Value::Null);
    }

    #[test]
    fn build_item_value_carries_through_custom_notes() {
        let template = serde_json::json!({
            "type": 1,
            "name": "",
            "notes": "Some notes about this item.",
            "favorite": false,
            "sshKey": null,
        });
        let payload = SshKeyPayload {
            private_key: "PRIV".to_string(),
            public_key: "ssh-ed25519 AAAA comment".to_string(),
            fingerprint: "SHA256:abc".to_string(),
        };
        let item = build_item_value(template, "my key", Some("used for prod servers"), &payload);
        assert_eq!(item["notes"], serde_json::json!("used for prod servers"));
    }

    #[test]
    fn comment_falls_back_to_embedded_when_no_pub() {
        let tmp = tempdir();
        let dir = tmp.path();

        let mut key = gen_ed25519();
        key.set_comment("embedded@comment");
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        write(dir, "id_nopub", &pem);

        let found = scan_dir(dir).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].comment, "embedded@comment");
    }

    // Minimal temp-dir helper so we don't need an extra dev-dependency.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut base = std::env::temp_dir();
        let unique = format!(
            "bw-ssh-import-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        base.push(unique);
        std::fs::create_dir_all(&base).unwrap();
        TempDir(base)
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
