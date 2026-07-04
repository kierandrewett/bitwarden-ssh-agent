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

use anyhow::{Context, Result};
use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroize;

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

/// Try to interpret a single file as an OpenSSH private key. Returns `Ok(None)`
/// if the file simply is not a private key (so the caller skips it), and only
/// errors on an unexpected I/O problem worth logging.
fn analyze_file(path: &Path) -> Result<Option<Candidate>> {
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

/// Entry point for `bitwarden-ssh-agent import`.
pub async fn run(
    ssh_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let _ = (config, dry_run);
    println!("bitwarden-ssh-agent import");
    println!("==========================\n");

    let dir = resolve_ssh_dir(ssh_dir)?;
    println!("Scanning {} for SSH private keys...", dir.display());
    let candidates = scan_dir(&dir)?;

    if candidates.is_empty() {
        println!("No SSH private keys found in {}.", dir.display());
        return Ok(());
    }

    println!("Found {} candidate key(s):", candidates.len());
    for c in &candidates {
        println!(
            "  {}  [{}]  {}  {}{}",
            c.path.display(),
            c.algo_label(),
            c.fingerprint,
            c.comment,
            if c.encrypted { "  (passphrase-protected)" } else { "" },
        );
    }

    // Scrub the raw private-key material we read off disk.
    let mut candidates = candidates;
    for c in &mut candidates {
        c.private_pem.zeroize();
    }

    anyhow::bail!("wizard not yet implemented")
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
