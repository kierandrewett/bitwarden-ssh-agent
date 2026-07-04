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

use std::path::PathBuf;

use anyhow::Result;

/// Entry point for `bitwarden-ssh-agent import`.
pub async fn run(
    ssh_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let _ = (ssh_dir, config, dry_run);
    println!("bitwarden-ssh-agent import");
    println!("==========================\n");
    anyhow::bail!("not yet implemented")
}
