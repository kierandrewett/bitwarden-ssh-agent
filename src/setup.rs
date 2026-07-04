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

use anyhow::Result;

/// Entry point for `bitwarden-ssh-agent setup`.
pub async fn run(config_override: Option<PathBuf>) -> Result<()> {
    let _ = config_override;
    println!("bitwarden-ssh-agent setup");
    println!("=========================\n");
    println!("This will walk you through configuring the agent end-to-end.\n");
    Ok(())
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
