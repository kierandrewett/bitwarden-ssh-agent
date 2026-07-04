//! Shared terminal-presentation helpers used by the interactive subcommands
//! (`setup` and `import`) so both wizards share one visual language: colored
//! step banners, green success marks, and spinners around silent operations.
//!
//! Everything here is TTY-gated: when stdout is not a terminal (piped, logged),
//! color is dropped and spinners hide themselves, so output stays clean.

use std::io::IsTerminal;

/// Whether stdout is a terminal, so ANSI color is worth emitting.
pub fn color_enabled() -> bool {
    std::io::stdout().is_terminal()
}

/// Wrap `s` in bold cyan when writing to a terminal, else return it plain.
pub fn bold_cyan(s: &str) -> String {
    if color_enabled() {
        format!("\x1b[1;36m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// A green check mark (falls back to a plain "✓" when not a terminal, which
/// stays legible when piped).
pub fn ok_mark() -> &'static str {
    if color_enabled() {
        "\x1b[32m✓\x1b[0m"
    } else {
        "✓"
    }
}

/// Print a colored, progress-numbered step banner so the user can follow along
/// (`Step n/total: title`).
pub fn step_banner(n: u8, total: u8, title: &str) {
    println!();
    println!("{}", bold_cyan(&format!("Step {n}/{total}: {title}")));
}

/// Print a final completion banner (unnumbered; the wizard's work is done).
pub fn done_banner(title: &str) {
    println!();
    println!("{}", bold_cyan(&format!("Done: {title}")));
}

/// Run an async operation while showing a steady spinner, clearing it on
/// completion so the caller can print its own success/failure line. The spinner
/// hides itself automatically when stdout/stderr is not a terminal.
pub async fn with_spinner<F, T>(message: &str, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let pb = indicatif::ProgressBar::new_spinner();
    if let Ok(style) = indicatif::ProgressStyle::with_template("{spinner:.cyan} {msg}") {
        pb.set_style(style);
    }
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(90));
    let out = fut.await;
    pb.finish_and_clear();
    out
}
