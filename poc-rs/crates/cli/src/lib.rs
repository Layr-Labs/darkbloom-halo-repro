//! Shared helpers for the PoC command-line tools.

#![forbid(unsafe_code)]

pub mod goflag;

use std::path::{Path, PathBuf};

/// Prints `<tool>: <message>` to stderr and exits with status 1.
pub fn die(tool: &str, msg: impl std::fmt::Display) -> ! {
    eprintln!("{tool}: {msg}");
    std::process::exit(1)
}

/// Sorted files in `dir` whose names end with `suffix` (a tiny
/// `filepath.Glob(dir/*suffix)`).
pub fn glob_suffix(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(suffix)))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Arguments after the program name.
pub fn cli_args() -> Vec<String> {
    std::env::args().skip(1).collect()
}

/// Reads `/proc/cmdline` as the boot loader passed it (trailing newline
/// removed, invalid UTF-8 replaced like Go's []rune conversion).
pub fn proc_cmdline() -> std::io::Result<String> {
    let b = std::fs::read("/proc/cmdline")?;
    Ok(String::from_utf8_lossy(&b).trim_end_matches('\n').to_owned())
}

/// Resolves when SIGINT or SIGTERM arrives.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
