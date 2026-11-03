//! A minimal logger in the style of Go's `log.New(os.Stderr, "prefix ",
//! log.LstdFlags|log.Lmsgprefix)`: `2026/11/02 16:14:11 prefix message`
//! (UTC). Cloneable and thread-safe; tests can capture lines.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::{Arc, Mutex};

type Sink = Arc<dyn Fn(&str) + Send + Sync>;

/// A prefixed line logger.
#[derive(Clone)]
pub struct Logger {
    prefix: Arc<str>,
    sink: Sink,
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger").field("prefix", &self.prefix).finish_non_exhaustive()
    }
}

impl Logger {
    /// Logs to standard error.
    pub fn stderr(prefix: &str) -> Self {
        Self { prefix: Arc::from(prefix), sink: Arc::new(|line: &str| eprintln!("{line}")) }
    }

    /// Logs to a custom sink (one call per line, without a trailing newline).
    pub fn with_sink(prefix: &str, sink: impl Fn(&str) + Send + Sync + 'static) -> Self {
        Self { prefix: Arc::from(prefix), sink: Arc::new(sink) }
    }

    /// Discards everything.
    pub fn discard() -> Self {
        Self { prefix: Arc::from(""), sink: Arc::new(|_| {}) }
    }

    /// A logger that keeps lines in memory (for tests).
    pub fn memory(prefix: &str) -> (Self, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let l2 = lines.clone();
        let logger = Self::with_sink(prefix, move |line| {
            if let Ok(mut v) = l2.lock() {
                v.push(line.to_owned());
            }
        });
        (logger, lines)
    }

    /// Writes one line.
    pub fn log(&self, msg: fmt::Arguments<'_>) {
        let now = chrono::Utc::now().format("%Y/%m/%d %H:%M:%S");
        (self.sink)(&format!("{now} {}{msg}", self.prefix));
    }
}

/// `logf!(logger, "format {}", args)` writes one line.
#[macro_export]
macro_rules! logf {
    ($logger:expr, $($arg:tt)*) => {
        $logger.log(format_args!($($arg)*))
    };
}
