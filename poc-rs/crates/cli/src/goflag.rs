//! Command-line flags with Go's `flag` package syntax, so the Rust tools are
//! drop-in replacements in the PoC scripts: `-name value`, `-name=value`,
//! `--name value`, boolean `-name` / `-name=false`, parsing stops at the
//! first non-flag argument or after `--`, `-h`/`-help` prints usage.

use std::fmt::Write as _;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Bool(bool),
    Int(i64),
    Uint(u64),
    Duration(Duration),
    Multi(Vec<String>),
}

#[derive(Debug, Clone)]
struct Def {
    name: &'static str,
    usage: &'static str,
    default: Value,
    value: Value,
}

/// A set of flags for one command.
#[derive(Debug, Clone)]
pub struct FlagSet {
    name: String,
    defs: Vec<Def>,
    args: Vec<String>,
}

/// A parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagError {
    /// `-h` or `-help` was given.
    Help,
    /// Any other problem (Go's message).
    Invalid(String),
}

impl std::fmt::Display for FlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Help => f.write_str("flag: help requested"),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for FlagError {}

/// Parses a Go duration string ("20s", "1m30s", "500ms", "1.5h").
pub fn parse_duration(s: &str) -> Option<Duration> {
    if s == "0" {
        return Some(Duration::ZERO);
    }
    let mut rest = s;
    let mut total = 0f64;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let num_len = rest.bytes().take_while(|b| b.is_ascii_digit() || *b == b'.').count();
        if num_len == 0 {
            return None;
        }
        let (num, tail) = rest.split_at(num_len);
        let n: f64 = num.parse().ok()?;
        let unit_len = tail.bytes().take_while(|b| !b.is_ascii_digit() && *b != b'.').count();
        let (unit, tail) = tail.split_at(unit_len);
        let scale = match unit {
            "ns" => 1e-9,
            "us" | "µs" | "μs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        total += n * scale;
        rest = tail;
    }
    Duration::try_from_secs_f64(total).ok()
}

/// Formats a duration like Go's `time.Duration.String()` for values
/// rounded to milliseconds ("21.6s", "4m22.123s", "350ms").
pub fn format_duration(d: Duration) -> String {
    db_gojson::duration_ms_string(d)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

impl FlagSet {
    /// An empty flag set for command `name`.
    pub fn new(name: &str) -> Self {
        Self { name: name.to_owned(), defs: Vec::new(), args: Vec::new() }
    }

    fn add(&mut self, name: &'static str, default: Value, usage: &'static str) -> &mut Self {
        self.defs.push(Def { name, usage, default: default.clone(), value: default });
        self
    }

    /// A string flag.
    pub fn string(&mut self, name: &'static str, default: &str, usage: &'static str) -> &mut Self {
        self.add(name, Value::Str(default.to_owned()), usage)
    }

    /// A boolean flag.
    pub fn boolean(&mut self, name: &'static str, default: bool, usage: &'static str) -> &mut Self {
        self.add(name, Value::Bool(default), usage)
    }

    /// An integer flag.
    pub fn int(&mut self, name: &'static str, default: i64, usage: &'static str) -> &mut Self {
        self.add(name, Value::Int(default), usage)
    }

    /// An unsigned integer flag.
    pub fn uint(&mut self, name: &'static str, default: u64, usage: &'static str) -> &mut Self {
        self.add(name, Value::Uint(default), usage)
    }

    /// A duration flag (Go syntax).
    pub fn duration(&mut self, name: &'static str, default: Duration, usage: &'static str) -> &mut Self {
        self.add(name, Value::Duration(default), usage)
    }

    /// A repeatable string flag.
    pub fn multi(&mut self, name: &'static str, usage: &'static str) -> &mut Self {
        self.add(name, Value::Multi(Vec::new()), usage)
    }

    fn find(&self, name: &str) -> Option<&Def> {
        self.defs.iter().find(|d| d.name == name)
    }

    /// Parses `args` (without the program/command name).
    pub fn parse(&mut self, args: &[String]) -> Result<(), FlagError> {
        let mut i = 0;
        while let Some(s) = args.get(i) {
            if s.len() < 2 || !s.starts_with('-') {
                break;
            }
            let mut name = s.get(1..).unwrap_or_default();
            if let Some(n) = name.strip_prefix('-') {
                if n.is_empty() {
                    i += 1; // "--" terminates the flags
                    break;
                }
                name = n;
            }
            if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
                return Err(FlagError::Invalid(format!("bad flag syntax: {s}")));
            }
            i += 1;
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (name, None),
            };
            let Some(pos) = self.defs.iter().position(|d| d.name == name) else {
                if name == "help" || name == "h" {
                    return Err(FlagError::Help);
                }
                return Err(FlagError::Invalid(format!("flag provided but not defined: -{name}")));
            };
            let is_bool = matches!(self.defs.get(pos).map(|d| &d.value), Some(Value::Bool(_)));
            let value = if is_bool {
                match inline {
                    Some(v) => Some(v),
                    None => Some("true".to_owned()),
                }
            } else {
                match inline {
                    Some(v) => Some(v),
                    None => {
                        let v = args.get(i).cloned();
                        if v.is_some() {
                            i += 1;
                        }
                        v
                    }
                }
            };
            let Some(value) = value else {
                return Err(FlagError::Invalid(format!("flag needs an argument: -{name}")));
            };
            let Some(def) = self.defs.get_mut(pos) else { continue };
            let bad = |what: &str| FlagError::Invalid(format!("invalid value {value:?} for flag -{name}: {what}"));
            def.value = match &mut def.value {
                Value::Str(_) => Value::Str(value.clone()),
                Value::Bool(_) => Value::Bool(
                    parse_bool(&value)
                        .ok_or_else(|| FlagError::Invalid(format!("invalid boolean value {value:?} for -{name}: parse error")))?,
                ),
                Value::Int(_) => Value::Int(value.parse().map_err(|_| bad("parse error"))?),
                Value::Uint(_) => Value::Uint(value.parse().map_err(|_| bad("parse error"))?),
                Value::Duration(_) => Value::Duration(parse_duration(&value).ok_or_else(|| bad("invalid duration"))?),
                Value::Multi(v) => {
                    let mut v = std::mem::take(v);
                    v.push(value.clone());
                    Value::Multi(v)
                }
            };
        }
        self.args = args.get(i..).unwrap_or_default().to_vec();
        Ok(())
    }

    /// Parses `args`; prints usage and exits like Go's `flag.ExitOnError`.
    pub fn parse_or_exit(&mut self, args: &[String]) {
        match self.parse(args) {
            Ok(()) => {}
            Err(FlagError::Help) => {
                eprint!("{}", self.usage());
                std::process::exit(0);
            }
            Err(FlagError::Invalid(m)) => {
                eprintln!("{m}");
                eprint!("{}", self.usage());
                std::process::exit(2);
            }
        }
    }

    /// A string flag's value.
    pub fn str(&self, name: &str) -> String {
        match self.find(name).map(|d| &d.value) {
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        }
    }

    /// A boolean flag's value.
    pub fn bool(&self, name: &str) -> bool {
        matches!(self.find(name).map(|d| &d.value), Some(Value::Bool(true)))
    }

    /// An integer flag's value.
    pub fn int_value(&self, name: &str) -> i64 {
        match self.find(name).map(|d| &d.value) {
            Some(Value::Int(v)) => *v,
            _ => 0,
        }
    }

    /// An unsigned flag's value.
    pub fn uint_value(&self, name: &str) -> u64 {
        match self.find(name).map(|d| &d.value) {
            Some(Value::Uint(v)) => *v,
            _ => 0,
        }
    }

    /// A duration flag's value.
    pub fn duration_value(&self, name: &str) -> Duration {
        match self.find(name).map(|d| &d.value) {
            Some(Value::Duration(v)) => *v,
            _ => Duration::ZERO,
        }
    }

    /// A repeatable flag's values.
    pub fn multi_values(&self, name: &str) -> Vec<String> {
        match self.find(name).map(|d| &d.value) {
            Some(Value::Multi(v)) => v.clone(),
            _ => Vec::new(),
        }
    }

    /// Positional arguments after the flags.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Usage text in Go's format.
    pub fn usage(&self) -> String {
        let mut out = format!("Usage of {}:\n", self.name);
        let mut defs: Vec<&Def> = self.defs.iter().collect();
        defs.sort_by_key(|d| d.name);
        for d in defs {
            let (kind, default) = match &d.default {
                Value::Str(s) => (" string", if s.is_empty() { String::new() } else { format!(" (default {s:?})") }),
                Value::Bool(b) => ("", if *b { " (default true)".to_owned() } else { String::new() }),
                Value::Int(v) => (" int", if *v == 0 { String::new() } else { format!(" (default {v})") }),
                Value::Uint(v) => (" uint", if *v == 0 { String::new() } else { format!(" (default {v})") }),
                Value::Duration(v) => {
                    (" duration", if v.is_zero() { String::new() } else { format!(" (default {})", format_duration(*v)) })
                }
                Value::Multi(_) => (" value", String::new()),
            };
            let _ = writeln!(out, "  -{}{kind}\n    \t{}{default}", d.name, d.usage);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn set() -> FlagSet {
        let mut fs = FlagSet::new("t");
        fs.string("name", "def", "a name")
            .boolean("live", false, "live")
            .int("n", 3, "count")
            .uint("svn", 1, "svn")
            .duration("challenge", Duration::from_secs(30), "interval")
            .multi("dev-root", "roots");
        fs
    }

    #[test]
    fn go_syntax() {
        let mut fs = set();
        fs.parse(&args(&[
            "-name",
            "x",
            "--live",
            "-n=7",
            "--svn",
            "9",
            "-challenge",
            "1m30s",
            "-dev-root",
            "a",
            "-dev-root=b",
            "image",
            "-name",
            "y",
        ]))
        .unwrap();
        assert_eq!(fs.str("name"), "x");
        assert!(fs.bool("live"));
        assert_eq!(fs.int_value("n"), 7);
        assert_eq!(fs.uint_value("svn"), 9);
        assert_eq!(fs.duration_value("challenge"), Duration::from_secs(90));
        assert_eq!(fs.multi_values("dev-root"), vec!["a", "b"]);
        assert_eq!(fs.args(), &args(&["image", "-name", "y"])[..]);
    }

    #[test]
    fn errors_and_terminator() {
        assert_eq!(set().parse(&args(&["-h"])), Err(FlagError::Help));
        assert!(matches!(set().parse(&args(&["-nope"])), Err(FlagError::Invalid(_))));
        assert!(matches!(set().parse(&args(&["-n", "x"])), Err(FlagError::Invalid(_))));
        assert!(matches!(set().parse(&args(&["-name"])), Err(FlagError::Invalid(_))));
        assert!(matches!(set().parse(&args(&["-live=maybe"])), Err(FlagError::Invalid(_))));
        let mut fs = set();
        fs.parse(&args(&["-live=false", "--", "-name"])).unwrap();
        assert!(!fs.bool("live"));
        assert_eq!(fs.args(), &args(&["-name"])[..]);
        assert_eq!(fs.str("name"), "def");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("20s"), Some(Duration::from_secs(20)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("1.5h"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_duration("10"), None);
        assert_eq!(parse_duration("x"), None);
        assert_eq!(format_duration(Duration::from_millis(21_600)), "21.6s");
        assert_eq!(format_duration(Duration::from_millis(262_123)), "4m22.123s");
        assert_eq!(format_duration(Duration::from_millis(350)), "350ms");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h0m0s");
    }
}
