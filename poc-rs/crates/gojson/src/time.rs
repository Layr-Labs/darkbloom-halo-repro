//! Go `time.Time` JSON encoding (RFC 3339 with nanoseconds).

use chrono::{DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A point in time with a fixed UTC offset, encoded like Go's `time.Time`
/// (`2006-01-02T15:04:05.999999999Z07:00`). The default value is Go's zero
/// time (`0001-01-01T00:00:00Z`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoTime(DateTime<FixedOffset>);

/// A time string that is not valid RFC 3339.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError(pub String);

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid time: {}", self.0)
    }
}

impl std::error::Error for TimeError {}

fn utc_offset() -> FixedOffset {
    // Offset 0 is always in range.
    FixedOffset::east_opt(0).unwrap_or_else(|| Utc.fix())
}

impl Default for GoTime {
    fn default() -> Self {
        Self::zero()
    }
}

impl GoTime {
    /// Go's zero time, `0001-01-01T00:00:00Z`.
    pub fn zero() -> Self {
        let d = NaiveDate::from_ymd_opt(1, 1, 1).unwrap_or(NaiveDate::MIN);
        Self(utc_offset().from_utc_datetime(&d.and_time(NaiveTime::MIN)))
    }

    /// The current time in UTC (Go's `time.Now().UTC()`).
    pub fn now_utc() -> Self {
        Self(Utc::now().fixed_offset())
    }

    /// Wraps a chrono time.
    pub fn from_datetime(t: DateTime<FixedOffset>) -> Self {
        Self(t)
    }

    /// From a UTC chrono time.
    pub fn from_utc(t: DateTime<Utc>) -> Self {
        Self(t.fixed_offset())
    }

    /// The inner chrono value.
    pub fn datetime(&self) -> DateTime<FixedOffset> {
        self.0
    }

    /// Whether this is Go's zero time.
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    /// Truncates to whole seconds (Go's `Truncate(time.Second)`).
    pub fn truncate_secs(&self) -> Self {
        Self(self.0.with_nanosecond(0).unwrap_or(self.0))
    }

    /// The same instant in UTC.
    pub fn to_utc(&self) -> Self {
        Self(self.0.with_timezone(&utc_offset()))
    }

    /// Adds a duration (saturating at the representable range).
    pub fn add(&self, d: Duration) -> Self {
        Self(self.0.checked_add_signed(d).unwrap_or(self.0))
    }

    /// Nanoseconds since the Unix epoch (Go's `UnixNano`; undefined outside
    /// roughly 1678..2262 in Go, saturating here).
    pub fn unix_nano(&self) -> i64 {
        self.0.timestamp_nanos_opt().unwrap_or(if self.0.timestamp() < 0 { i64::MIN } else { i64::MAX })
    }

    /// Whether `self` is strictly after `other` (instant comparison).
    pub fn after(&self, other: &GoTime) -> bool {
        self.0 > other.0
    }

    /// Whether `self` is strictly before `other` (instant comparison).
    pub fn before(&self, other: &GoTime) -> bool {
        self.0 < other.0
    }

    /// RFC 3339 with seconds only (Go's `time.RFC3339` layout).
    pub fn rfc3339(&self) -> String {
        let mut s = self.base();
        s.push_str(&self.zone());
        s
    }

    fn base(&self) -> String {
        let t = self.0;
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second().min(59))
    }

    fn zone(&self) -> String {
        let off = self.0.offset().local_minus_utc();
        if off == 0 {
            return "Z".to_owned();
        }
        let sign = if off < 0 { '-' } else { '+' };
        let abs = off.unsigned_abs();
        format!("{sign}{:02}:{:02}", abs / 3600, (abs / 60) % 60)
    }

    /// Go's `RFC3339Nano` rendering (as used by `MarshalJSON`).
    pub fn to_go_string(&self) -> Result<String, TimeError> {
        let year = self.0.year();
        if !(0..=9999).contains(&year) {
            return Err(TimeError(format!("year {year} outside of range [0,9999]")));
        }
        let mut s = self.base();
        let ns = self.0.nanosecond() % 1_000_000_000;
        if ns != 0 {
            let frac = format!("{ns:09}");
            s.push('.');
            s.push_str(frac.trim_end_matches('0'));
        }
        s.push_str(&self.zone());
        Ok(s)
    }

    /// Parses RFC 3339 as Go's `time.Time.UnmarshalJSON` does (strictly:
    /// `YYYY-MM-DDTHH:MM:SS[.fraction]` then `Z` or `±HH:MM`).
    pub fn parse(s: &str) -> Result<Self, TimeError> {
        let bad = || TimeError(s.chars().take(64).collect());
        let b = s.as_bytes();
        let num = |range: std::ops::Range<usize>| -> Result<u32, TimeError> {
            let part = b.get(range).ok_or_else(bad)?;
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
            part.iter().try_fold(0u32, |acc, d| acc.checked_mul(10)?.checked_add(u32::from(d - b'0'))).ok_or_else(bad)
        };
        let sep = |i: usize, c: u8| -> Result<(), TimeError> { if b.get(i) == Some(&c) { Ok(()) } else { Err(bad()) } };
        let year = num(0..4)?;
        sep(4, b'-')?;
        let month = num(5..7)?;
        sep(7, b'-')?;
        let day = num(8..10)?;
        sep(10, b'T')?;
        let hour = num(11..13)?;
        sep(13, b':')?;
        let minute = num(14..16)?;
        sep(16, b':')?;
        let second = num(17..19)?;
        let mut i = 19;
        let mut nanos = 0u32;
        if b.get(i) == Some(&b'.') || b.get(i) == Some(&b',') {
            i += 1;
            let start = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            let digits = i - start;
            if digits == 0 || digits > 9 {
                return Err(bad());
            }
            nanos = num(start..i)? * 10u32.pow(u32::try_from(9 - digits).map_err(|_| bad())?);
        }
        let offset_secs: i32 = match b.get(i) {
            Some(b'Z') if b.len() == i + 1 => 0,
            Some(&c @ (b'+' | b'-')) if b.len() == i + 6 => {
                sep(i + 3, b':')?;
                let hh = num(i + 1..i + 3)?;
                let mm = num(i + 4..i + 6)?;
                if hh > 23 || mm > 59 {
                    return Err(bad());
                }
                let v = i32::try_from(hh * 3600 + mm * 60).map_err(|_| bad())?;
                if c == b'-' { -v } else { v }
            }
            _ => return Err(bad()),
        };
        if hour > 23 || minute > 59 || second > 59 {
            return Err(bad());
        }
        let date = NaiveDate::from_ymd_opt(i32::try_from(year).map_err(|_| bad())?, month, day).ok_or_else(bad)?;
        let time = NaiveTime::from_hms_nano_opt(hour, minute, second, nanos).ok_or_else(bad)?;
        let off = FixedOffset::east_opt(offset_secs).ok_or_else(bad)?;
        let local = NaiveDateTime::new(date, time);
        let dt = off.from_local_datetime(&local).single().ok_or_else(bad)?;
        Ok(Self(dt))
    }
}

impl fmt::Debug for GoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_go_string() {
            Ok(s) => write!(f, "GoTime({s})"),
            Err(_) => write!(f, "GoTime({:?})", self.0),
        }
    }
}

impl fmt::Display for GoTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_go_string() {
            Ok(s) => f.write_str(&s),
            Err(_) => write!(f, "{}", self.0),
        }
    }
}

impl Serialize for GoTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let v = self.to_go_string().map_err(serde::ser::Error::custom)?;
        s.serialize_str(&v)
    }
}

impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Go treats JSON null as "leave the zero value".
        let s: Option<std::borrow::Cow<'de, str>> = Option::deserialize(d)?;
        match s {
            None => Ok(GoTime::zero()),
            Some(s) => GoTime::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn go_format_round_trip() {
        for s in [
            "2026-11-02T15:04:05Z",
            "2026-11-02T15:04:05.1Z",
            "2026-11-02T15:04:05.123456789Z",
            "2026-11-02T15:04:05.12345-08:00",
            "0001-01-01T00:00:00Z",
            "2026-11-02T23:59:59+05:30",
        ] {
            let t = GoTime::parse(s).unwrap();
            assert_eq!(t.to_go_string().unwrap(), s);
        }
        assert_eq!(GoTime::zero().to_go_string().unwrap(), "0001-01-01T00:00:00Z");
        let t = GoTime::parse("2026-11-02T15:04:05.120000000Z").unwrap();
        assert_eq!(t.to_go_string().unwrap(), "2026-11-02T15:04:05.12Z");
        assert_eq!(GoTime::parse("2026-11-02T15:04:05+00:00").unwrap().to_go_string().unwrap(), "2026-11-02T15:04:05Z");
    }

    #[test]
    fn rejects_bad_times() {
        for s in [
            "",
            "2026-11-02",
            "2026-11-02 15:04:05Z",
            "2026-13-02T15:04:05Z",
            "2026-02-30T15:04:05Z",
            "2026-11-02T24:00:00Z",
            "2026-11-02T15:04:60Z",
            "2026-11-02T15:04:05.Z",
            "2026-11-02T15:04:05.1234567890Z",
            "2026-11-02T15:04:05+0800",
            "2026-11-02T15:04:05z",
            "2026-11-02T15:04:05Zjunk",
            "+026-11-02T15:04:05Z",
        ] {
            assert!(GoTime::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn unix_nano() {
        let t = GoTime::parse("1970-01-01T00:00:01.5Z").unwrap();
        assert_eq!(t.unix_nano(), 1_500_000_000);
    }
}
