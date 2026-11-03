//! Go `encoding/json` compatibility for the Darkbloom AMD PoC.
//!
//! The Go reference implementation hashes and signs several JSON encodings
//! (release manifests are re-marshalled for their digest, workflow graphs
//! are hashed, receipts and statements are signed or quoted as produced).
//! This crate makes the Rust side produce *byte-identical* output to Go's
//! `json.Marshal` / `json.MarshalIndent`:
//!
//! * HTML-sensitive characters (`<`, `>`, `&`) and U+2028/U+2029 are escaped
//!   as `\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`;
//! * floats use Go's `strconv.AppendFloat(f, 'f'|'e', -1, 64)` rules;
//! * `[]byte` is standard, padded base64 (`null` decodes to empty);
//! * `time.Time` is RFC 3339 with nanoseconds, trailing zeros trimmed, `Z`
//!   for UTC and `±hh:mm` otherwise ([`GoTime`]).
//!
//! Struct field order follows declaration order (as in Go), and maps must
//! be `BTreeMap`s so keys are sorted (as Go sorts map keys).

#![forbid(unsafe_code)]

mod time;

pub use crate::time::{GoTime, TimeError};

use serde::Serialize;
use serde_json::ser::{CharEscape, CompactFormatter, Formatter, PrettyFormatter};
use std::io;

/// Errors from encoding or decoding.
pub type Error = serde_json::Error;

/// Encodes `value` exactly like Go's `json.Marshal`.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(256);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter::new(CompactFormatter));
    value.serialize(&mut ser)?;
    Ok(out)
}

/// Encodes `value` exactly like Go's `json.MarshalIndent(v, "", "  ")`.
pub fn to_vec_indent<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(1024);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter::new(PrettyFormatter::with_indent(b"  ")));
    value.serialize(&mut ser)?;
    Ok(out)
}

/// Encodes like Go's `json.NewEncoder(w).Encode(v)`: compact plus a newline.
pub fn to_vec_line<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = to_vec(value)?;
    out.push(b'\n');
    Ok(out)
}

/// Decodes JSON. Unknown fields are rejected only for types annotated with
/// `#[serde(deny_unknown_fields)]` (the Go code uses `DisallowUnknownFields`
/// for those); trailing data is always rejected.
pub fn from_slice<'a, T: serde::Deserialize<'a>>(data: &'a [u8]) -> Result<T, Error> {
    serde_json::from_slice(data)
}

/// Formats a float64 as Go's encoding/json does.
pub fn format_f64(f: f64) -> String {
    if !f.is_finite() {
        // Go refuses to encode NaN/Inf; serde_json writes null. None of the
        // PoC's values can be non-finite (they are ratios of validated ints).
        return "null".to_owned();
    }
    let abs = f.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let s = format!("{f:e}");
        // Rust: "1e21", "1.5e-7"; Go: "1e+21", "1.5e-07" cleaned to "1.5e-7".
        match s.split_once('e') {
            Some((mant, exp)) if !exp.starts_with('-') => format!("{mant}e+{exp}"),
            _ => s,
        }
    } else {
        // Rust's Display prints the shortest round-trip digits without an
        // exponent, which is Go's 'f' format with precision -1.
        format!("{f}")
    }
}

/// Go's `d.Round(time.Millisecond).String()` for a non-negative duration:
/// "0s", "512ms", "23.497s", "1m1.5s", "1h0m0s" (halves round up).
pub fn duration_ms_string(d: std::time::Duration) -> String {
    let ms = d.as_nanos().saturating_add(500_000) / 1_000_000;
    if ms == 0 {
        return "0s".to_owned();
    }
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let (secs, frac) = (ms / 1000, ms % 1000);
    let (h, m, sec) = (secs / 3600, (secs / 60) % 60, secs % 60);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h{m}m"));
    } else if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    out.push_str(&sec.to_string());
    if frac > 0 {
        out.push('.');
        out.push_str(format!("{frac:03}").trim_end_matches('0'));
    }
    out.push('s');
    out
}

/// A serde_json formatter producing Go's encoding/json byte layout.
#[derive(Debug, Clone)]
pub struct GoFormatter<F> {
    inner: F,
}

impl<F> GoFormatter<F> {
    /// Wraps a compact or pretty formatter.
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: Formatter> Formatter for GoFormatter<F> {
    fn write_null<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.write_null(w)
    }
    fn write_bool<W: ?Sized + io::Write>(&mut self, w: &mut W, value: bool) -> io::Result<()> {
        self.inner.write_bool(w, value)
    }
    fn write_i8<W: ?Sized + io::Write>(&mut self, w: &mut W, v: i8) -> io::Result<()> {
        self.inner.write_i8(w, v)
    }
    fn write_i16<W: ?Sized + io::Write>(&mut self, w: &mut W, v: i16) -> io::Result<()> {
        self.inner.write_i16(w, v)
    }
    fn write_i32<W: ?Sized + io::Write>(&mut self, w: &mut W, v: i32) -> io::Result<()> {
        self.inner.write_i32(w, v)
    }
    fn write_i64<W: ?Sized + io::Write>(&mut self, w: &mut W, v: i64) -> io::Result<()> {
        self.inner.write_i64(w, v)
    }
    fn write_i128<W: ?Sized + io::Write>(&mut self, w: &mut W, v: i128) -> io::Result<()> {
        self.inner.write_i128(w, v)
    }
    fn write_u8<W: ?Sized + io::Write>(&mut self, w: &mut W, v: u8) -> io::Result<()> {
        self.inner.write_u8(w, v)
    }
    fn write_u16<W: ?Sized + io::Write>(&mut self, w: &mut W, v: u16) -> io::Result<()> {
        self.inner.write_u16(w, v)
    }
    fn write_u32<W: ?Sized + io::Write>(&mut self, w: &mut W, v: u32) -> io::Result<()> {
        self.inner.write_u32(w, v)
    }
    fn write_u64<W: ?Sized + io::Write>(&mut self, w: &mut W, v: u64) -> io::Result<()> {
        self.inner.write_u64(w, v)
    }
    fn write_u128<W: ?Sized + io::Write>(&mut self, w: &mut W, v: u128) -> io::Result<()> {
        self.inner.write_u128(w, v)
    }
    fn write_f32<W: ?Sized + io::Write>(&mut self, w: &mut W, v: f32) -> io::Result<()> {
        // Go formats float32 with 32-bit shortest digits; Display on f32 does too.
        if !v.is_finite() {
            return w.write_all(b"null");
        }
        let abs = v.abs();
        let s = if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
            let s = format!("{v:e}");
            match s.split_once('e') {
                Some((mant, exp)) if !exp.starts_with('-') => format!("{mant}e+{exp}"),
                _ => s,
            }
        } else {
            format!("{v}")
        };
        w.write_all(s.as_bytes())
    }
    fn write_f64<W: ?Sized + io::Write>(&mut self, w: &mut W, v: f64) -> io::Result<()> {
        w.write_all(format_f64(v).as_bytes())
    }
    fn write_number_str<W: ?Sized + io::Write>(&mut self, w: &mut W, v: &str) -> io::Result<()> {
        self.inner.write_number_str(w, v)
    }
    fn begin_string<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.begin_string(w)
    }
    fn end_string<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_string(w)
    }
    fn write_string_fragment<W: ?Sized + io::Write>(&mut self, w: &mut W, fragment: &str) -> io::Result<()> {
        // serde_json already escapes '"', '\\' and control characters exactly
        // like Go >= 1.22 (\b \f \n \r \t and \u00XX). Go additionally
        // escapes HTML-sensitive characters and the JS line separators.
        let mut start = 0;
        for (i, ch) in fragment.char_indices() {
            let esc: &[u8] = match ch {
                '<' => b"\\u003c",
                '>' => b"\\u003e",
                '&' => b"\\u0026",
                '\u{2028}' => b"\\u2028",
                '\u{2029}' => b"\\u2029",
                _ => continue,
            };
            w.write_all(fragment.get(start..i).unwrap_or_default().as_bytes())?;
            w.write_all(esc)?;
            start = i + ch.len_utf8();
        }
        w.write_all(fragment.get(start..).unwrap_or_default().as_bytes())
    }
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, w: &mut W, e: CharEscape) -> io::Result<()> {
        self.inner.write_char_escape(w, e)
    }
    fn write_byte_array<W: ?Sized + io::Write>(&mut self, w: &mut W, v: &[u8]) -> io::Result<()> {
        self.inner.write_byte_array(w, v)
    }
    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.begin_array(w)
    }
    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_array(w)
    }
    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        self.inner.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_array_value(w)
    }
    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.begin_object(w)
    }
    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_object(w)
    }
    fn begin_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        self.inner.begin_object_key(w, first)
    }
    fn end_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_object_key(w)
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.begin_object_value(w)
    }
    fn end_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.inner.end_object_value(w)
    }
    fn write_raw_fragment<W: ?Sized + io::Write>(&mut self, w: &mut W, fragment: &str) -> io::Result<()> {
        self.inner.write_raw_fragment(w, fragment)
    }
}

/// `#[serde(with = "db_gojson::b64")]` for Go `[]byte` fields: standard
/// padded base64; `null` decodes to an empty vector (Go's nil slice).
pub mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes bytes as a base64 string.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    /// Deserializes a base64 string (or `null`).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: Option<std::borrow::Cow<'de, str>> = Option::deserialize(d)?;
        match s {
            None => Ok(Vec::new()),
            Some(s) => STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom),
        }
    }
}

/// Like [`b64`] but serializes an empty value as `null` (a Go nil `[]byte`).
pub mod b64_nil {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserializer, Serializer};

    /// Serializes bytes as base64, or `null` when empty.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if v.is_empty() { s.serialize_none() } else { s.serialize_str(&STANDARD.encode(v)) }
    }

    /// Deserializes a base64 string (or `null`).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::b64::deserialize(d)
    }
}

/// `#[serde(with = "db_gojson::b64_zeroizing")]` for secret `[]byte` fields.
pub mod b64_zeroizing {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    /// Serializes secret bytes as base64.
    pub fn serialize<S: Serializer>(v: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let enc = Zeroizing::new(STANDARD.encode(v.as_slice()));
        s.serialize_str(&enc)
    }

    /// Deserializes secret bytes from base64 (or `null`).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let s: Option<Zeroizing<String>> = Option::deserialize(d)?.map(Zeroizing::new);
        match s {
            None => Ok(Zeroizing::new(Vec::new())),
            Some(s) => STANDARD.decode(s.as_bytes()).map(Zeroizing::new).map_err(serde::de::Error::custom),
        }
    }
}

/// `#[serde(with = "db_gojson::b64_list")]` for Go `[][]byte` fields.
/// Empty serializes as `null` (Go nil slice); `null` decodes to empty.
pub mod b64_list {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes a list of byte strings.
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        if v.is_empty() {
            return s.serialize_none();
        }
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&STANDARD.encode(b))?;
        }
        seq.end()
    }

    /// Deserializes a list of base64 strings (elements may be `null`).
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v: Option<Vec<Option<String>>> = Option::deserialize(d)?;
        v.unwrap_or_default()
            .into_iter()
            .map(|s| match s {
                None => Ok(Vec::new()),
                Some(s) => STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom),
            })
            .collect()
    }
}

/// `#[serde(with = "db_gojson::nil_vec")]` for Go slices that are nil when
/// empty: an empty vector serializes as `null`, and `null` decodes to empty.
pub mod nil_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes `null` for an empty vector.
    pub fn serialize<S: Serializer, T: Serialize>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        if v.is_empty() { s.serialize_none() } else { v.serialize(s) }
    }

    /// Accepts `null` or an array.
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
        Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
    }
}

/// `#[serde(deserialize_with = "db_gojson::null_default")]`: Go decodes JSON
/// `null` into a zero value; this does the same for any `Default` type.
pub fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    use serde::Deserialize as _;
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// `omitempty` predicate for integers.
pub fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
/// `omitempty` predicate for unsigned integers.
pub fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
/// `omitempty` predicate for unsigned 32-bit integers.
pub fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
/// `omitempty` predicate for floats.
pub fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
/// `omitempty` predicate for booleans.
pub fn is_false(v: &bool) -> bool {
    !*v
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[test]
    fn durations_format_like_go() {
        use std::time::Duration as D;
        for (d, want) in [
            (D::ZERO, "0s"),
            (D::from_micros(499), "0s"),
            (D::from_micros(500), "1ms"),
            (D::from_millis(512), "512ms"),
            (D::from_secs(1), "1s"),
            (D::from_micros(23_497_100), "23.497s"),
            (D::from_micros(23_497_500), "23.498s"),
            (D::from_millis(23_400), "23.4s"),
            (D::from_millis(61_500), "1m1.5s"),
            (D::from_secs(3600), "1h0m0s"),
            (D::from_millis(3_723_004), "1h2m3.004s"),
        ] {
            assert_eq!(duration_ms_string(d), want, "{d:?}");
        }
    }

    #[test]
    fn escapes_like_go() {
        let s = "a<b>&c\u{2028}\u{2029}\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f}é中";
        let out = String::from_utf8(to_vec(&s).unwrap()).unwrap();
        assert_eq!(out, "\"a\\u003cb\\u003e\\u0026c\\u2028\\u2029\\\"\\\\\\n\\r\\t\\b\\f\\u0001\u{7f}é中\"");
    }

    #[test]
    fn floats_like_go() {
        for (f, want) in [
            (1.0, "1"),
            (0.0, "0"),
            (-0.0, "-0"),
            (1.048576, "1.048576"),
            (0.262144, "0.262144"),
            (2.0625, "2.0625"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1.5e300, "1.5e+300"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1.5e-10, "1.5e-10"),
            (123456789.125, "123456789.125"),
        ] {
            assert_eq!(format_f64(f), want, "{f}");
        }
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct S {
        #[serde(with = "b64")]
        a: Vec<u8>,
        #[serde(with = "b64_list")]
        l: Vec<Vec<u8>>,
        m: BTreeMap<String, String>,
        #[serde(with = "nil_vec")]
        n: Vec<i64>,
    }

    #[test]
    fn bytes_and_maps() {
        let mut m = BTreeMap::new();
        m.insert("z".to_owned(), "1".to_owned());
        m.insert("a".to_owned(), "2".to_owned());
        let v = S { a: vec![1, 2, 3, 250], l: vec![], m, n: vec![] };
        let out = String::from_utf8(to_vec(&v).unwrap()).unwrap();
        assert_eq!(out, r#"{"a":"AQID+g==","l":null,"m":{"a":"2","z":"1"},"n":null}"#);
        let back: S = from_slice(out.as_bytes()).unwrap();
        assert_eq!(back, v);
        let nulls: S = from_slice(br#"{"a":null,"l":["AQ==",null],"m":{},"n":[1]}"#).unwrap();
        assert_eq!(nulls.a, Vec::<u8>::new());
        assert_eq!(nulls.l, vec![vec![1], vec![]]);
        assert!(from_slice::<S>(br#"{"a":"AQID+g==","l":null,"m":{},"n":null} x"#).is_err());
    }

    #[test]
    fn indent_like_go() {
        #[derive(Serialize)]
        struct T {
            a: i64,
            b: Vec<i64>,
            c: BTreeMap<String, i64>,
            d: Vec<i64>,
        }
        let out = to_vec_indent(&T { a: 1, b: vec![1, 2], c: BTreeMap::new(), d: vec![] }).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\n  \"a\": 1,\n  \"b\": [\n    1,\n    2\n  ],\n  \"c\": {},\n  \"d\": []\n}");
    }
}
