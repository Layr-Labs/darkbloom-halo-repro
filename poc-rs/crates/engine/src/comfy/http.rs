//! The ComfyUI HTTP client: loopback only, plain HTTP, no proxy, no
//! redirects (a redirected POST would re-send the prompt elsewhere), 60 s
//! timeout and bounded responses (512 MiB GET, 8 MiB POST, as in Go).

use crate::EngineError;
use reqwest::StatusCode;
use std::fmt::Write as _;
use std::time::Duration;
use zeroize::Zeroizing;

const GET_LIMIT: usize = 512 << 20;
const POST_LIMIT: usize = 8 << 20;

/// A ComfyUI endpoint.
#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    base: String,
}

/// A failed POST: transport failure, or a non-200 status with its body.
pub(crate) enum PostError {
    Net(String),
    Status(StatusCode, Zeroizing<Vec<u8>>),
}

/// Formats an error with its causes (reqwest's Display omits them).
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        let _ = write!(s, ": {c}");
        cur = c.source();
    }
    s
}

impl Http {
    /// Accepts only `http://` URLs on 127.0.0.1, localhost or ::1.
    pub(crate) fn new(url: &str) -> Result<Self, EngineError> {
        let u = reqwest::Url::parse(url).map_err(|e| EngineError(format!("ComfyUI URL {url:?}: {e}")))?;
        let host = u.host_str().unwrap_or_default();
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            return Err(EngineError(format!("ComfyUI must be on loopback, not {}", host.trim_matches(['[', ']']))));
        }
        if u.scheme() != "http" || u.query().is_some() || u.fragment().is_some() {
            return Err(EngineError(format!("ComfyUI URL must be plain http://host:port, not {url:?}")));
        }
        // ComfyUI is plain HTTP on loopback; the TLS configuration (reqwest
        // is built with TLS support for the consumer client) trusts nothing.
        let no_tls = db_tls::client_config(&db_tls::Trust::Pinned(Vec::new())).map_err(|e| EngineError(e.to_string()))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_backend_preconfigured(no_tls)
            .build()
            .map_err(|e| EngineError(format!("HTTP client: {}", chain(&e))))?;
        Ok(Self { client, base: u.as_str().trim_end_matches('/').to_owned() })
    }

    /// Whether a GET of `path` answers 200 within `timeout` (body ignored).
    pub(crate) async fn probe(&self, path: &str, timeout: Duration) -> bool {
        match self.client.get(format!("{}{path}", self.base)).timeout(timeout).send().await {
            Ok(rsp) => rsp.status() == StatusCode::OK,
            Err(_) => false,
        }
    }

    /// GETs a path; any status but 200 is an error.
    pub(crate) async fn get(&self, path: &str) -> Result<Zeroizing<Vec<u8>>, EngineError> {
        let rsp =
            self.client.get(format!("{}{path}", self.base)).send().await.map_err(|e| EngineError(format!("GET {path}: {}", chain(&e))))?;
        let status = rsp.status();
        let body = read_limited(rsp, GET_LIMIT).await.map_err(|e| EngineError(format!("GET {path}: {e}")))?;
        if status != StatusCode::OK {
            return Err(EngineError(format!("GET {path}: {status}")));
        }
        Ok(body)
    }

    /// POSTs a JSON body (zeroized once sent).
    pub(crate) async fn post(&self, path: &str, body: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, PostError> {
        let rsp = self
            .client
            .post(format!("{}{path}", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes::Bytes::from_owner(body))
            .send()
            .await
            .map_err(|e| PostError::Net(chain(&e)))?;
        let status = rsp.status();
        let out = read_limited(rsp, POST_LIMIT).await.map_err(PostError::Net)?;
        if status != StatusCode::OK {
            return Err(PostError::Status(status, out));
        }
        Ok(out)
    }

    /// POSTs a small control message, ignoring the outcome (best effort).
    pub(crate) async fn post_quiet(&self, path: &str, body: &serde_json::Value) {
        if let Ok(b) = db_gojson::to_vec(body) {
            let _ = self.post(path, Zeroizing::new(b)).await;
        }
    }
}

/// Reads a body into a zeroizing buffer, refusing more than `limit` bytes.
/// Growth goes through fresh zeroizing buffers, so no stale copy remains.
async fn read_limited(mut rsp: reqwest::Response, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let hint = rsp.content_length().and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
    if hint > limit {
        return Err(format!("response of {hint} bytes exceeds the {limit} byte limit"));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(hint));
    while let Some(chunk) = rsp.chunk().await.map_err(|e| chain(&e))? {
        let need = buf.len() + chunk.len();
        if need > limit {
            return Err(format!("response exceeds the {limit} byte limit"));
        }
        if buf.capacity() < need {
            let mut bigger = Zeroizing::new(Vec::with_capacity(need.max(buf.capacity() * 2).min(limit)));
            bigger.extend_from_slice(&buf);
            buf = bigger;
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn escape(s: &str, keep: impl Fn(u8) -> bool, space_plus: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || keep(b) {
            out.push(char::from(b));
        } else if b == b' ' && space_plus {
            out.push('+');
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Go's `url.PathEscape`.
pub(crate) fn path_escape(s: &str) -> String {
    escape(s, |b| matches!(b, b'$' | b'&' | b'+' | b':' | b'=' | b'@'), false)
}

/// Go's `url.QueryEscape`.
pub(crate) fn query_escape(s: &str) -> String {
    escape(s, |_| false, true)
}

/// The `/view` path for an output file (Go's `url.Values.Encode` order).
pub(crate) fn view_path(filename: &str, subfolder: &str, kind: &str) -> String {
    format!("/view?filename={}&subfolder={}&type={}", query_escape(filename), query_escape(subfolder), query_escape(kind))
}

/// Shortens text to at most `n` bytes (on a character boundary) plus "…".
pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", s.get(..end).unwrap_or_default())
}

/// How Python's `json.dumps` (ComfyUI's encoder, `ensure_ascii=True`)
/// writes a string's contents.
fn python_json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
        }
    }
    out
}

/// Replaces request secrets (raw, Go/serde-escaped or Python-escaped)
/// with a placeholder. Secrets shorter than 4 bytes are left alone.
pub(crate) fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for s in secrets.iter().filter(|s| s.len() >= 4) {
        let mut forms = vec![(*s).to_owned(), python_json_escape(s)];
        if let Ok(q) = serde_json::to_string(s) {
            forms.push(q.trim_matches('"').to_owned());
        }
        // Go's encoding/json form (\u003c, \u003e, \u0026, \u2028, \u2029),
        // as the prompt appears in Go-encoded JSON.
        if let Ok(q) = db_gojson::to_vec(s) {
            forms.push(String::from_utf8_lossy(&q).trim_matches('"').to_owned());
        }
        for f in forms {
            if !f.is_empty() {
                out = out.replace(&f, "[redacted]");
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Every encoding a prompt can come back in is redacted: raw, Python's
    /// json.dumps (ComfyUI), serde_json, and Go's HTML-escaping encoder.
    #[test]
    fn redacts_every_json_form_of_the_prompt() {
        let prompt = "a <b> & \"c\" caf\u{e9} \u{2028}x";
        let forms = [
            prompt.to_owned(),
            python_json_escape(prompt),
            serde_json::to_string(prompt).unwrap().trim_matches('"').to_owned(),
            String::from_utf8(db_gojson::to_vec(prompt).unwrap()).unwrap().trim_matches('"').to_owned(),
        ];
        assert!(forms[3].contains("\\u003cb\\u003e \\u0026"), "{}", forms[3]);
        for f in &forms {
            let text = format!("error: value {f} rejected");
            let out = redact(&text, &[prompt]);
            assert_eq!(out, "error: value [redacted] rejected", "form {f:?} not redacted");
        }
    }
}
