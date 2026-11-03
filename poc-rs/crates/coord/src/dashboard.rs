//! The coordinator dashboard at `/` (everything HTML-escaped).

use crate::{LedgerEntry, Server};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;
use db_gojson::GoTime;
use db_tpmattest::{Check, Tier};
use std::fmt::Write as _;
use std::sync::Arc;

/// Escapes text for HTML element content and attribute values.
pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '\0' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn short(s: &str) -> String {
    match s.char_indices().nth(16) {
        Some((i, _)) => format!("{}…", s.get(..i).unwrap_or_default()),
        None => s.to_owned(),
    }
}

/// A Go-style rendering of whole seconds ("1m30s", "-4s").
fn go_secs(secs: i64) -> String {
    let (sign, s) = if secs < 0 { ("-", secs.unsigned_abs()) } else { ("", secs.unsigned_abs()) };
    let (h, m, sec) = (s / 3600, (s / 60) % 60, s % 60);
    let mut out = sign.to_owned();
    if h > 0 {
        let _ = write!(out, "{h}h");
    }
    if h > 0 || m > 0 {
        let _ = write!(out, "{m}m");
    }
    let _ = write!(out, "{sec}s");
    out
}

fn ago(t: &GoTime) -> String {
    let now = GoTime::now_utc().datetime();
    go_secs((now - t.datetime()).num_milliseconds().saturating_add(500).div_euclid(1000))
}

fn until(t: &GoTime) -> String {
    let now = GoTime::now_utc().datetime();
    go_secs((t.datetime() - now).num_milliseconds().saturating_add(500).div_euclid(1000))
}

struct DashProvider {
    id: String,
    account: String,
    session: String,
    device: String,
    root: String,
    tpm_mode: String,
    firmware: String,
    release: String,
    gpu: String,
    tier: Tier,
    leased: bool,
    lease_until: GoTime,
    quotes: u64,
    reset: u32,
    models: Vec<db_wire::ModelCap>,
    checks: Vec<Check>,
}

struct DashJob {
    id: String,
    provider: String,
    model: String,
    size: String,
    state: &'static str,
    err: String,
    bytes: i64,
    created: GoTime,
}

const HEAD: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>Darkbloom AMD PoC coordinator</title>
<meta http-equiv="refresh" content="5">
<style>body{font:14px ui-monospace,Menlo,monospace;margin:24px;background:#0b0b0c;color:#e8e8e8}
h1{font-size:18px}h2{font-size:15px;margin-top:28px}table{border-collapse:collapse;margin:8px 0}
td,th{border:1px solid #333;padding:4px 8px;text-align:left;vertical-align:top}th{background:#18181b}
.ok{color:#5fd068}.bad{color:#ff6b6b}.info{color:#9aa0a6}.tier{font-weight:bold}.warn{color:#f5c542}</style></head><body>
<h1>Darkbloom on AMD — PoC coordinator</h1>
"#;

fn render(started: &GoTime, providers: &[DashProvider], jobs: &[DashJob], ledger: &[LedgerEntry]) -> String {
    let mut h = String::from(HEAD);
    let _ = write!(
        h,
        "<p class=\"info\">Routes sealed image/video jobs only to providers with a live TPM-attested lease. The coordinator never holds a key that opens a prompt or an output. Up {}.</p>\n<h2>Providers</h2>\n",
        esc(&ago(started))
    );
    if providers.is_empty() {
        h.push_str("<p class=\"info\">No providers connected.</p>");
    }
    for p in providers {
        let _ = write!(
            h,
            "\n<table><tr><th>provider</th><td>{} (account {}, session {})</td></tr>\n<tr><th>device</th><td>{} — root: {} — TPM: {} {}</td></tr>\n",
            esc(&p.id),
            esc(&p.account),
            esc(&short(&p.session)),
            esc(&p.device),
            esc(&p.root),
            esc(&p.tpm_mode),
            esc(&p.firmware)
        );
        let lease = if p.leased {
            format!("(lease {} left, {} quotes, resetCount {})", until(&p.lease_until), p.quotes, p.reset)
        } else {
            "(no lease)".to_owned()
        };
        let _ = write!(
            h,
            "<tr><th>tier</th><td class=\"tier {}\">{} {}</td></tr>\n<tr><th>release</th><td>{}</td></tr>\n<tr><th>models</th><td>",
            if p.leased { "ok" } else { "bad" },
            esc(p.tier.as_str()),
            esc(&lease),
            esc(&p.release)
        );
        for m in &p.models {
            let _ = write!(h, "{} ({}, ≤{}×{}) ", esc(&m.id), esc(&m.kind), m.max_width, m.max_height);
        }
        let _ = write!(h, "— GPU {}</td></tr>\n<tr><th>checks</th><td>", esc(&p.gpu));
        for c in &p.checks {
            let class = if c.ok {
                "ok"
            } else if c.effect == "required" {
                "bad"
            } else if c.effect == "tier" {
                "warn"
            } else {
                "info"
            };
            let _ = write!(
                h,
                "<div class=\"{class}\">{} {} <span class=\"info\">[{}]</span> {}</div>",
                if c.ok { "✓" } else { "✗" },
                esc(&c.name),
                esc(&c.effect),
                esc(&c.detail)
            );
        }
        h.push_str("</td></tr>\n</table>\n");
    }
    h.push_str("\n<h2>Jobs</h2><table><tr><th>job</th><th>provider</th><th>model</th><th>size</th><th>state</th><th>sealed bytes</th><th>age</th></tr>\n");
    for j in jobs {
        let class = match j.state {
            "done" => "ok",
            "error" => "bad",
            _ => "",
        };
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"{class}\">{} {}</td><td>{}</td><td>{}</td></tr>",
            esc(&short(&j.id)),
            esc(&short(&j.provider)),
            esc(&j.model),
            esc(&j.size),
            esc(j.state),
            esc(&j.err),
            j.bytes,
            esc(&ago(&j.created))
        );
    }
    h.push_str("</table>\n<h2>Ledger (billed from verified provider receipts)</h2><table><tr><th>job</th><th>model</th><th>units</th><th>price µUSD</th><th>release</th></tr>\n");
    for e in ledger {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{} img, {:.2} MP, {} steps, {} ms</td><td>{}</td><td>{}</td></tr>",
            esc(&short(&e.job_id)),
            esc(&e.model),
            e.units.images,
            e.units.megapixels,
            e.units.steps,
            e.units.gpu_millis,
            e.price_micro,
            esc(&e.release)
        );
    }
    h.push_str("</table>\n</body></html>");
    h
}

/// `GET /`.
pub(crate) async fn handle_dashboard(State(s): State<Arc<Server>>) -> Response {
    let (providers, mut jobs, ledger) = {
        let st = s.lock();
        let now = GoTime::now_utc();
        let mut providers = Vec::new();
        for conn in st.providers.values() {
            let Some((p, ps)) = st.conns.get(conn) else { continue };
            let v = ps.verdict.as_deref();
            providers.push(DashProvider {
                id: p.id.clone(),
                account: p.account_id.clone(),
                session: p.session_id.clone(),
                device: p.device_id.clone(),
                root: p.root_name.clone(),
                tpm_mode: p.hello.tpm_mode.clone(),
                firmware: v.map(|v| v.tpm_firmware.clone()).unwrap_or_default(),
                release: v.map(|v| v.release.clone()).unwrap_or_default(),
                gpu: p.hello.gpu.clone(),
                tier: v.map_or(Tier::Rejected, |v| v.tier.clone()),
                leased: Server::leased(ps, &now),
                lease_until: ps.lease_until,
                quotes: ps.quotes,
                reset: v.map_or(0, |v| v.reset_count),
                models: p.hello.models.clone(),
                checks: v.map(|v| v.checks.clone()).unwrap_or_default(),
            });
        }
        providers.sort_by(|a, b| a.id.cmp(&b.id));
        let jobs: Vec<DashJob> = st
            .jobs
            .values()
            .map(|j| DashJob {
                id: j.id.clone(),
                provider: j.provider_id.clone(),
                model: j.parsed.model.clone(),
                size: format!("{}×{}, {} steps", j.parsed.width, j.parsed.height, j.parsed.steps),
                state: j.state,
                err: j.err.clone(),
                bytes: j.size,
                created: j.created,
            })
            .collect();
        (providers, jobs, st.ledger.clone())
    };
    jobs.sort_by_key(|j| std::cmp::Reverse(j.created));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(render(&s.started, &providers, &jobs, &ledger).into())
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_and_durations() {
        assert_eq!(esc("<script>alert('x')</script>&\""), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&#34;");
        assert_eq!(go_secs(0), "0s");
        assert_eq!(go_secs(90), "1m30s");
        assert_eq!(go_secs(3725), "1h2m5s");
        assert_eq!(go_secs(-4), "-4s");
        assert_eq!(short("0123456789abcdefXYZ"), "0123456789abcdef…");
        assert_eq!(short("short"), "short");
    }
}
