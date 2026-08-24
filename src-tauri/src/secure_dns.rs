//! SECURITY (#4 privacy): secure DNS resolution for the desktop client.
//!
//! The WebView's default DNS resolution leaks every hostname the client
//! contacts to the OS resolver — and therefore to the local network and the
//! ISP. This module provides DNS-over-HTTPS (DoH) resolution via a
//! non-logging resolver, used by the updater and any native HTTP client.
//!
//! The WebView itself cannot be forced onto DoH portably; the documented
//! hard-fail posture is: in OpSec-strict mode, the client verifies that the
//! API origin resolves identically via DoH and warns the user on mismatch
//! (DNS tampering / captive portal detection).

use std::sync::OnceLock;

/// Default non-logging resolver (Quad9 — no logs, no DNSSEC bypass, Swiss
/// jurisdiction). Overridable via QXP_DOH_URL.
const DEFAULT_DOH_URL: &str = "https://dns.quad9.net/dns-query";

pub fn doh_url() -> String {
    std::env::var("QXP_DOH_URL")
        .ok()
        .filter(|v| v.starts_with("https://"))
        .unwrap_or_else(|| DEFAULT_DOH_URL.to_owned())
}

/// Resolve a hostname to its IPv4 addresses via DNS-over-HTTPS (RFC 8484,
/// application/dns-json wireformat as popularized by Google/Cloudflare and
/// supported by Quad9).
pub async fn resolve_via_doh(hostname: &str) -> Result<Vec<std::net::IpAddr>, String> {
    let url = format!(
        "{}?name={}&type=A",
        doh_url(),
        urlencoding::encode(hostname)
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("DoH client: {e}"))?;

    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| format!("DoH query failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("DoH response parse: {e}"))?;

    let mut out = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(|a| a.as_array()) {
        for answer in answers {
            if answer.get("type").and_then(|t| t.as_u64()) == Some(1) {
                if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = data.parse::<std::net::IpAddr>() {
                        out.push(ip);
                    }
                }
            }
        }
    }

    if out.is_empty() {
        return Err(format!("DoH: no A record for {hostname}"));
    }
    Ok(out)
}

/// Compare DoH resolution with system resolution for the API origin.
/// A mismatch indicates DNS tampering, a captive portal, or a hijacked
/// resolver — surfaced to the user as a security warning.
pub async fn verify_dns_consistency(hostname: &str) -> Result<bool, String> {
    let doh_ips = resolve_via_doh(hostname).await?;
    let host = hostname.to_owned();
    let system_ips: Vec<std::net::IpAddr> = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        format!("{host}:443")
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>())
            .unwrap_or_default()
    })
    .await
    .map_err(|e| format!("join: {e}"))?;

    if system_ips.is_empty() {
        return Ok(false);
    }

    // Consistent if at least one system IP appears in the DoH answer set.
    Ok(doh_ips.iter().any(|ip| system_ips.contains(ip)))
}

static DNS_WARNING_SHOWN: OnceLock<()> = OnceLock::new();

/// Run the DNS consistency check once at startup; log a warning on mismatch.
/// Never blocks startup — this is a detection mechanism, not a gate.
pub fn spawn_dns_watchdog(hostname: String) {
    tokio::spawn(async move {
        match verify_dns_consistency(&hostname).await {
            Ok(true) => {}
            Ok(false) => {
                if DNS_WARNING_SHOWN.set(()).is_ok() {
                    eprintln!(
                        "SECURITY WARNING: DNS resolution for {hostname} differs between \
                         DoH and the system resolver. Possible DNS tampering, captive \
                         portal, or hijacked resolver. Consider using a trusted network \
                         or Tor."
                    );
                }
            }
            Err(err) => {
                // DoH unavailability is not fatal (offline, blocked network);
                // stay silent to avoid noise.
                let _ = err;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_url_default_is_https() {
        assert!(doh_url().starts_with("https://"));
    }
}
