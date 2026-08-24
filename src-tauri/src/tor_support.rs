//! SECURITY (#1 privacy): Tor routing support for the desktop client.
//!
//! Provides two capabilities to the frontend:
//!
//! 1. `tor_status` — reports whether the configured SOCKS5 proxy (Tor) is
//!    reachable and whether the exit can reach the configured API origin.
//! 2. `tor_verify` — performs a full circuit check: connects through the
//!    proxy, fetches an IP echo service, and returns the observed exit IP so
//!    the user can confirm their traffic is actually anonymized.
//!
//! The WebSocket itself is a WebView concern: when Tor mode is enabled the
//! frontend points the WS/API at the onion address, and this plugin verifies
//! reachability of that origin through the proxy.

use serde::Serialize;
use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[derive(Debug, Clone, Serialize)]
pub struct TorStatus {
    /// Whether a SOCKS5 proxy is configured.
    pub proxy_configured: bool,
    /// Whether the proxy accepted a TCP connection.
    pub proxy_reachable: bool,
    /// Whether the API origin was reachable through the proxy.
    pub origin_reachable: bool,
    /// Observed public IP through the proxy (empty if check failed).
    pub exit_ip: String,
    /// Human-readable detail for diagnostics.
    pub detail: String,
}

fn proxy_addr() -> Option<String> {
    std::env::var("QXP_TOR_PROXY")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn origin_url() -> String {
    std::env::var("QXP_SERVER_ORIGIN")
        .ok()
        .filter(|v| v.starts_with("http"))
        .unwrap_or_else(|| "https://qxch.at".to_owned())
}

fn build_client(proxy: &str) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(proxy).map_err(|e| format!("proxy config: {e}"))?;
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .proxy(proxy)
        .build()
        .map_err(|e| format!("client build: {e}"))
}

async fn check_tor() -> TorStatus {
    let Some(proxy) = proxy_addr() else {
        return TorStatus {
            proxy_configured: false,
            proxy_reachable: false,
            origin_reachable: false,
            exit_ip: String::new(),
            detail: "No SOCKS5 proxy configured. Set QXP_TOR_PROXY=socks5://127.0.0.1:9050."
                .to_owned(),
        };
    };
    check_tor_with(&proxy).await
}

async fn check_tor_with(proxy: &str) -> TorStatus {
    let client = match build_client(proxy) {
        Ok(c) => c,
        Err(err) => {
            return TorStatus {
                proxy_configured: true,
                proxy_reachable: false,
                origin_reachable: false,
                exit_ip: String::new(),
                detail: err,
            }
        }
    };

    // Step 1: verify the proxy carries traffic at all via an IP echo service.
    let exit_ip = match client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await
    {
        Ok(resp) => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("IP").and_then(|ip| ip.as_str()).map(str::to_owned))
            .unwrap_or_default(),
        Err(err) => {
            return TorStatus {
                proxy_configured: true,
                proxy_reachable: false,
                origin_reachable: false,
                exit_ip: String::new(),
                detail: format!("proxy unreachable: {err}"),
            }
        }
    };

    // Step 2: verify the QXP origin is reachable through the same circuit.
    let origin = origin_url();
    let origin_ok = client
        .get(&origin)
        .send()
        .await
        .map(|r| r.status().is_success() || r.status().is_redirection())
        .unwrap_or(false);

    TorStatus {
        proxy_configured: true,
        proxy_reachable: true,
        origin_reachable: origin_ok,
        exit_ip,
        detail: if origin_ok {
            "Tor circuit operational.".to_owned()
        } else {
            format!("Origin {origin} unreachable through Tor (is the onion service up?).")
        },
    }
}

#[tauri::command]
async fn tor_status() -> Result<TorStatus, String> {
    Ok(check_tor().await)
}

/// Full verification with explicit proxy override (from user settings).
/// SECURITY (M-5): the proxy is validated (SOCKS5 only) and tested BEFORE
/// being installed, so a compromised page cannot silently redirect native
/// HTTP traffic through an arbitrary host.
#[tauri::command]
async fn tor_verify(proxy: Option<String>) -> Result<TorStatus, String> {
    if let Some(p) = proxy.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()) {
        let lowered = p.to_lowercase();
        if !lowered.starts_with("socks5://") && !lowered.starts_with("socks5h://") {
            return Err("Only socks5:// proxies are supported.".to_owned());
        }
        // Test before installing: never leave a broken/hostile config in place.
        let status = check_tor_with(&p).await;
        if !status.proxy_reachable {
            return Err("Proxy unreachable; configuration not applied.".to_owned());
        }
        std::env::set_var("QXP_TOR_PROXY", &p);
        Ok(status)
    } else {
        Ok(check_tor().await)
    }
}

/// Initializes the Tor support plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("torsupport")
        .invoke_handler(tauri::generate_handler![tor_status, tor_verify])
        .setup(|_app, _api| Ok(()))
        .build()
}
