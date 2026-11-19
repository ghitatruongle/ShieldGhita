//! Track 1 (0.1.5-alpha2): auto-update checker.
//!
//! One-way HTTPS GET to the GitHub releases API — never receives connections,
//! never uploads anything. Network errors stay silent (debug log only);
//! `check_updates = false` in config.toml disables the feature entirely
//! (no request is sent at all).

use crate::modules::config::AppConfig;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const RELEASES_API_URL: &str =
    "https://api.github.com/repos/ghitatruongle/ShieldGhita/releases/latest";
/// Re-check interval while the app stays open (plan Track 1: 12h).
const RECHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Compare two version strings ("0.1.5-alpha1", "v0.1.5", "0.2.0" ...).
/// Returns true only when `remote` is strictly newer than `current`.
///
/// Rules (semver-like, hand-rolled — no `semver` dep to keep the binary small):
/// - leading `v`/`V` is ignored; a version with no parseable core is "unknown".
/// - core is `major.minor.patch` numeric triple, compared left to right.
/// - same core: no pre-release suffix > any pre-release (`0.1.5` > `0.1.5-alpha1`).
/// - pre-release identifiers split on `.`; numeric identifiers compare
///   numerically (`alpha2` < `alpha10`), otherwise lexicographically.
pub fn is_newer(current: &str, remote: &str) -> bool {
    let (cur, rem) = (parse_version(current), parse_version(remote));
    match (cur, rem) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(c), Some(r)) => compare_version(&c, &r) == std::cmp::Ordering::Less,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Version {
    core: [u64; 3],
    pre: Vec<(String, u64)>,
}

fn parse_version(s: &str) -> Option<Version> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    if s.is_empty() {
        return None;
    }
    let (core_str, pre_str) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut core = [0u64; 3];
    for (i, part) in core_str.split('.').enumerate().take(3) {
        core[i] = part.parse().ok()?;
    }
    // Any leftover core component (e.g. "1.2.3.4") is accepted but ignored.
    let pre = pre_str
        .map(|p| {
            p.split('.')
                .map(|ident| {
                    let idx = ident
                        .find(|c: char| c.is_ascii_digit())
                        .unwrap_or(ident.len());
                    let digits = ident[idx..].parse().unwrap_or(0);
                    (ident[..idx].to_string(), digits)
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Version { core, pre })
}

fn compare_version(a: &Version, b: &Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for i in 0..3 {
        match a.core[i].cmp(&b.core[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        // No pre-release > any pre-release on the same core.
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            let max_len = a.pre.len().max(b.pre.len());
            for i in 0..max_len {
                match (a.pre.get(i), b.pre.get(i)) {
                    (Some(x), Some(y)) => {
                        let ord = x.cmp(y);
                        if ord != Ordering::Equal {
                            return ord;
                        }
                    }
                    // Shorter identifier list sorts first (semver rule).
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (None, None) => break,
                }
            }
            Ordering::Equal
        }
    }
}

/// Extract `tag_name` from a GitHub API `/releases/latest` JSON body.
pub fn remote_tag_from_json(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("tag_name")?.as_str().map(|s| s.to_string())
}

/// Query the GitHub API for the newest release tag.
async fn fetch_latest_tag(client: &reqwest::Client) -> Result<String, String> {
    let resp = client
        .get(RELEASES_API_URL)
        .header(
            "User-Agent",
            format!("ShieldGhita/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/vnd.github+json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    let body = resp.text().await.map_err(|e| format!("body: {e}"))?;
    remote_tag_from_json(&body).ok_or_else(|| "no tag_name in response".to_string())
}

/// Background watcher: check once at startup, then every 12h while the app is
/// open. When a newer tag is found, raise the in-app update banner (the banner
/// itself is i18n-rendered in Slint; Rust only sets the version string).
/// Pushing to the UI must happen on the Slint event loop.
pub async fn watch_for_updates(config: Arc<RwLock<AppConfig>>, ui: slint::Weak<crate::AppWindow>) {
    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Update checker disabled, client build failed: {e}");
            return;
        }
    };
    loop {
        let enabled = config.read().map(|c| c.check_updates).unwrap_or(true);
        if enabled {
            match fetch_latest_tag(&client).await {
                Ok(tag) => {
                    if is_newer(env!("CARGO_PKG_VERSION"), &tag) {
                        let ui_iter = ui.clone();
                        let shown = slint::invoke_from_event_loop(move || {
                            if let Some(u) = ui_iter.upgrade() {
                                u.set_update_available(true);
                                u.set_update_version(tag.clone().into());
                                tracing::info!("Update available: {tag}");
                            }
                        });
                        if shown.is_err() {
                            tracing::debug!("Update banner skipped: event loop gone");
                        }
                    }
                }
                Err(e) => {
                    // Silent by design — a failed update check must never bother
                    // the user or log at a level that looks like a problem.
                    tracing::debug!("Update check skipped: {e}");
                }
            }
        }
        tokio::time::sleep(RECHECK_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_table() {
        // Same version → false.
        assert!(!is_newer("0.1.5-alpha1", "0.1.5-alpha1"));
        assert!(!is_newer("0.1.5", "0.1.5"));
        // Alpha increments.
        assert!(is_newer("0.1.5-alpha1", "0.1.5-alpha2"));
        assert!(!is_newer("0.1.5-alpha2", "0.1.5-alpha1"));
        // Pre-release < release on the same core.
        assert!(is_newer("0.1.5-alpha1", "0.1.5"));
        assert!(!is_newer("0.1.5", "0.1.5-alpha2"));
        // Numeric pre-release identifiers compare numerically.
        assert!(is_newer("0.1.5-alpha1", "0.1.5-alpha10"));
        assert!(!is_newer("0.1.5-alpha10", "0.1.5-alpha2"));
        // Older remote → false.
        assert!(!is_newer("0.1.5-alpha1", "0.1.4"));
        assert!(!is_newer("0.1.5", "0.1.4"));
        // Major/minor jumps.
        assert!(is_newer("0.1.5-alpha1", "0.2.0"));
        assert!(is_newer("0.1.5-alpha1", "1.0.0"));
        // `v` prefix on remote tags.
        assert!(is_newer("0.1.5-alpha1", "v0.1.5-alpha2"));
        assert!(!is_newer("0.1.5-alpha1", "v0.1.4"));
        // Garbage / empty remote → never "newer".
        assert!(!is_newer("0.1.5-alpha1", "garbage"));
        assert!(!is_newer("0.1.5-alpha1", ""));
        // Unknown current, valid remote → newer.
        assert!(is_newer("garbage", "0.1.5-alpha2"));
    }

    #[test]
    fn test_remote_tag_from_json() {
        assert_eq!(
            remote_tag_from_json(r#"{"tag_name":"v0.1.5-alpha2","name":"x"}"#),
            Some("v0.1.5-alpha2".to_string())
        );
        assert_eq!(remote_tag_from_json("not json"), None);
        assert_eq!(remote_tag_from_json(r#"{"other":1}"#), None);
        assert_eq!(
            remote_tag_from_json(r#"{"tag_name":null}"#),
            None,
            "null tag_name must not become Some"
        );
    }
}
