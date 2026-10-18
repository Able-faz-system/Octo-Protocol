//! Per-IP fixed-window rate limiting for public and auth endpoints.
//!
//! In-memory and per-process (matches this API's single-instance deployment). Handlers call
//! [`RateLimiter::check`] explicitly, the same way auth is enforced per-handler here — there is
//! no tower middleware layer to configure or bypass.

use axum::http::HeaderMap;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cap on tracked (ip, class) buckets before expired entries are swept.
const SWEEP_THRESHOLD: usize = 10_000;

// Rate limit thresholds and fixed windows for API endpoints.
pub const AUTH_RATE_LIMIT: u32 = 10;
pub const AUTH_RATE_WINDOW: Duration = Duration::from_secs(60);
pub const OTP_RESEND_USER_LIMIT: u32 = 3;
pub const OTP_RESEND_USER_WINDOW: Duration = Duration::from_secs(3600);
pub const OTP_RESEND_IP_LIMIT: u32 = 10;
pub const OTP_RESEND_IP_WINDOW: Duration = Duration::from_secs(3600);
pub const PAY_READ_LIMIT: u32 = 60;
pub const PAY_READ_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_INTENT_LIMIT: u32 = 5;
pub const PAY_INTENT_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_STATUS_LIMIT: u32 = 60;
pub const PAY_STATUS_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SIGNING_INFO_LIMIT: u32 = 60;
pub const PAY_SIGNING_INFO_WINDOW: Duration = Duration::from_secs(60);
pub const PAY_SUBMIT_LIMIT: u32 = 20;
pub const PAY_SUBMIT_WINDOW: Duration = Duration::from_secs(60);
// Seed-backup retrieval: legitimate use is a rare new-device recovery, so keep this tight.
pub const BACKUP_USER_LIMIT: u32 = 5;
pub const BACKUP_USER_WINDOW: Duration = Duration::from_secs(3600);

/// Bucket key: the client IP plus the endpoint class it is being limited against.
type BucketKey = (String, &'static str);
/// Bucket value: when the current fixed window started, and hits so far within it.
type Bucket = (Instant, u32);

#[derive(Clone, Default)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<BucketKey, Bucket>>>,
}

impl RateLimiter {
    /// Record a hit for `(ip, class)`; false when the fixed window's limit is exceeded.
    pub fn check(&self, ip: &str, class: &'static str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter lock");

        if buckets.len() > SWEEP_THRESHOLD {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < window);
        }

        let entry = buckets.entry((ip.to_string(), class)).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (network, prefix) = match cidr.trim().split_once('/') {
        Some((network, prefix)) => (network, prefix.parse::<u32>().ok()),
        None => return cidr.trim().parse::<IpAddr>().ok() == Some(ip),
    };
    let Some(prefix) = prefix else { return false };
    match (ip, network.parse::<IpAddr>().ok()) {
        (IpAddr::V4(ip), Some(IpAddr::V4(network))) if prefix <= 32 => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), Some(IpAddr::V6(network))) if prefix <= 128 => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn is_trusted_proxy(ip: IpAddr) -> bool {
    std::env::var("TRUSTED_PROXY_CIDRS")
        .ok()
        .is_some_and(|value| value.split(',').any(|cidr| ip_in_cidr(ip, cidr)))
}

/// Resolve the client address while honoring forwarding headers only from configured proxies.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let Some(peer_ip) = peer.map(|addr| addr.ip()) else {
        return "unknown".to_string();
    };
    if !is_trusted_proxy(peer_ip) {
        return peer_ip.to_string();
    }

    let Some(xff) = headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) else {
        return peer_ip.to_string();
    };
    let forwarded: Option<Vec<IpAddr>> = xff
        .split(',')
        .map(|value| value.trim().parse::<IpAddr>().ok())
        .collect();
    let Some(forwarded) = forwarded else {
        return peer_ip.to_string();
    };
    forwarded
        .into_iter()
        .rev()
        .find(|ip| !is_trusted_proxy(*ip))
        .unwrap_or(peer_ip)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let rl = RateLimiter::default();
        let window = Duration::from_secs(60);
        for _ in 0..5 {
            assert!(rl.check("1.2.3.4", "test", 5, window));
        }
        assert!(!rl.check("1.2.3.4", "test", 5, window));
        // A different IP has its own bucket.
        assert!(rl.check("5.6.7.8", "test", 5, window));
        // A different class on the same IP has its own bucket too.
        assert!(rl.check("1.2.3.4", "other", 5, window));
    }

    #[test]
    fn window_resets_after_expiry() {
        let rl = RateLimiter::default();
        let window = Duration::from_millis(30);
        assert!(rl.check("1.2.3.4", "test", 1, window));
        assert!(!rl.check("1.2.3.4", "test", 1, window));
        std::thread::sleep(Duration::from_millis(40));
        assert!(rl.check("1.2.3.4", "test", 1, window));
    }

    #[test]
    fn client_ip_uses_socket_peer_without_a_trusted_proxy() {
        let empty = HeaderMap::new();
        let peer = "127.0.0.1:5000".parse().ok();
        assert_eq!(client_ip(&empty, peer), "127.0.0.1");
        assert_eq!(client_ip(&empty, None), "unknown");
    }

    #[test]
    fn cidr_matching_supports_ipv4_and_ipv6() {
        assert!(ip_in_cidr("10.2.3.4".parse().unwrap(), "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.2.3.4".parse().unwrap(), "10.0.0.0/8"));
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
    }
}
