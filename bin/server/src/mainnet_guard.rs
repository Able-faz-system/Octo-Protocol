//! Startup guard: refuse to run on mainnet with placeholder/low-entropy secrets or plaintext URLs.
//!
//! Every problem is collected into one error so an operator fixes the whole config in one pass.
//! Messages name the offending variable only — never its value.

use octo_wallet_core::StellarNetwork;
use std::fmt;

/// HS256 key length recommended by RFC 7518 §3.2 (the 16-byte dev floor is too weak for mainnet).
const MAINNET_MIN_JWT_SECRET_LEN: usize = 32;

/// Minimum estimated entropy for any mainnet secret; well below what a CSPRNG value scores.
const MIN_ENTROPY_BITS: f64 = 128.0;

/// Exact values published in this repo (CI, docs), so they are public knowledge.
const KNOWN_PLACEHOLDERS: &[&str] = &[
    "supersecretjwtkeyforminimumnsixteenbytes",
    "re_test_dummy_key_for_ci",
];

/// Substrings that mark a value as a template someone forgot to fill in.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "<",
    ">",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "example",
    "dummy",
    "your_",
    "your-",
    "supersecret",
    "xxxxxxxx",
];

/// The subset of server config whose safety depends on the network.
pub struct MainnetCheck<'a> {
    pub jwt_secret: &'a [u8],
    pub master_key: &'a [u8; 32],
    pub master_key_next: Option<&'a [u8; 32]>,
    pub resend_api_key: &'a str,
    pub horizon_url: &'a str,
    pub public_app_url: &'a str,
    pub public_api_url: Option<&'a str>,
}

/// All reasons the config is unsafe for mainnet. Contains variable names only, never values.
#[derive(Debug)]
pub struct UnsafeMainnetConfig(pub Vec<String>);

impl fmt::Display for UnsafeMainnetConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to start on mainnet with an unsafe configuration: {}",
            self.0.join("; ")
        )
    }
}

impl std::error::Error for UnsafeMainnetConfig {}

/// Validate `cfg` for `network`. Non-mainnet networks are always accepted.
pub fn check(network: StellarNetwork, cfg: &MainnetCheck<'_>) -> Result<(), UnsafeMainnetConfig> {
    if network != StellarNetwork::Public {
        return Ok(());
    }
    let mut problems = Vec::new();

    if cfg.jwt_secret.len() < MAINNET_MIN_JWT_SECRET_LEN {
        problems.push(format!(
            "JWT_SECRET must be at least {MAINNET_MIN_JWT_SECRET_LEN} bytes on mainnet"
        ));
    }
    if is_placeholder(cfg.jwt_secret) {
        problems.push("JWT_SECRET is a placeholder value".to_string());
    }
    if estimated_entropy_bits(cfg.jwt_secret) < MIN_ENTROPY_BITS {
        problems.push("JWT_SECRET has too little entropy (use `openssl rand -hex 32`)".to_string());
    }

    if is_weak_key(cfg.master_key) {
        problems
            .push("MASTER_KEY has too little entropy (use `openssl rand -base64 32`)".to_string());
    }
    if let Some(next) = cfg.master_key_next {
        if is_weak_key(next) {
            problems.push(
                "MASTER_KEY_NEXT has too little entropy (use `openssl rand -base64 32`)"
                    .to_string(),
            );
        }
        if next == cfg.master_key {
            problems.push("MASTER_KEY_NEXT must differ from MASTER_KEY".to_string());
        }
    }

    if is_placeholder(cfg.resend_api_key.as_bytes()) {
        problems.push("RESEND_API_KEY is a placeholder value".to_string());
    }

    for (name, url) in [
        ("HORIZON_URL", Some(cfg.horizon_url)),
        ("PUBLIC_APP_URL", Some(cfg.public_app_url)),
        ("PUBLIC_API_URL", cfg.public_api_url),
    ] {
        if url.is_some_and(|url| !is_https(url)) {
            problems.push(format!("{name} must be an https:// URL with a host on mainnet"));
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(UnsafeMainnetConfig(problems))
    }
}

/// True for a published placeholder or a value containing a template marker.
fn is_placeholder(value: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(value).trim().to_ascii_lowercase();
    KNOWN_PLACEHOLDERS.iter().any(|p| lower == *p)
        || PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m))
}

/// Low byte-entropy, or a constant-step run like `00 01 02 …`, which scores high but is guessable.
fn is_weak_key(key: &[u8; 32]) -> bool {
    let step = key[1].wrapping_sub(key[0]);
    let arithmetic = key.windows(2).all(|w| w[1].wrapping_sub(w[0]) == step);
    arithmetic || estimated_entropy_bits(key) < MIN_ENTROPY_BITS
}

/// Shannon entropy of the byte distribution times length: a cheap upper bound on real entropy.
fn estimated_entropy_bits(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2() * len
        })
        .sum()
}

/// `https://` (any case) followed by a non-empty authority.
fn is_https(url: &str) -> bool {
    let url = url.trim();
    url.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        && url[8..].chars().next().is_some_and(|c| c != '/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_KEY: [u8; 32] = [
        0xf9, 0x67, 0x11, 0x28, 0x67, 0x65, 0xd5, 0x1d, 0xa2, 0x7e, 0x56, 0xc7, 0x5f, 0x70, 0xcc,
        0xb2, 0xf0, 0xa6, 0x56, 0x20, 0x11, 0xad, 0x1e, 0xfc, 0x91, 0xf5, 0x0a, 0x9b, 0xf6, 0x95,
        0x8f, 0x81,
    ];
    const GOOD_JWT: &[u8] = b"e0214f45e62929235961abd74a25ad658e1a3400bdbf6c638f91a0163b9f48df";

    fn safe() -> MainnetCheck<'static> {
        MainnetCheck {
            jwt_secret: GOOD_JWT,
            master_key: &GOOD_KEY,
            master_key_next: None,
            resend_api_key: "re_9fK2mQ7xLp4vT8wZ3nB6hJ1c",
            horizon_url: "https://horizon.stellar.org",
            public_app_url: "https://app.octo.dev",
            public_api_url: Some("https://api.octo.dev"),
        }
    }

    // Asserts mainnet rejects `cfg` with a message mentioning `needle`.
    fn assert_rejected(cfg: MainnetCheck<'_>, needle: &str) {
        let err = check(StellarNetwork::Public, &cfg).expect_err("config should be rejected");
        assert!(err.to_string().contains(needle), "{needle:?} not in {err}");
    }

    #[test]
    fn accepts_a_safe_mainnet_config() {
        check(StellarNetwork::Public, &safe()).unwrap();
    }

    #[test]
    fn testnet_is_not_held_to_mainnet_rules() {
        let cfg = MainnetCheck {
            jwt_secret: b"supersecretjwtkeyforminimumnsixteenbytes",
            master_key: &[0; 32],
            horizon_url: "http://localhost:8000",
            public_app_url: "http://localhost:3000",
            ..safe()
        };
        check(StellarNetwork::Testnet, &cfg).unwrap();
    }

    #[test]
    fn rejects_the_ci_jwt_placeholder() {
        let cfg = MainnetCheck {
            jwt_secret: b"supersecretjwtkeyforminimumnsixteenbytes",
            ..safe()
        };
        assert_rejected(cfg, "JWT_SECRET is a placeholder");
    }

    #[test]
    fn rejects_a_templated_jwt_secret() {
        let cfg = MainnetCheck {
            jwt_secret: b"<generate-with-openssl-rand-hex-32-and-paste-here>",
            ..safe()
        };
        assert_rejected(cfg, "JWT_SECRET is a placeholder");
    }

    #[test]
    fn rejects_a_jwt_secret_shorter_than_32_bytes() {
        let cfg = MainnetCheck {
            jwt_secret: b"e0214f45e62929235961abd7",
            ..safe()
        };
        assert_rejected(cfg, "JWT_SECRET must be at least 32 bytes");
    }

    #[test]
    fn rejects_a_low_entropy_jwt_secret() {
        let cfg = MainnetCheck {
            jwt_secret: b"abababababababababababababababababababab",
            ..safe()
        };
        assert_rejected(cfg, "JWT_SECRET has too little entropy");
    }

    #[test]
    fn rejects_the_all_zero_ci_master_key() {
        let cfg = MainnetCheck {
            master_key: &[0; 32],
            ..safe()
        };
        assert_rejected(cfg, "MASTER_KEY has too little entropy");
    }

    #[test]
    fn rejects_a_sequential_master_key() {
        let seq: [u8; 32] = std::array::from_fn(|i| i as u8);
        let cfg = MainnetCheck {
            master_key: &seq,
            ..safe()
        };
        assert_rejected(cfg, "MASTER_KEY has too little entropy");
    }

    #[test]
    fn rejects_a_low_entropy_master_key_next() {
        let cfg = MainnetCheck {
            master_key_next: Some(&[0x41; 32]),
            ..safe()
        };
        assert_rejected(cfg, "MASTER_KEY_NEXT has too little entropy");
    }

    #[test]
    fn rejects_master_key_next_equal_to_master_key() {
        let cfg = MainnetCheck {
            master_key_next: Some(&GOOD_KEY),
            ..safe()
        };
        assert_rejected(cfg, "MASTER_KEY_NEXT must differ");
    }

    #[test]
    fn rejects_the_ci_resend_placeholder() {
        let cfg = MainnetCheck {
            resend_api_key: "re_test_dummy_key_for_ci",
            ..safe()
        };
        assert_rejected(cfg, "RESEND_API_KEY is a placeholder");
    }

    #[test]
    fn rejects_plain_http_horizon_url() {
        let cfg = MainnetCheck {
            horizon_url: "http://horizon.stellar.org",
            ..safe()
        };
        assert_rejected(cfg, "HORIZON_URL must be an https:// URL");
    }

    #[test]
    fn rejects_plain_http_public_app_url() {
        let cfg = MainnetCheck {
            public_app_url: "http://localhost:3000",
            ..safe()
        };
        assert_rejected(cfg, "PUBLIC_APP_URL must be an https:// URL");
    }

    #[test]
    fn rejects_plain_http_public_api_url() {
        let cfg = MainnetCheck {
            public_api_url: Some("http://api.octo.dev"),
            ..safe()
        };
        assert_rejected(cfg, "PUBLIC_API_URL must be an https:// URL");
    }

    #[test]
    fn rejects_https_url_without_a_host() {
        let cfg = MainnetCheck {
            horizon_url: "https:///accounts",
            ..safe()
        };
        assert_rejected(cfg, "HORIZON_URL must be an https:// URL");
    }

    #[test]
    fn reports_every_problem_in_one_error_without_leaking_values() {
        let cfg = MainnetCheck {
            jwt_secret: b"supersecretjwtkeyforminimumnsixteenbytes",
            master_key: &[0; 32],
            horizon_url: "http://horizon.stellar.org",
            ..safe()
        };
        let err = check(StellarNetwork::Public, &cfg).unwrap_err();
        assert_eq!(err.0.len(), 3, "{err}");
        assert!(!err.to_string().contains("supersecret"));
    }
}
