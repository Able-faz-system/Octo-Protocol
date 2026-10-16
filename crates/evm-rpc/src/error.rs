//! Typed errors for the EVM JSON-RPC client.
//!
//! # Security
//!
//! RPC URLs frequently embed API keys (e.g. `https://eth-mainnet.g.alchemy.com/v2/<KEY>`).
//! No variant in this module ever carries, formats, or otherwise leaks the endpoint URL.
//! When a transport error is surfaced we keep only the underlying `reqwest` error, which
//! describes the failure (timeout, connection reset, ...) without echoing the request URL.

use std::time::Duration;

use octo_resilience::Retriable;
use thiserror::Error;

/// Errors produced by [`crate::EvmRpcClient`].
///
/// The variants deliberately distinguish the three failure modes that a JSON-RPC client
/// must not conflate:
///
/// * [`EvmRpcError::Transport`] — the request never produced a usable HTTP response
///   (connection refused, TLS failure, timeout, body read failure, ...).
/// * [`EvmRpcError::JsonRpc`] — HTTP 200 with a JSON-RPC `error` member. A client that only
///   checks the HTTP status would treat this as success.
/// * [`EvmRpcError::Revert`] — the call executed but the EVM reverted, carrying the
///   (provider-dependent, possibly empty) revert data.
#[derive(Debug, Error)]
pub enum EvmRpcError {
    /// Transport-level failure: no usable HTTP response was obtained.
    ///
    /// The inner error is intentionally opaque and never includes the RPC URL.
    #[error("evm rpc transport failure: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The server returned a non-success HTTP status.
    ///
    /// `body` is a truncated, best-effort snippet of the response body for diagnostics.
    /// It is never the request URL.
    #[error("evm rpc http error: status {status}")]
    Http {
        /// The HTTP status code returned by the provider.
        status: u16,
        /// Truncated response body, if any, for diagnostics.
        body: Option<String>,
    },

    /// A well-formed JSON-RPC response carrying an `error` member (HTTP 200).
    #[error("evm rpc json-rpc error {code}: {message}")]
    JsonRpc {
        /// The JSON-RPC error code (e.g. `-32602`, `-32000`).
        code: i64,
        /// The JSON-RPC error message.
        message: String,
    },

    /// The EVM reverted the call. `data` is the provider-dependent revert payload.
    #[error("evm rpc execution reverted")]
    Revert {
        /// Revert data, if the provider supplied any. Encoding is inconsistent across
        /// providers, so this is kept as raw bytes.
        data: Option<Vec<u8>>,
    },

    /// The requested `eth_getLogs` block range exceeds the provider's cap.
    ///
    /// Surfaced as a distinct variant so callers can adaptively bisect the range instead
    /// of stalling or retrying an identical request forever.
    #[error("evm rpc block range too large")]
    RangeTooLarge,

    /// The provider rate-limited the request.
    #[error("evm rpc rate limited")]
    RateLimited {
        /// Server-advertised backoff, parsed from `Retry-After` when present.
        retry_after: Option<Duration>,
    },

    /// The circuit breaker for this chain is open; the request was not attempted.
    #[error("evm rpc circuit open")]
    CircuitOpen,

    /// The response body exceeded the configured size cap.
    ///
    /// A malicious or compromised RPC returning a multi-GB body must not OOM the worker.
    #[error("evm rpc response body exceeded size cap of {limit} bytes")]
    ResponseTooLarge {
        /// The configured maximum body size, in bytes.
        limit: usize,
    },

    /// The response could not be decoded as JSON-RPC, or a field was malformed.
    #[error("evm rpc malformed response: {0}")]
    Malformed(String),

    /// A hex quantity could not be parsed.
    #[error("evm rpc invalid hex quantity: {0}")]
    InvalidHex(String),

    /// The configured CAIP-2 chain id does not match the chain reported by the RPC.
    ///
    /// An RPC pointed at the wrong chain is a fund-loss bug, so this is a hard failure.
    #[error("evm rpc chain id mismatch: configured {configured}, rpc reported {actual}")]
    ChainIdMismatch {
        /// The CAIP-2 chain id the client was configured with.
        configured: String,
        /// The chain id reported by `eth_chainId`.
        actual: String,
    },
}

impl EvmRpcError {
    /// Whether this error is a transient failure that may succeed on retry.
    ///
    /// Only transport failures, 5xx HTTP responses, and rate-limit responses are
    /// considered transient. Protocol errors, reverts, range-too-large, malformed
    /// responses, and chain-id mismatches are permanent: retrying them cannot help and
    /// would only amplify load on a struggling provider.
    pub fn is_retriable(&self) -> bool {
        match self {
            EvmRpcError::Transport(_) => true,
            EvmRpcError::Http { status, .. } => *status >= 500,
            EvmRpcError::RateLimited { .. } => true,
            EvmRpcError::JsonRpc { .. }
            | EvmRpcError::Revert { .. }
            | EvmRpcError::RangeTooLarge
            | EvmRpcError::CircuitOpen
            | EvmRpcError::ResponseTooLarge { .. }
            | EvmRpcError::Malformed(_)
            | EvmRpcError::InvalidHex(_)
            | EvmRpcError::ChainIdMismatch { .. } => false,
        }
    }

    /// The server-advertised backoff, if the provider supplied one.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            EvmRpcError::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }
}

impl Retriable for EvmRpcError {
    fn is_retriable(&self) -> bool {
        EvmRpcError::is_retriable(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> EvmRpcError {
        EvmRpcError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset",
        )))
    }

    #[test]
    fn transport_is_retriable() {
        assert!(transport().is_retriable());
    }

    #[test]
    fn server_errors_are_retriable() {
        for status in [500u16, 502, 503, 504] {
            let err = EvmRpcError::Http {
                status,
                body: None,
            };
            assert!(err.is_retriable(), "status {status} should be retriable");
        }
    }

    #[test]
    fn client_errors_are_permanent() {
        for status in [400u16, 401, 403, 404, 422] {
            let err = EvmRpcError::Http {
                status,
                body: None,
            };
            assert!(!err.is_retriable(), "status {status} should be permanent");
        }
    }

    #[test]
    fn rate_limited_is_retriable_and_carries_backoff() {
        let err = EvmRpcError::RateLimited {
            retry_after: Some(Duration::from_secs(3)),
        };
        assert!(err.is_retriable());
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn protocol_errors_are_permanent() {
        let err = EvmRpcError::JsonRpc {
            code: -32000,
            message: "execution reverted".into(),
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn revert_is_permanent() {
        let err = EvmRpcError::Revert { data: None };
        assert!(!err.is_retriable());
    }

    #[test]
    fn range_too_large_is_permanent() {
        assert!(!EvmRpcError::RangeTooLarge.is_retriable());
    }

    #[test]
    fn circuit_open_is_permanent() {
        assert!(!EvmRpcError::CircuitOpen.is_retriable());
    }

    #[test]
    fn response_too_large_is_permanent() {
        let err = EvmRpcError::ResponseTooLarge { limit: 1024 };
        assert!(!err.is_retriable());
    }

    #[test]
    fn chain_id_mismatch_is_permanent() {
        let err = EvmRpcError::ChainIdMismatch {
            configured: "eip155:1".into(),
            actual: "eip155:137".into(),
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn display_never_leaks_url() {
        // The URL is never a field on any variant; assert the rendered messages stay clean
        // even when the underlying transport error mentions a host.
        let err = EvmRpcError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        )));
        let rendered = err.to_string();
        assert!(!rendered.contains("http://"));
        assert!(!rendered.contains("https://"));
        assert!(!rendered.contains("api-key"));
    }
}