//! Resilient JSON-RPC client for EVM chains.
//!
//! `octo-evm-rpc` is the EVM counterpart to the purpose-built Stellar clients in
//! `crates/ingest/src/horizon.rs` and `crates/api/src/horizon.rs`. It speaks
//! JSON-RPC 2.0 over HTTP and wraps reads in [`octo-resilience`] retry and
//! circuit-breaker machinery.
//!
//! # Submit asymmetry (AD-5)
//!
//! Reads (`eth_call`, `eth_getLogs`, `eth_blockNumber`,
//! `eth_getTransactionReceipt`, ...) are idempotent and therefore safe to retry
//! transparently. `eth_sendRawTransaction` is **not**: a retry after a timeout
//! can double-submit a transaction, and the client cannot distinguish "the node
//! never saw it" from "the node accepted it and the response was lost". The
//! submit path is therefore deliberately excluded from the resilience wrapper —
//! it is issued exactly once and any failure is surfaced to the caller, which
//! owns the reconciliation strategy. See the header comment in
//! `crates/ingest/src/horizon.rs` for the established reasoning.
//!
//! # The JSON-RPC-over-HTTP-200 error trap
//!
//! JSON-RPC 2.0 reports protocol-level failures as an `error` member in an
//! otherwise successful HTTP 200 response. A client that only inspects the HTTP
//! status code will read every failure as success. This crate parses the
//! envelope explicitly and distinguishes three failure classes:
//!
//! * [`EvmRpcError::Transport`] — the request never produced a valid JSON-RPC
//!   response (connection failure, non-2xx status, malformed body, oversized
//!   body).
//! * [`EvmRpcError::JsonRpc`] — a well-formed JSON-RPC `error` object.
//! * [`EvmRpcError::Revert`] — an execution revert, carrying the raw revert
//!   data (encoding varies between providers).
//!
//! # Security
//!
//! RPC URLs frequently embed API keys. This crate never logs the URL. Response
//! bodies are capped at a configurable maximum size so that a malicious or
//! compromised RPC endpoint cannot OOM the worker.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;

pub use client::{
    CallKind, EvmRpcClient, EvmRpcClientConfig, LogFilter, LogEntry, TransactionReceipt,
    DEFAULT_MAX_RESPONSE_BYTES,
};
pub use error::EvmRpcError;

/// Convenience alias for results produced by this crate.
pub type Result<T> = std::result::Result<T, EvmRpcError>;