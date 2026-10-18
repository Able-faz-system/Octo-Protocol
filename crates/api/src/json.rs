//! Lenient JSON body parsing.
//!
//! Endpoints accept an optional JSON body: an **empty** body is treated as `T::default()`, so a
//! `POST` with no body is valid (e.g. `create_wallet` with no options). A present-but-invalid body
//! fails with 400. Implemented as a helper over `Bytes` rather than a custom extractor to avoid
//! `FromRequest` trait-lifetime friction.

use crate::error::ApiError;
use axum::body::Bytes;

/// Parse an optional JSON body: empty → `T::default()`, invalid → 400.
pub fn parse_optional<T>(bytes: &Bytes) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned + Default,
{
    if bytes.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice::<T>(bytes).map_err(|_| ApiError::BadRequest("invalid JSON body".into()))
}

/// PATCH-field deserializer: absent → `None`, `null` → `Some(None)`, value → `Some(Some(v))`.
///
/// Pair with `#[serde(default, deserialize_with = "crate::json::double_option::deserialize")]`
/// so a client can tell "leave unchanged" (omit the field) apart from "clear it" (send `null`).
pub mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(d).map(Some)
    }
}

/// Serialize an `i64` as a JSON **string**.
///
/// For values that can exceed JavaScript's `Number.MAX_SAFE_INTEGER` (9,007,199,254,740,991),
/// a JSON number is lossy: `JSON.parse` rounds it to the nearest float64, silently changing the
/// value. Stellar sequence numbers are already ~1.6e16, so they must cross the wire as strings —
/// which is exactly why Horizon returns them that way too.
///
/// Serialize-only on purpose: the types using this are response bodies, so adding a matching
/// `deserialize` here would just be dead code.
pub mod i64_as_string {
    use serde::Serializer;

    pub fn serialize<S: Serializer>(value: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
}
