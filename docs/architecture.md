# Architecture

This document records architectural decisions for the Octo Protocol workspace. Each decision is
recorded as a lightweight ADR (Architecture Decision Record) so that the rationale survives the
pull request that introduced it.

---

## ADR-001: EVM key handling crate selection (`alloy-primitives` vs `k256` + `sha3` + `bip32`)

**Status:** Accepted (resolves the crate-selection requirement of #217; binds #218, #225, #226)

**Context**

`crates/evm-core` (`octo-evm-core`) must provide secp256k1 key handling, BIP-32/BIP-44 derivation,
keccak-256 address encoding with EIP-55 checksums, and low-`s` (EIP-2) normalised signing. This
crate handles secret key material and therefore inherits `wallet-core`'s full lint wall and
`zeroize`-on-drop discipline.

Two candidate stacks were evaluated:

1. **`alloy-primitives`** (plus the wider `alloy` family) — the Rust Ethereum ecosystem's
   batteries-included stack. Provides `Address`, `B256`, keccak-256, EIP-55 checksumming, and
   (via `alloy-signer` / `alloy-signer-local`) signing and derivation.
2. **`k256` + `sha3` + `bip32`** — a minimal, composable stack: `k256` (RustCrypto secp256k1),
   `sha3` (RustCrypto keccak-256), and `bip32` (RustCrypto BIP-32 derivation), assembled by us.

**Evaluation criteria**

- **MSRV 1.84.1.** The workspace pins MSRV 1.84.1. The `alloy` family moves quickly and its
  transitive dependency graph has repeatedly raised its MSRV ahead of the workspace pin; adopting
  `alloy-primitives` would either force an MSRV bump or require pinning to an older release that
  drifts from the rest of the ecosystem. The `k256` + `sha3` + `bip32` stack is maintained by
  RustCrypto, whose crates track a conservative MSRV and are already present in the workspace
  dependency graph (via `wallet-core`'s use of RustCrypto primitives).
- **`cargo deny check` (licenses, advisories, bans, sources).** The `alloy` family pulls a large
  transitive graph (including `ruint`, `alloy-rlp`, `alloy-sol-type-parser`, and, for the signer
  crates, `coins-bip39` / `coins-bip32`). Each addition is a new license, advisory, and source
  surface to audit. The `k256` + `sha3` + `bip32` stack is small, already vetted in this
  workspace, and adds no new license classes. `bip32` is dual-licensed MIT/Apache-2.0, matching
  the workspace policy.
- **Secret-material discipline.** We require `zeroize`-on-drop for all secret material and
  constant-time comparison. `k256`'s `SecretKey` and `NonZeroScalar` implement `Zeroize` and
  `ConstantTimeEq` directly, and `bip32`'s extended key types expose the raw scalar for us to
  wrap in `Zeroizing`. `alloy-signer-local`'s key types do not expose the same guarantees at the
  granularity we need, and its `Signer` trait is oriented around signing arbitrary payloads,
  which conflicts with our "no raw-bytes signing oracle" posture (see `wallet-core/src/signer.rs`).
- **Test-vector provenance.** BIP-32's own Test Vectors 1 and 2 are defined against the raw
  BIP-32 algorithm; `bip32` exposes the intermediate extended keys needed to assert against them
  directly. `alloy`'s higher-level derivation wrappers hide those intermediates.

**Decision**

Adopt **`k256` + `sha3` + `bip32`** as the EVM key-handling stack for `octo-evm-core`.

- `k256` for secp256k1 key generation, signing, recovery, and low-`s` normalisation.
- `sha3` for keccak-256 (address derivation and EIP-55 checksumming).
- `bip32` for BIP-32 extended-key derivation, driven by the existing BIP-39 mnemonic type from
  `wallet-core`.

`alloy-primitives` is **rejected** for this crate. It may still be used in non-secret-handling
contexts (e.g. RPC types in a future `evm-rpc` crate) if its MSRV and `cargo deny` profile are
acceptable there, but it must not be the source of key material or signing.

**Consequences**

- **#218** (transaction building / signing) consumes `octo-evm-core`'s typed signing operations
  rather than an `alloy` `Signer`. It must not introduce a raw-bytes signing path.
- **#225** (EVM RPC / provider integration) may use `alloy` types for wire formats, but must
  convert to `octo-evm-core` types at the boundary and must not route key material through
  `alloy`.
- **#226** (EVM integration tests) must pin the same `k256` / `sha3` / `bip32` versions and must
  not add `alloy-signer-local` as a dev-dependency, to keep the `cargo deny` surface identical
  between the crate and its tests.
- Any future proposal to adopt `alloy` for key handling must supersede this ADR and re-run the
  MSRV and `cargo deny` evaluation.

---

## ADR-002: EVM derivation path and its non-hardened-level security consequence

**Status:** Accepted (resolves the derivation-path requirement of #217; binds #220, #224)

**Context**

`octo-wallet-core` derives Stellar keys via SEP-0005 SLIP-0010 **ed25519** at
`m/44'/148'/index'` — every level hardened. EVM uses a different curve (secp256k1), a different
derivation standard (BIP-32/BIP-44), a different coin type (60), and a different address format
(last 20 bytes of keccak-256 of the uncompressed public key, with an EIP-55 mixed-case checksum).

**Decision**

`octo-evm-core` derives EVM keys at:

```
m / 44' / 60' / 0' / 0 / {index}
```

The **purpose**, **coin type**, and **account** levels are hardened (`44'`, `60'`, `0'`). The
**change** and **address index** levels are **non-hardened** (`0`, `{index}`).

This matches the de-facto BIP-44 convention for Ethereum and is what allows xpub-based address
derivation: an extended public key at `m/44'/60'/0'/0` can derive every address index without
access to the private key.

**Security consequence (prominent)**

Because the change and index levels are **non-hardened**, the following holds:

> **A leaked child private key at `m/44'/60'/0'/0/{i}` together with the account xpub at
> `m/44'/60'/0'/0` compromises every sibling key at `m/44'/60'/0'/0/{j}` for all `j`.**

This is a property of BIP-32 non-hardened derivation, not a bug in our implementation. Given a
non-hardened child private key `k_i` and the parent chain code, an attacker can recover the parent
private key `k_par`, and from `k_par` derive every sibling. Hardened levels prevent this because
the chain code is derived from the private key, not the public key.

This is why the Stellar path is all-hardened and the EVM path is not: the EVM ecosystem's tooling
(xpub-based address generation, watch-only wallets) depends on the non-hardened tail, and we accept
the trade-off to remain interoperable.

**Consequences**

- **#220** (EVM account management) must treat the account xpub as **secret-equivalent** for the
  purposes of sibling-key compromise. It must not persist or transmit the xpub alongside any child
  private key, and must document the compromise property in its own API docs.
- **#224** (EVM key backup / recovery) must not export a child private key and the account xpub
  together. If both are needed, the export must be gated behind an explicit, documented warning.
- `octo-evm-core`'s `derive.rs` must document the non-hardened tail and the sibling-compromise
  property at the derivation entry point, so that callers cannot miss it.
- Any future change to harden the change/index levels would break xpub-based derivation and must
  supersede this ADR.

---

## ADR-003: Chain-scoped AAD for sealed key material

**Status:** Accepted (resolves the sealing-context requirement of #217)

**Context**

`octo-evm-core` reuses `octo-crypto` for sealing key material. We must not add a second encryption
scheme. A sealed EVM key must not be openable in a Stellar context, and vice versa.

**Decision**

The `context` AAD string passed to `octo-crypto` is chain-scoped, e.g. `"octo:eip155:1"` for
Ethereum mainnet. Stellar uses its own context string. The AAD is bound into the AEAD, so a
ciphertext sealed under one context fails authentication under another.

**Consequences**

- `octo-evm-core` must never seal or open key material without an explicit chain-scoped context.
- A test in `octo-evm-core` asserts that a seed sealed with an `eip155` context **fails** to open
  with a `stellar` context.
- Any new chain must define its own context string; reusing another chain's context is a bug.
</｜｜DSML｜｜ parameter>

---

## Database access

The server talks to Postgres through `octo-store`. In production it should connect as a
least-privilege runtime role (`octo_app`, `RUN_MIGRATIONS=false`) while a separate migrator role
applies migrations with `octo-server --migrate-only`. Roles, exact grants and the runbook:
[postgres-roles.md](postgres-roles.md).
