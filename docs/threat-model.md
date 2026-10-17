# octo Threat Model

> **Honest scope.** No system is "safe against all hacks." This document enumerates the attack
> classes that actually apply to octo's architecture, the concrete defense for each, and the step
> that enforces it. It is a living document — every new feature must say which of these it touches.

## What octo is (for threat-modeling)

octo is a **non-custodial backend service**. A user's wallet key is generated and held
**client-side** (browser/SDK); the server stores only the public account and an opaque backup
blob the client encrypted under the user's password. The server **cannot sign for a user wallet
and cannot decrypt that blob.** It validates client-signed transactions and relays them.

The one exception — and it is the important one for this document — is the per-wallet **gas
tank**: a separate, server-held account carrying *fee float only*, used to sign fee-bump
envelopes for gas sponsorship. That is the sole plaintext key material on the server, and its
worst-case exposure is the gas budget, never customer balances.

octo is **not** a smart-contract system. Therefore the famous web3 exploit classes that assume
on-chain contracts **do not apply**:

| Classic web3 hack | Applies to octo? | Why |
|---|---|---|
| Reentrancy, delegatecall, proxy bugs | ❌ | No smart contracts. We send native Stellar payment ops. |
| Flash-loan / oracle manipulation | ❌ | We don't price or lend. |
| Bridge / cross-chain exploits | ❌ (MVP) | No bridging in the MVP. |
| `tx.origin`, integer overflow in Solidity | ❌ | Not Solidity. Rust + checked arithmetic. |
| Approval / `permit` phishing | ❌ | No ERC-20 allowances on Stellar. |

octo's **real** threat surface is the **submit path** (validating client-signed transactions
before relaying them), the **gas-tank key**, **deposit accounting**, and ordinary web2 backend
security. Note what moved off this list: "an attacker steals the user seed from the server" is no
longer a threat, because there is no such seed to steal. That single change removes the category
responsible for the largest share of real-world crypto theft.

---

## Threat classes that DO apply, and our defenses

### A. Key & seed compromise  *(highest severity — 44% of 2024 crypto theft was key compromise)*
| Threat | Defense | Step |
|---|---|---|
| **User seed stolen from the server** | **Structurally impossible: the server never has it.** Keys are generated client-side; only the public account is transmitted. A total compromise of the API, DB and backups yields no user key | cutover |
| User key backup stolen from DB dump / backup | `encrypted_backup` is ciphertext the **client** produced under the user's password (PBKDF2→AES-256-GCM in the browser). octo stores it opaquely and holds no password or key to open it | cutover |
| Gas-tank seed stolen from DB dump / backup | Seed stored **AES-256-GCM encrypted**, random nonce+salt; master key from KMS/secret-manager, never in the DB or repo. **Loss is bounded by the gas budget — no customer funds** | 3, 5 |
| Seed/keys leaked via logs, crash dumps, swap | Secrets live only in `wallet-core`; `Zeroizing` wrappers wipe seed & derived keys on drop; `Debug` never prints secret bytes; `unwrap`/`panic` denied by clippy there | 3, 4 |
| Master key compromise | KMS-held key; zero-downtime rotation via `sealed_scheme` + `bin/migrate-keys`; defense-in-depth so DB-only compromise is insufficient. Only gas tanks are affected | 3, rotation |
| Weak randomness in key/nonce generation | Use `OsRng` (CSPRNG) only; never `rand::thread_rng` seeded predictably for key material; test that two seals of same plaintext differ | 3, 4 |
| Derived key reused across contexts | One derivation path per account; keys are ephemeral and zeroized | 4 |
| **User loses password *and* recovery phrase** | **Accepted, unavoidable consequence of non-custody:** octo cannot reset or recover the wallet. This is a deliberate trade — the same property that makes a server breach harmless makes recovery impossible without the user's own secrets. Must be stated plainly in any product UI | product |

### B. Submit-path abuse  *(the relay must not become a "sign anything" oracle)*
| Threat | Defense | Step |
|---|---|---|
| Attacker gets octo to sign an arbitrary/malicious tx **for a user wallet** | **No key exists server-side to coerce.** The submit path only *validates and relays* — it never signs or alters a user transaction | cutover |
| Malicious/forged XDR relayed via `submit-signed` | Validated before relay: must be a v1 `Tx` envelope, carry ≥1 signature, have **source account == this wallet**, and use only allowlisted operations (payment / path-payment / change-trust). Tampering invalidates the client's signature, so Horizon rejects it | 10 |
| Confused-deputy: API caller moves others' funds | The relayed transaction must be signed by the wallet's own key, which the caller does not have. Wallet routes are additionally scoped to the authenticated tenant | 6, 10 |
| Fee/op injection (set-options, merge-account) | Operation-type allowlist rejects `ACCOUNT_MERGE`, `SET_OPTIONS`, and anything else outside the allowlist, on both the submit and sponsor paths | 10 |
| Fee-bump abuse (sponsorship) | The gas tank signs **only the outer fee-bump envelope**; the user's inner tx is passed through untouched. Self-sponsorship rejected. Per-tx fee cap + daily budget reserved atomically under a per-wallet advisory lock (a plain conditional insert raced under READ COMMITTED and over-spent) | sponsorship |

### C. Deposit accounting attacks  *(how exchanges actually get double-spent)*
| Threat | Defense | Step |
|---|---|---|
| **Double-credit on failed/reorged tx** (the Mt. Gox class) | Only credit deposits with `successful == true` from Horizon; key off the **immutable tx hash + operation id**; idempotent insert (unique constraint) so replays can't double-credit | 8 |
| **Memo-less / wrong-memo deposit** misattribution | Attribute strictly by muxed id **or** a valid numeric memo id that maps to a known address; unmatched deposits go to a **quarantine/unattributed** state, never auto-credited to a guess | 8 |
| Replayed Horizon events | Cursor is monotonic + dedup by tx hash; reprocessing the same payment is a no-op | 8 |
| Spoofed asset / fake token deposit | Credit only **whitelisted assets** (issuer + code must match an enabled asset); ignore unknown trustlines/tokens | 8, later (asset mgmt) |
| Claimable-balance side-channel | Treat claimable balances explicitly; do not credit until claimed into the master under our control | 8 (documented), later |
| Dust / griefing to inflate accounting | Minimum-amount thresholds; amounts stored as exact integers (stroops), never floats | 8 |

### D. Outbound transfer attacks
> Since the cutover these are largely enforced **by Stellar itself**, not by octo — the client
> signs over the exact destination, amount and sequence number, so the network rejects anything
> octo could alter in transit.

| Threat | Defense | Step |
|---|---|---|
| Double-spend via retried request | The signed transaction pins a **sequence number**; Stellar accepts it at most once. A replayed relay of the same signed XDR is rejected on-chain (`tx_bad_seq`) | protocol |
| Race / TOCTOU on balance | Not octo's to arbitrate: the ledger enforces sufficient balance atomically at apply time (`op_underfunded`) | protocol |
| Amount precision bug (float rounding) | All amounts are integer **stroops** end-to-end; convert at the edge only | 4, 10 |
| Destination tampering in transit | TLS everywhere — **and** the destination is inside the client's signature, so any modification by octo or a MITM invalidates the transaction | 10 |
| Sponsored fee double-charge | Sponsorship dedups on the **inner transaction hash** (unique index → `409`), so the same user tx cannot be fee-bumped twice out of the budget | sponsorship |

### E. Web2 backend surface  *(the unglamorous majority of real breaches)*
| Threat | Defense | Step |
|---|---|---|
| SQL injection | `sqlx` parameterized queries only; no string-built SQL. Blast radius limited by a non-owner runtime role with DML only ([postgres-roles.md](postgres-roles.md)) | 5 |
| AuthN/AuthZ bypass | Dashboard JWT **or** per-wallet API key, with per-route authorization. Sensitive actions (gas-tank provisioning, key-backup read, API-key management) require a JWT and reject API keys. Key-backup reads are rate-limited per user (5/hour) and refuse to serve without writing an audit row | 6 |
| Stolen session token stays valid | Tokens carry a unique `jti`; `logout` **and** `refresh` deny-list the presented token, and every authenticated request checks the deny-list. (Refresh previously re-issued without revoking, and could even return a byte-identical token) | 6 |
| SSRF via webhook/Horizon URLs | `is_safe_url` blocks loopback, private, link-local and carrier-grade-NAT targets — IPv4 **and bracketed IPv6** (a naive `:`-split previously let `[fe80::1]` through) | 9 |
| Webhook forgery / tampering | Outbound webhooks **HMAC-SHA256 signed**; consumers verify. Inbound (if any) verified | 9 |
| Replay of API requests | TLS; mutating on-chain actions are pinned by the signed transaction's sequence number, so a replay is rejected on-chain | 10 |
| Secrets in env/CI logs | `.env` git-ignored; CI uses masked secrets; no secret echoed in logs | 2 ✓ |
| Dependency supply-chain (malicious/yanked crate) | `cargo-deny` (advisories + licenses + yanked) in CI; pinned `Cargo.lock`; MSRV-locked tree | 2 ✓ |
| DoS / resource exhaustion | Request limits, timeouts, connection pool caps; pagination bounds | 6, 11 |
| Information leak in errors | Typed errors; no internal detail or secret in API responses | 5, 6 |

### F. Operational / process
| Threat | Defense | Step |
|---|---|---|
| Unsafe Rust memory bugs | `#![forbid(unsafe_code)]` in every crate (already set) | 2 ✓ |
| Panics that crash or leak | `clippy::unwrap_used`/`expect_used` denied in `wallet-core`; errors propagated | 3, 4 |
| No audit trail | Append-only transaction + webhook-delivery logs; `audit_logs` UPDATE/DELETE/TRUNCATE blocked by DB triggers (`0026`) | 5, 9 |
| Wrong master key / broken RNG discovered only at first signature | Startup self-test (`octo_api::self_test`): canary seal/open + RNG sanity per key, then opens the newest stored sealed row; any failure aborts boot | 4 |
| Disaster recovery (user wallet) | **The user's responsibility, by design.** Recovery is via their BIP39 mnemonic, or the password-encrypted backup blob octo stores but cannot read. octo has no ability to recover a wallet whose owner has lost both | cutover |
| Disaster recovery (gas tank) | Gas-tank seeds are server-held and covered by DB backup + master-key rotation (`bin/migrate-keys`) | rotation |
| Schema migrations silently not applied | sqlx keys migrations by version number, so two files sharing a version means only one ever runs. A test pins the exact applied version set — this had already happened five times before it was caught | 5 |

---

## Enforced continuously (CI gates)
- `cargo-deny` — advisories, yanked crates, license policy.
- `cargo clippy --all-targets -D warnings` — plus secret-safety lints in `wallet-core`/`crypto`.
- `cargo test --workspace` — including the OpenAPI **drift test**, which validates live responses
  against `docs/openapi.yaml` so the spec cannot silently diverge from the code.
- Tests must include **negative** cases (tamper, replay, wrong-asset, double-spend).
- (Planned) `cargo audit`, secret-scanning, and a fuzz target for derivation/decode.

> **A CI gate that cannot start is not a gate.** These commands are correct, but a dev-dependency
> was committed to `Cargo.lock` at a version requiring a newer Rust than `rust-toolchain.toml`
> pins (`wiremock 0.6.5` needs edition2024 / 1.85; the toolchain is 1.84.1). With `--locked`,
> cargo fails at the *dependency-download* step — before compiling anything — so clippy and the
> test suite never executed, and a series of merges landed with a test suite that had never been
> run. Treat "CI failed to resolve dependencies" as a **red** result, never as infrastructure
> noise to be retried past.

## Known limitations (by design)
- **Browser-held keys shift risk to the client.** Removing the server-side key removes the
  server as a honeypot, but a compromised client (XSS, malicious extension, malware) can reach
  the key at unlock time. Encryption at rest does not help there — mitigation is a strict CSP,
  dependency hygiene, and eventually hardware-wallet signing.
- **Unrecoverable by design.** If a user loses both password and recovery phrase, the funds are
  gone; octo cannot help. This must be said plainly in product UI, not buried.
- **Gas tank remains a hot key** (online, encrypted + zeroized + op-allowlisted). Exposure is
  bounded by the gas budget; MPC/HSM for this key is a later phase.

> If you add a feature, add its row(s) above and the test that proves the defense.
