# AGENTS.md

Rust implementation of MOLE (Moderation of unLinkable Endorsements): Client,
Anchor and Moderator roles over EC-IHAT and EC-ACT, browser bindings
(wasm-bindgen), and the `guac` CLI. Experimental. Downstream
users pin this crate by Git revision.

## Layout

- `src/`: library. `protocol.rs` message codecs, `client.rs` / `anchor.rs` /
  `moderator.rs` roles, `storage.rs` `Store` / `GrantStore` and local secret-state envelopes,
  `http.rs` HTTP carriage, `browser.rs` wasm-bindgen API (`browser` feature).
- `cli/`: `guac-cli` (binary `guac`). `cli/tests/flow.rs` drives real curl
  against an in-process Anchor and Moderator.
- `tests/`: transcripts, encodings, grant storage, epoch rotation; `tests/browser.cjs` checks the
  Wasm bindings in Node. `tests/vectors/transcripts.json` is checked in.
  `tests/credential_lifecycle.rs` exercises generated end-to-end flows with proptest.
- `fuzz/`: standalone cargo-fuzz targets for grants and HTTP fields; run instructions in `fuzz/README.md`.
- `examples/`: `flow` (full exchange), `generate_vectors`.
- `scripts/emsdk.mjs`: pinned Emscripten for `wasm32-unknown-emscripten`.

## Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo check --target wasm32-unknown-unknown --features browser --locked
wasm-pack build --target nodejs --out-dir target/browser-node --features browser --locked
node tests/browser.cjs
cargo run --locked --example generate_vectors   # only when vectors must change
```

CI (`.github/workflows/ci.yml`) runs the same on pushes to `main` and on pull
requests.

## Constraints

- `#![forbid(unsafe_code)]` stays. No `.unwrap()` outside tests and doctests;
  use `?` or `.expect("why it holds")`.
- Errors are typed (`thiserror`). Callers must be able to tell malformed,
  invalid, expired, replayed and consumed apart; never collapse them into a
  string. Exception: the Moderator recomputes redemption challenges from the
  time window, so a stale challenge surfaces as `Error::Endorsement`.
- Fail closed: any parse, verification or storage failure rejects. A
  `Recovered` presentation never authorizes the protected operation.
- Credentials, endorsements and pending states are single-use: not `Clone`,
  consumed by successful use. Hold secret bytes in `Zeroizing`. Keep both
  properties when adding types.
- `GrantStore` must be shared by every grant server and take each session
  atomically, at most once; a failed grant response still consumes it.
- Bring your own I/O: no HTTP client, clock, RNG policy or storage backend in
  the library. Times are Unix seconds passed in by the caller.
- Crypto: only SHA-256, HMAC-SHA-256 and the OS CSPRNG via `getrandom`. Never hand-roll primitives; protocol crypto comes
  from the pinned `act-rs` / `ihat-rs` revisions. Bumping them is its own
  change: regenerate vectors.
- Do not claim FIPS compliance or swap cryptographic backends without review.
- Wire formats follow the MOLE drafts. Raise deviations upstream.
- Untrusted bytes enter through `protocol.rs` and `http.rs` codecs. Parsers
  are fuzzed; add a `cargo-fuzz` target before widening them.
- Tests consume checked-in vectors; never regenerate expected results to make a
  test pass. `tests/encoding.rs` holds hand-written encodings.
- Keep `Cargo.lock` committed and builds `--locked`. New dependencies need a
  reason; prefer what is already in the tree.
- Re-export dependency crates whose types appear in the public Rust API.
- The `browser` feature must keep building for `wasm32-unknown-unknown`, and the
  library for `wasm32-unknown-emscripten`, which Cloudflare Workers need.
  Don't add dependencies that break either target.
- Public API changes are breaking for downstream users pinning a `rev`; call
  them out in the change description.
- No secrets, tokens or real keys in the repo. `transcripts.json` holds
  synthetic test secrets only.
- AI-generated changes need human review before merge. Keep this file current.
