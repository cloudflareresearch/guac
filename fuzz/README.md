# Fuzzing

With `cargo-fuzz` and nightly Rust installed:

```sh
cargo +nightly fuzz run grant -- -max_len=131073
cargo +nightly fuzz run http -- -dict=fuzz/http.dict
```

`grant` exercises grant requests, both client response phases, pending-state decoding and endorsement storage.
Includes one byte above the network size cap. Local state is never used to
authorize an operation.

`http` feeds `Authorization`, `WWW-Authenticate` and `Mole-Credential` field
values to their parsers, and checks that whatever parses prints back to the
same value.

Run a short smoke check with `-runs=100`.
