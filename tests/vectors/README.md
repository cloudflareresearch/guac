# Vectors

`transcripts.json` contains captured MOLE exchanges and synthetic test secrets.
Bytes are hex; credit amounts and times are decimal strings. Challenges are
authenticated under `moderator_secret`: the redemption challenge expires at 130,
and the presentation challenge binds `operation-1` in the window containing 100.
The `*_raw` fields contain ACT's secret state/credential encodings for consumers
that do not implement guac's local storage envelope. Protocol message fields
hold raw type-specific payloads as HTTP carries them, without outer wrappers;
`redemption_challenge` and `issuance_request` are the complete
`WWW-Authenticate` and `Authorization` field values. An empty `update` is a
recorded NoUpdate.

Generate new transcripts explicitly:

```sh
cargo run --example generate_vectors
```

Outputs change because upstream operations use OS randomness. The corpus records
the draft revision and crypto revisions. Tests consume checked-in transcripts rather
than regenerating expected results. EC-IHAT grant messages can be parsed, but
grant finalization is covered by the real Anchor smoke check, which persists and
restores client and server state. The corpus omits those secret continuations.

`tests/encoding.rs` also checks hand-written encodings independently of generation.
