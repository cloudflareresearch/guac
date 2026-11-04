# 🥑 guac --- a MOLE implementation

Rust implementation of MOLE (Moderation of unLinkable Endorsements) [architecture](https://datatracker.ietf.org/doc/draft-jms-mole-architecture/), [protocol](https://datatracker.ietf.org/doc/draft-jms-mole-transport/), and [HTTP transport](https://datatracker.ietf.org/doc/draft-jms-mole-http-transport/).

Anchors vouch for a Client with [EC-IHAT](https://datatracker.ietf.org/doc/draft-ladd-mole-ec-ihat/) endorsements. Moderators turn them into [EC-ACT](https://datatracker.ietf.org/doc/draft-schlesinger-mole-ec-act/) credit tokens, which Clients spend without being linked across requests.

> [!WARNING]
> Experimental. APIs and wire formats will change as the specifications evolve.

## Features

- Client, Anchor and Moderator roles
- Credentials spend credits, get change back, and recover a lost update
- Bring your own I/O: guac handles bytes, you pick the HTTP client, storage and clock
- Browser client through wasm-bindgen (`browser` feature)

## Installation

```toml
[dependencies]
guac = { git = "https://github.com/cloudflareresearch/guac", rev = "<commit>" }
```

Set `rev` to a commit hash. The API is unstable, so don't track a branch.

## Usage

A Moderator issues a credential with 8 credits to a Client that needs no endorsement. The Client spends 2, and gets 1 back.

```rust
use guac::{
    Client, EndorsementPolicy, IssuanceInput, Moderator, PresentationOutcome, UpdatePolicy,
    storage::MemoryStore,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client;
    let moderator = Moderator::generate(
        "https://moderator.example/",
        4,                    // balance bits
        b"demo-1".to_vec(),   // credential context
        EndorsementPolicy::NotRequired,
        60,                   // update retention, seconds
    )?;
    let store = MemoryStore::default();

    // Issuance: 8 credits.
    let challenge = moderator.redemption_challenge(0)?;
    let (request, pending) = client.request_credential(
        IssuanceInput::WithoutEndorsement,
        moderator.configuration(),
        &challenge,
    )?;
    let response = moderator.issue(&store, &request, 8, 0)?;
    let credential = pending.finish(&response)?;

    // Presentation: cost 2, bound to the protected request.
    let challenge = moderator.presentation_challenge(2, 0, b"POST /op", 0)?;
    let pending = client.present(credential, &challenge)?;
    let result = moderator.process(
        &store,
        pending.presentation(),
        2,
        0,
        b"POST /op",
        UpdatePolicy::ReturnCredits(1),
        0,
    )?;
    if let PresentationOutcome::Accepted(_) = &result {
        // Perform the protected operation. `Recovered` never authorizes it.
    }
    let _credential = pending.finish(result.update())?;
    Ok(())
}
```

[examples/flow.rs](examples/flow.rs) adds an Anchor and update recovery: `cargo run --example flow`.

Endorsement grants require a `RedemptionScope::for_moderator_domain("moderator.example")`.
EC-IHAT binds this scope during the grant; redemption checks the Moderator endpoint's domain.
The experimental context encoding scopes by domain only, not port, path, key, or policy.
Use ASCII DNS names (punycode for international names); IP endpoints cannot redeem scoped endorsements.
This breaks the previous `start_grant` / browser `startGrant` APIs and invalidates older
endorsements and pending grants. Credential storage is unchanged.

### CLI

Install from the checkout with `cargo install --path cli --locked`. With an Anchor, Moderator and protected endpoint running:

```sh
guac anchor add my-anchor https://anchor.example/config
guac moderator add my-site https://moderator.example/config
guac endorsement request --anchor my-anchor --count 3
# Use one of the endorsement IDs printed above.
guac credential issue --moderator my-site --endorsement <endorsement-id> --as my-site-credential
guac curl --credential my-site-credential -- -X POST https://api.example/counter
```

The CLI saves client state locally. You can run `guac --help` to learn more.

## Embedding guac

The library leaves storage to you. We provide `MemoryStore` for testing and examples.

### Running an Anchor or Moderator

Implement [`GrantStore`](src/storage.rs) for an Anchor and [`Store`](src/storage.rs) for a Moderator. Storage must be durable and shared by all servers using the same keys and context. Both require atomic insert-if-absent. `GrantStore` also requires an atomic take: replace the pending session with a consumed marker until expiry, even if the grant response fails. Reusing that session can leak the Anchor key.

`Anchor::to_secret_bytes` exports the 48-byte EC-IHAT key seed and `Anchor::from_secret` restores from it; the Moderator secret stays a 32-byte scalar. Anchor secrets saved by earlier revisions were 32-byte scalars, which EC-IHAT can no longer import: generate a new Anchor key, publish its configuration, and expect endorsements under the old key to stop redeeming.

### Persisting a client

Credentials and endorsements are single-use. Before sending a request, save its pending state in the same transaction that removes what it replaces. Secret exports are zeroizing buffers; encrypt them at rest where appropriate.

```rust,ignore
let pending = client.present(credential, &challenge)?; // credential is now spent

// One transaction: delete the old credential row, insert the pending row.
db.replace("credential", "pending", &pending.to_storage_bytes())?;

let response = send(pending.presentation()); // only after the write
let credential = pending.finish(response.update())?;

db.replace("pending", "credential", &credential.to_storage_bytes())?;
```

## Security

This code has not been audited.

## License

[Apache-2.0](./LICENSE).
