use std::num::NonZeroU16;

use guac::{
    Anchor, AnchorSet, Client, CredentialOutcome, EndorsementPolicy, GrantStep, IssuanceInput,
    Moderator, PresentationOutcome, UpdatePolicy, storage::MemoryStore,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client;
    let epoch = b"demo-epoch-1".to_vec();
    let anchor = Anchor::generate(epoch.clone())?;
    let second_anchor = Anchor::generate(epoch)?;
    let anchors = AnchorSet::new(&[
        anchor.configuration().clone(),
        second_anchor.configuration().clone(),
    ])?;
    let moderator = Moderator::generate(
        "https://moderator.example/",
        4,
        b"demo-credits-1".to_vec(),
        EndorsementPolicy::Required(anchors),
        60,
    )?;
    let store = MemoryStore::default();

    // https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-architecture.html#fig-mole-architecture-endorsement
    // Trust establishment is assumed in this in-process example.
    //
    // +--------+                 +--------+
    // | Client |                 | Anchor |
    // +---+----+                 +---+----+
    //     |                          |
    //     |<==Trust Establishment===>|
    //     |                          |
    //     +--- EndorsementRequest -->|
    //     |<-- EndorsementResponse --+
    //     |                          |
    // EndorsementFinalization        |
    //     |                          |
    // `store` also holds the Anchor's grant session between the exchanges.
    let (request, pending) = client.start_grant(anchor.configuration(), NonZeroU16::MIN);
    let response = anchor.grant(&store, &request, 0, 30, NonZeroU16::MIN)?;
    let GrantStep::Continue { request, pending } = pending.advance(&response)? else {
        return Err("grant ended after the commitment".into());
    };
    let response = anchor.grant(&store, &request, 0, 30, NonZeroU16::MIN)?;
    let GrantStep::Complete(mut endorsements) = pending.advance(&response)? else {
        return Err("grant needs another exchange".into());
    };
    let endorsement = endorsements.pop().ok_or("grant produced no endorsement")?;

    // https://moderation-of-unlinkable-endorsements.github.io/internet-drafts/draft-jms-mole-protocols.html#fig-credential-flow
    //
    // +--------+                             +-----------+
    // | Client |                             | Moderator |
    // +---+----+                             +-----+-----+
    //     |                                        |
    //     |<--------- ModeratorChallenge ----------+
    //     +--- Redemption + IssuanceRequest ------>|
    //     |<---------- IssuanceResponse -----------+
    // Finalize                                    |
    //     |                                        |
    let challenge = moderator.redemption_challenge(0)?;
    let (request, pending) = client.request_credential(
        IssuanceInput::Endorsement(endorsement),
        moderator.configuration(),
        &challenge,
    )?;
    let credential = pending.finish(&moderator.issue(&store, &request, 8, 0)?)?;

    // Continuing the same specification figure:
    //
    //     |<-------- CredentialChallenge ----------+
    //     +-------- PresentationAndUpdate -------->|
    //     |<-------------- Update? ----------------+
    // Finalize                                    |
    //     |                                        |
    // The binding identifies the request; the Moderator recomputes it on presentation.
    let binding = b"POST https://moderator.example/counter";
    let challenge = moderator.presentation_challenge(2, 1, binding, 0)?;
    let pending = client.present(credential, &challenge)?;
    // A browser must persist this AND the original HTTP request before sending.
    let stored = pending.to_storage_bytes();
    let result = moderator.process(
        &store,
        pending.presentation(),
        2,
        1,
        binding,
        UpdatePolicy::ReturnCredits(1),
        0,
    )?;
    assert!(matches!(result, PresentationOutcome::Accepted(_)));
    // Perform the protected operation only for Accepted.

    // Simulate a lost response. Recovery succeeds even after challenge expiry.
    let pending =
        guac::PendingPresentation::from_storage_bytes(&stored, moderator.configuration())?;
    let recovered = moderator.process(
        &store,
        pending.presentation(),
        2,
        1,
        binding,
        UpdatePolicy::Consume,
        59,
    )?;
    assert!(matches!(recovered, PresentationOutcome::Recovered(_)));
    match pending.finish(recovered.update())? {
        CredentialOutcome::Replaced(credential) => {
            println!("remaining credits: {}", credential.balance())
        }
        CredentialOutcome::Consumed => println!("credential consumed"),
    }
    Ok(())
}
