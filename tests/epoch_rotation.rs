use std::num::NonZeroU16;

use guac::{
    Anchor, AnchorSet, Client, Endorsement, EndorsementPolicy, Error, GrantStep, IssuanceInput,
    Moderator, ModeratorConfig, storage::MemoryStore,
};

const ENDPOINT: &str = "https://moderator.example/issue";

fn endorse(anchor: &Anchor) -> Endorsement {
    let store = MemoryStore::default();
    let (request, pending) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MIN,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    let response = anchor
        .grant(&store, &request, 0, 30, NonZeroU16::MIN)
        .unwrap();
    let GrantStep::Continue { request, pending } = pending.advance(&response).unwrap() else {
        panic!("challenge expected")
    };
    let response = anchor
        .grant(&store, &request, 0, 30, NonZeroU16::MIN)
        .unwrap();
    let GrantStep::Complete(mut endorsements) = pending.advance(&response).unwrap() else {
        panic!("endorsement expected")
    };
    endorsements.pop().unwrap()
}

/// What a client builds from one `endorsements` entry of the directory.
fn client_config(moderator: &Moderator, set: &AnchorSet) -> ModeratorConfig {
    let config = moderator.configuration();
    ModeratorConfig::new(
        ENDPOINT,
        &config.public_key(),
        config.balance_bits(),
        config.credential_context().to_vec(),
        EndorsementPolicy::Required(set.clone()),
        60,
    )
    .unwrap()
}

#[test]
fn previous_epoch_endorsements_redeem_during_rotation() {
    let old = Anchor::generate(b"day-1".to_vec()).unwrap();
    let new = Anchor::generate(b"day-2".to_vec()).unwrap();
    let old_set = AnchorSet::new(&[old.configuration().clone()]).unwrap();
    let new_set = AnchorSet::new(&[new.configuration().clone()]).unwrap();
    let only_new = Moderator::generate(
        ENDPOINT,
        4,
        b"ctx".to_vec(),
        EndorsementPolicy::Required(new_set.clone()),
        60,
    )
    .unwrap();
    let secret = only_new.to_secret_bytes();
    let moderator = Moderator::from_secret(
        &secret,
        ENDPOINT,
        4,
        b"ctx".to_vec(),
        EndorsementPolicy::Required(new_set.clone()),
        60,
    )
    .unwrap();
    // Populate the challenge cache before changing the accepted policy.
    let before_rotation = moderator.redemption_challenge(0).unwrap();
    let moderator = moderator.accept_previous(old_set.clone()).unwrap();
    assert_ne!(before_rotation, moderator.redemption_challenge(0).unwrap());
    // Challenges bind every accepted set.
    assert_ne!(
        moderator.redemption_challenge(0).unwrap(),
        only_new.redemption_challenge(0).unwrap()
    );
    let store = MemoryStore::default();
    for (anchor, set, epoch) in [(&old, &old_set, b"day-1"), (&new, &new_set, b"day-2")] {
        let challenge = moderator.redemption_challenge(0).unwrap();
        let (request, _) = Client
            .request_credential(
                IssuanceInput::Endorsement(endorse(anchor)),
                &client_config(&moderator, set),
                &challenge,
            )
            .unwrap();
        let issuance = moderator.prepare_issuance(&request, 8, 0).unwrap();
        assert_eq!(issuance.epoch(), Some(&epoch[..]));
        assert!(moderator.issue(&store, &request, 8, 0).is_ok());
        assert!(matches!(
            moderator.issue(&store, &request, 8, 0),
            Err(Error::Replay)
        ));
    }

    // Without the previous set, a previous-epoch endorsement is rejected.
    let challenge = only_new.redemption_challenge(0).unwrap();
    let (request, _) = Client
        .request_credential(
            IssuanceInput::Endorsement(endorse(&old)),
            &client_config(&only_new, &old_set),
            &challenge,
        )
        .unwrap();
    assert!(only_new.prepare_issuance(&request, 8, 0).is_err());
}

#[test]
fn previous_set_needs_another_epoch_and_a_required_policy() {
    let set = AnchorSet::new(&[Anchor::generate(b"day-1".to_vec())
        .unwrap()
        .configuration()
        .clone()])
    .unwrap();
    let make = |policy| Moderator::generate(ENDPOINT, 4, b"ctx".to_vec(), policy, 60).unwrap();
    assert!(matches!(
        make(EndorsementPolicy::Required(set.clone())).accept_previous(set.clone()),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        make(EndorsementPolicy::NotRequired).accept_previous(set),
        Err(Error::Configuration(_))
    ));
}
