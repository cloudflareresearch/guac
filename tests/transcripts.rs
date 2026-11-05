mod support;

use guac::{
    AnchorConfig, AnchorSet, Client, Credential, CredentialOutcome, Endorsement, EndorsementPolicy,
    Error, IssuanceInput, Moderator, ModeratorConfig, PendingIssuance, PendingPresentation,
    PresentationOutcome, UpdatePolicy,
    http::{Authorization, Challenge},
    protocol::{
        CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
        CredentialUpdate, EndorsementRequest, EndorsementResponse, ModeratorChallenge,
        RecoveryHandle,
    },
    storage::{MemoryStore, PresentationRecord, Spent, Store},
};

fn corpus() -> support::Corpus {
    serde_json::from_str(include_str!("vectors/transcripts.json")).expect("vector corpus")
}

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("hex bytes")
}
fn array<const N: usize>(hex: &str) -> [u8; N] {
    bytes(hex).try_into().expect("fixed length")
}

fn configuration(case: &support::Transcript) -> ModeratorConfig {
    let endorsements = if case.anchors.is_empty() {
        EndorsementPolicy::NotRequired
    } else {
        let anchors: Vec<_> = case
            .anchors
            .iter()
            .map(|anchor| {
                AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch)).unwrap()
            })
            .collect();
        EndorsementPolicy::Required(AnchorSet::new(&anchors).unwrap())
    };
    ModeratorConfig::new(
        &case.endpoint,
        &array(&case.moderator_public),
        case.balance_bits,
        bytes(&case.credential_context),
        endorsements,
        case.retention_seconds.parse().unwrap(),
    )
    .unwrap()
}

fn redemption(case: &support::Transcript) -> ModeratorChallenge {
    match Challenge::parse([case.redemption_challenge.as_str()]).as_slice() {
        [Challenge::Redeem(challenge)] => challenge.clone(),
        _ => panic!("redemption challenge"),
    }
}

fn issuance(case: &support::Transcript) -> CredentialRequest {
    match Authorization::parse(&case.issuance_request).unwrap() {
        Some(Authorization::Issue(request)) => request,
        _ => panic!("issuance request"),
    }
}

fn setup(case: &support::Transcript) -> (Moderator, MemoryStore) {
    let moderator = Moderator::new(&array(&case.moderator_secret), configuration(case)).unwrap();
    (moderator, MemoryStore::default())
}

const OPERATION: &[u8] = b"operation-1";

#[test]
fn checked_in_transcripts_verify_and_finalize() {
    let corpus = corpus();
    assert_eq!(corpus.version, 2);
    assert_eq!(corpus.act_revision, support::ACT_REV);
    assert_eq!(corpus.ihat_revision, support::IHAT_REV);
    for case in corpus.cases {
        let (moderator, store) = setup(&case);
        for (request, response) in &case.grant_exchanges {
            assert_eq!(
                EndorsementRequest::from_bytes(&bytes(request))
                    .unwrap()
                    .to_bytes(),
                bytes(request)
            );
            assert_eq!(
                EndorsementResponse::from_bytes(&bytes(response))
                    .unwrap()
                    .to_bytes(),
                bytes(response)
            );
        }
        if let Some(endorsement) = &case.endorsement_storage {
            let valid_anchors = case
                .anchors
                .iter()
                .filter(|anchor| {
                    let config =
                        AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch))
                            .unwrap();
                    Endorsement::from_storage_bytes(&bytes(endorsement), &config).is_ok()
                })
                .count();
            assert_eq!(valid_anchors, 1);
        }
        let config = moderator.configuration();
        let params: act::Params = act::Params::new(case.balance_bits).unwrap();
        let public_key: act::PublicKey =
            act::PublicKey::from_bytes(&array(&case.moderator_public)).unwrap();
        let mut context = bytes(&case.credential_context);
        context.push(case.balance_bits);
        let raw_state =
            act::ClientIssuanceState::from_bytes(&params, &bytes(&case.issuance_state_raw))
                .unwrap();
        let response_bytes = bytes(&case.issuance_response);
        let raw_response = act::IssueResponseMessage::from_bytes(&params, &response_bytes).unwrap();
        let raw_credential =
            act::finalize_issue(&params, &public_key, &context, raw_state, &raw_response).unwrap();
        assert_eq!(*raw_credential.to_bytes(), bytes(&case.credential_raw));
        let challenge = redemption(&case);
        assert_eq!(
            Challenge::Redeem(challenge.clone()).to_string(),
            case.redemption_challenge
        );
        let request = issuance(&case);
        assert_eq!(
            Authorization::Issue(request.clone()).to_string(),
            case.issuance_request
        );
        let stored_response =
            CredentialResponse::from_bytes(&bytes(&case.issuance_response)).unwrap();
        assert_eq!(stored_response.to_bytes(), bytes(&case.issuance_response));
        let issuance =
            PendingIssuance::from_storage_bytes(&bytes(&case.issuance_state), config).unwrap();
        assert_eq!(issuance.finish(&stored_response).unwrap().balance(), 8);
        let response = moderator.issue(&store, &request, 8, 100).unwrap();
        let issuance =
            PendingIssuance::from_storage_bytes(&bytes(&case.issuance_state), config).unwrap();
        assert_eq!(issuance.finish(&response).unwrap().balance(), 8);
        let repeated = moderator.issue(&store, &request, 8, 100);
        if case.anchors.is_empty() {
            assert!(repeated.is_ok());
        } else {
            assert!(matches!(repeated, Err(Error::Replay)));
        }
        let credential =
            Credential::from_storage_bytes(&bytes(&case.credential_storage), config).unwrap();
        assert_eq!(credential.balance(), 8);
        let pending =
            PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), config)
                .unwrap();
        assert_eq!(pending.presentation().to_bytes(), bytes(&case.presentation));
        let update = CredentialUpdate::from_bytes(&bytes(&case.update)).unwrap();
        assert_eq!(update.to_bytes(), bytes(&case.update));
        if let Some(balance) = &case.expected_balance {
            let raw_state =
                act::ClientSpendState::from_bytes(&params, &bytes(&case.presentation_state_raw))
                    .unwrap();
            let update_bytes = bytes(&case.update);
            let raw_update = act::RefundMessage::from_bytes(&params, &update_bytes).unwrap();
            let raw_credential =
                act::finalize_refund(&params, &public_key, &context, raw_state, &raw_update)
                    .unwrap();
            assert_eq!(raw_credential.balance().to_string(), *balance);
        }
        match pending.finish(&update).unwrap() {
            CredentialOutcome::Replaced(credential) => assert_eq!(
                Some(credential.balance().to_string()),
                case.expected_balance
            ),
            CredentialOutcome::Consumed => assert!(case.expected_balance.is_none()),
        }
        let presentation_challenge =
            CredentialChallenge::from_bytes(&bytes(&case.presentation_challenge)).unwrap();
        assert_eq!(
            presentation_challenge.to_bytes(),
            bytes(&case.presentation_challenge)
        );
        // Issue exactly the captured challenge: its encoding defines the proof context.
        let issued = moderator
            .presentation_challenge(2, 1, OPERATION, 100)
            .unwrap();
        assert_eq!(issued, presentation_challenge);
        let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
        let policy = if case.expected_balance.is_some() {
            UpdatePolicy::ReturnCredits(1)
        } else {
            UpdatePolicy::Consume
        };
        let result = moderator
            .process(&store, &presentation, 2, 1, OPERATION, policy, 100)
            .unwrap();
        assert!(matches!(result, PresentationOutcome::Accepted(_)));
        // The challenge has expired; recovery answers from the record.
        let recovered = moderator
            .process(
                &store,
                &presentation,
                2,
                1,
                OPERATION,
                UpdatePolicy::Consume,
                159,
            )
            .unwrap();
        assert!(matches!(recovered, PresentationOutcome::Recovered(_)));
        assert_eq!(result.update(), recovered.update());
        let pending =
            PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), config)
                .unwrap();
        match pending.finish(recovered.update()).unwrap() {
            CredentialOutcome::Replaced(credential) => assert_eq!(
                Some(credential.balance().to_string()),
                case.expected_balance
            ),
            CredentialOutcome::Consumed => assert!(case.expected_balance.is_none()),
        }
    }
}

#[test]
#[cfg(not(target_os = "emscripten"))]
fn racing_presentations_authorize_once() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    moderator
                        .process(
                            &store,
                            &presentation,
                            2,
                            1,
                            OPERATION,
                            UpdatePolicy::ReturnCredits(1),
                            100,
                        )
                        .unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let accepted = results
        .iter()
        .filter(|result| matches!(result, PresentationOutcome::Accepted(_)))
        .count();
    assert_eq!(accepted, 1);
    assert_eq!(results[0].update(), results[1].update());
}

#[test]
fn recovery_survives_store_restart_but_not_retention() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let result = moderator
        .process(
            &store,
            &presentation,
            2,
            1,
            OPERATION,
            UpdatePolicy::ReturnCredits(1),
            100,
        )
        .unwrap();
    let nullifier = moderator.nullifier(&presentation).unwrap();
    let Some(Spent::Retained(stored)) = store.presentation(&nullifier).unwrap() else {
        panic!("retained record");
    };
    let stored = stored.to_bytes();
    let restored = MemoryStore::default();
    let record = PresentationRecord::from_bytes(&stored).unwrap();
    assert!(
        restored
            .insert_presentation(nullifier, &record)
            .unwrap()
            .is_none()
    );
    let process = |now| {
        moderator.process(
            &restored,
            &presentation,
            2,
            1,
            OPERATION,
            UpdatePolicy::Consume,
            now,
        )
    };
    let recovered = process(131).unwrap();
    assert!(matches!(recovered, PresentationOutcome::Recovered(_)));
    assert_eq!(recovered.update(), result.update());
    // Retention ends at 160; the nullifier stays recorded.
    assert!(matches!(process(160), Err(Error::Replay)));
    assert!(matches!(process(1_000), Err(Error::Replay)));
}

#[test]
fn recovery_handle_is_lookup_only() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let config = moderator.configuration();
    let pending =
        PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), config)
            .unwrap();
    let handle = pending.recovery_handle();
    let header = Authorization::Recover(handle).to_string();
    assert_eq!(
        Authorization::parse(&header).unwrap(),
        Some(Authorization::Recover(handle))
    );
    // Nothing recorded: unavailable, and recovery records nothing.
    assert!(matches!(
        moderator.recover(&store, &handle, 100),
        Err(Error::Replay)
    ));
    assert!(store.presentation(&handle.nullifier()).unwrap().is_none());
    let result = moderator
        .process(
            &store,
            pending.presentation(),
            2,
            1,
            OPERATION,
            UpdatePolicy::ReturnCredits(1),
            100,
        )
        .unwrap();
    assert_eq!(
        moderator.recover(&store, &handle, 159).unwrap(),
        *result.update()
    );
    assert!(matches!(
        moderator.recover(&store, &handle, 160),
        Err(Error::Replay)
    ));
    let mut wrong = handle.to_bytes();
    wrong[95] ^= 1;
    let wrong = RecoveryHandle::from_bytes(&wrong).unwrap();
    assert!(matches!(
        moderator.recover(&store, &wrong, 100),
        Err(Error::Replay)
    ));
    let mut foreign = handle.to_bytes();
    foreign[0] ^= 1;
    let foreign = RecoveryHandle::from_bytes(&foreign).unwrap();
    assert!(matches!(
        moderator.recover(&store, &foreign, 100),
        Err(Error::Replay)
    ));
}

#[test]
fn request_bound_challenges_cover_one_to_two_windows() {
    let case = &corpus().cases[2];
    let (moderator, _) = setup(case);
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let verify = |now| {
        moderator.verify(
            &presentation,
            2,
            1,
            OPERATION,
            UpdatePolicy::ReturnCredits(1),
            now,
        )
    };
    // Captured at 100 in window 3; accepted in windows 3 and 4 (90..=149).
    assert!(verify(90).is_ok());
    assert!(verify(149).is_ok());
    assert!(verify(150).is_err());
    assert!(verify(89).is_err());
    assert!(matches!(
        moderator.verify(&presentation, 2, 0, OPERATION, UpdatePolicy::Consume, 100),
        Err(Error::Mismatch)
    ));
}

#[test]
fn redemption_challenges_are_authenticated_and_expire() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let anchors: Vec<_> = case
        .anchors
        .iter()
        .map(|anchor| AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch)).unwrap())
        .collect();
    // Each request redeems the same endorsement; only acceptance records it.
    let request_for = |challenge: &ModeratorChallenge| {
        let endorsement = Endorsement::from_storage_bytes(
            &bytes(case.endorsement_storage.as_ref().unwrap()),
            &anchors[0],
        )
        .unwrap();
        Client
            .request_credential(
                IssuanceInput::Endorsement(endorsement),
                moderator.configuration(),
                challenge,
            )
            .unwrap()
            .0
    };
    let rejected = |result: Result<CredentialResponse, Error>| {
        assert!(matches!(result, Err(Error::Endorsement(_))), "{result:?}");
    };
    let request = issuance(case);
    rejected(moderator.issue(&store, &request, 8, 150));
    let challenge = redemption(case);
    let captured = challenge.payload().to_vec();
    for index in [0, 7, captured.len() - 1] {
        let mut forged = captured.clone();
        forged[index] ^= 1;
        let forged = ModeratorChallenge::from_parts(challenge.endorsement_type(), &forged).unwrap();
        rejected(moderator.issue(&store, &request_for(&forged), 8, 100));
    }
    let other = Moderator::generate(
        &case.endpoint,
        4,
        bytes(&case.credential_context),
        EndorsementPolicy::Required(AnchorSet::new(&anchors).unwrap()),
        60,
    )
    .unwrap();
    let foreign = other.redemption_challenge(100).unwrap();
    assert_ne!(foreign, challenge);
    rejected(moderator.issue(&store, &request_for(&foreign), 8, 100));
    assert!(moderator.issue(&store, &request, 8, 100).is_ok());
}

#[test]
fn invalid_update_preserves_pending_state() {
    let case = &corpus().cases[0];
    let config = configuration(case);
    let pending =
        PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), &config)
            .unwrap();
    let mut corrupt = bytes(&case.update);
    let last = corrupt.last_mut().unwrap();
    *last ^= 1;
    let corrupt = CredentialUpdate::from_bytes(&corrupt).unwrap();
    let failure = pending.finish(&corrupt).unwrap_err();
    assert_eq!(
        failure.pending.presentation().to_bytes(),
        bytes(&case.presentation)
    );
    let valid = CredentialUpdate::from_bytes(&bytes(&case.update)).unwrap();
    assert!(matches!(
        failure.pending.finish(&valid),
        Ok(CredentialOutcome::Replaced(_))
    ));
}

#[test]
fn wrong_binding_and_changed_replay_are_rejected() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let process = |presentation, binding: &[u8]| {
        moderator.process(
            &store,
            presentation,
            2,
            1,
            binding,
            UpdatePolicy::ReturnCredits(1),
            100,
        )
    };
    assert!(process(&presentation, b"another-operation").is_err());
    assert!(process(&presentation, b"").is_err());
    assert!(matches!(
        process(&presentation, OPERATION),
        Ok(PresentationOutcome::Accepted(_))
    ));
    let mut changed = presentation.to_bytes();
    *changed.last_mut().unwrap() ^= 1;
    let changed = CredentialPresentation::from_bytes(&changed).unwrap();
    assert!(process(&changed, OPERATION).is_err());
}

#[test]
fn invalid_issuance_does_not_consume_redemption_challenge() {
    let case = &corpus().cases[2];
    let (moderator, store) = setup(case);
    let valid = issuance(case);
    let mut corrupt = valid.issuance().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let request =
        CredentialRequest::from_parts(valid.endorsement_type(), valid.redemption(), &corrupt)
            .unwrap();
    assert!(moderator.issue(&store, &request, 8, 100).is_err());
    let request = issuance(case);
    assert!(moderator.issue(&store, &request, 8, 100).is_ok());
}

#[test]
fn rejected_update_policy_does_not_record_a_spend() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let process = |credits| {
        moderator.process(
            &store,
            &presentation,
            2,
            1,
            OPERATION,
            UpdatePolicy::ReturnCredits(credits),
            100,
        )
    };
    assert!(process(4).is_err());
    assert!(matches!(process(1), Ok(PresentationOutcome::Accepted(_))));
}

#[test]
fn credential_storage_cannot_change_destination_or_context() {
    let case = &corpus().cases[2];
    let config = ModeratorConfig::new(
        "https://other.example/",
        &array(&case.moderator_public),
        4,
        bytes(&case.credential_context),
        EndorsementPolicy::NotRequired,
        60,
    )
    .unwrap();
    assert!(matches!(
        Credential::from_storage_bytes(&bytes(&case.credential_storage), &config),
        Err(Error::Mismatch)
    ));
    let config = ModeratorConfig::new(
        &case.endpoint,
        &array(&case.moderator_public),
        4,
        b"next-context".to_vec(),
        EndorsementPolicy::NotRequired,
        60,
    )
    .unwrap();
    assert!(matches!(
        PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), &config),
        Err(Error::Mismatch)
    ));
}

#[test]
fn endorsement_policy_changes_do_not_change_credential_identity() {
    let case = &corpus().cases[0];
    let config = ModeratorConfig::new(
        &case.endpoint,
        &array(&case.moderator_public),
        4,
        bytes(&case.credential_context),
        EndorsementPolicy::NotRequired,
        120,
    )
    .unwrap();
    assert!(Credential::from_storage_bytes(&bytes(&case.credential_storage), &config).is_ok());
    assert!(
        PendingPresentation::from_storage_bytes(&bytes(&case.pending_presentation), &config)
            .is_ok()
    );
}

#[test]
fn restored_credentials_follow_credit_bounds() {
    let case = &corpus().cases[2];
    let (moderator, _) = setup(case);
    for (cost, allowance) in [(9, 0), (0, 8)] {
        let challenge = moderator
            .presentation_challenge(cost, allowance, b"", 100)
            .unwrap();
        let credential = Credential::from_storage_bytes(
            &bytes(&case.credential_storage),
            moderator.configuration(),
        )
        .unwrap();
        // Rejected locally: typed, and the credential comes back unspent.
        let failure = Client.present(credential, &challenge).unwrap_err();
        assert!(matches!(failure.error, Error::Amount));
        let valid = moderator
            .presentation_challenge(2, 1, OPERATION, 100)
            .unwrap();
        assert!(Client.present(failure.credential, &valid).is_ok());
    }
}

#[test]
fn rejected_request_returns_the_endorsement() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let anchor = &case.anchors[0];
    let config = AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch)).unwrap();
    let endorsement = Endorsement::from_storage_bytes(
        &bytes(case.endorsement_storage.as_ref().unwrap()),
        &config,
    )
    .unwrap();
    let other = Moderator::generate(
        &case.endpoint,
        4,
        bytes(&case.credential_context),
        EndorsementPolicy::NotRequired,
        60,
    )
    .unwrap();
    let wrong = other.redemption_challenge(100).unwrap();
    let failure = Client
        .request_credential(
            IssuanceInput::Endorsement(endorsement),
            moderator.configuration(),
            &wrong,
        )
        .unwrap_err();
    assert!(matches!(failure.error, Error::Mismatch));
    let challenge = moderator.redemption_challenge(100).unwrap();
    let (request, _) = Client
        .request_credential(*failure.input, moderator.configuration(), &challenge)
        .unwrap();
    assert!(moderator.issue(&store, &request, 8, 100).is_ok());
}

#[test]
fn endorsement_replay_is_rejected_even_under_a_fresh_challenge() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let request = issuance(case);
    moderator.issue(&store, &request, 8, 100).unwrap();
    let challenge = moderator.redemption_challenge(120).unwrap();
    let anchor = &case.anchors[0];
    let config = AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch)).unwrap();
    let endorsement = Endorsement::from_storage_bytes(
        &bytes(case.endorsement_storage.as_ref().unwrap()),
        &config,
    )
    .unwrap();
    let (request, _) = Client
        .request_credential(
            IssuanceInput::Endorsement(endorsement),
            moderator.configuration(),
            &challenge,
        )
        .unwrap();
    let issuance = moderator.prepare_issuance(&request, 8, 120).unwrap();
    assert!(issuance.replay_id().is_some());
    assert!(matches!(
        moderator.issue(&store, &request, 8, 120),
        Err(Error::Replay)
    ));
}

#[test]
fn broken_issuance_proof_under_a_valid_endorsement_is_a_credential_error() {
    let case = &corpus().cases[0];
    let (moderator, _) = setup(case);
    let request = issuance(case);
    let mut proof = request.issuance().to_vec();
    *proof.last_mut().unwrap() ^= 1;
    let broken =
        CredentialRequest::from_parts(request.endorsement_type(), request.redemption(), &proof)
            .unwrap();
    for now in [100, 120] {
        let result = moderator.prepare_issuance(&broken, 8, now);
        assert!(matches!(result, Err(Error::Credential(_))), "{now}");
    }
}

#[derive(Default)]
struct FailingStore {
    memory: MemoryStore,
    fail: std::sync::atomic::AtomicBool,
}

impl FailingStore {
    fn check(&self) -> Result<(), Error> {
        if self.fail.swap(false, std::sync::atomic::Ordering::SeqCst) {
            Err(Error::Storage("simulated commit failure".into()))
        } else {
            Ok(())
        }
    }
}

impl Store for FailingStore {
    fn insert_redemption(&self, id: [u8; 32]) -> Result<bool, Error> {
        self.check()?;
        self.memory.insert_redemption(id)
    }
    fn insert_presentation(
        &self,
        nullifier: [u8; 32],
        record: &PresentationRecord,
    ) -> Result<Option<Spent>, Error> {
        self.check()?;
        self.memory.insert_presentation(nullifier, record)
    }
    fn presentation(&self, nullifier: &[u8; 32]) -> Result<Option<Spent>, Error> {
        self.memory.presentation(nullifier)
    }
}

#[test]
fn failed_commits_release_nothing_and_can_be_retried() {
    let case = &corpus().cases[0];
    let (moderator, _) = setup(case);
    let store = FailingStore::default();
    let request = issuance(case);
    store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        moderator.issue(&store, &request, 8, 100),
        Err(Error::Storage(_))
    ));
    assert!(moderator.issue(&store, &request, 8, 100).is_ok());
    let presentation = CredentialPresentation::from_bytes(&bytes(&case.presentation)).unwrap();
    let process = || {
        moderator.process(
            &store,
            &presentation,
            2,
            1,
            OPERATION,
            UpdatePolicy::ReturnCredits(1),
            100,
        )
    };
    store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(process(), Err(Error::Storage(_))));
    assert!(matches!(process(), Ok(PresentationOutcome::Accepted(_))));
}

#[test]
fn redemption_recomputes_windows_and_leaves_unendorsed_limits_to_the_host() {
    let corpus = corpus();
    for case in &corpus.cases[..3] {
        let (moderator, _) = setup(case);
        let challenge = moderator.redemption_challenge(100).unwrap();
        assert_eq!(challenge, moderator.redemption_challenge(119).unwrap());
        assert_ne!(challenge, moderator.redemption_challenge(120).unwrap());
        let request = issuance(case);
        for now in [100, 119, 120, 149] {
            let issuance = moderator.prepare_issuance(&request, 8, now).unwrap();
            assert_eq!(issuance.replay_id().is_none(), case.anchors.is_empty());
        }
        if !case.anchors.is_empty() {
            assert!(moderator.prepare_issuance(&request, 8, 150).is_err());
            assert!(moderator.prepare_issuance(&request, 8, 89).is_err());
        }
    }
    let case = &corpus.cases[2];
    let (moderator, _) = setup(case);
    let store = FailingStore::default();
    store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let challenge = moderator.redemption_challenge(100).unwrap();
    for (endpoint, context) in [
        (
            "https://other.example/issue",
            bytes(&case.credential_context),
        ),
        (case.endpoint.as_str(), b"other-policy".to_vec()),
    ] {
        let other = Moderator::from_secret(
            &array(&case.moderator_secret),
            endpoint,
            case.balance_bits,
            context,
            EndorsementPolicy::NotRequired,
            60,
        )
        .unwrap();
        assert_ne!(challenge, other.redemption_challenge(100).unwrap());
    }
    for _ in 0..2 {
        let (request, pending) = Client
            .request_credential(
                IssuanceInput::WithoutEndorsement,
                moderator.configuration(),
                &challenge,
            )
            .unwrap();
        let response = moderator.issue(&store, &request, 8, 100).unwrap();
        assert_eq!(pending.finish(&response).unwrap().balance(), 8);
    }
    assert!(
        store.fail.load(std::sync::atomic::Ordering::SeqCst),
        "no replay-store calls"
    );
}

#[test]
fn redemption_binds_the_ordered_anchor_set() {
    let case = &corpus().cases[0];
    let (moderator, store) = setup(case);
    let mut anchors: Vec<_> = case
        .anchors
        .iter()
        .map(|anchor| AnchorConfig::new(&array(&anchor.public_key), bytes(&anchor.epoch)).unwrap())
        .collect();
    let endorsement = Endorsement::from_storage_bytes(
        &bytes(case.endorsement_storage.as_ref().unwrap()),
        &anchors[0],
    )
    .unwrap();
    anchors.reverse();
    let config = ModeratorConfig::new(
        &case.endpoint,
        &array(&case.moderator_public),
        4,
        bytes(&case.credential_context),
        EndorsementPolicy::Required(AnchorSet::new(&anchors).unwrap()),
        60,
    )
    .unwrap();
    let challenge = redemption(case);
    let (request, _) = Client
        .request_credential(IssuanceInput::Endorsement(endorsement), &config, &challenge)
        .unwrap();
    assert!(moderator.issue(&store, &request, 8, 100).is_err());
    let valid = issuance(case);
    assert!(moderator.issue(&store, &valid, 8, 100).is_ok());
}
