#![cfg(not(target_family = "wasm"))]

use std::num::NonZeroU16;

use guac::{
    Anchor, AnchorSet, Client, Credential, CredentialOutcome, EndorsementPolicy, Error, GrantStep,
    IssuanceInput, Moderator, PendingPresentation, PresentationOutcome, UpdatePolicy,
    protocol::{CredentialPresentation, CredentialResponse, CredentialUpdate},
    storage::MemoryStore,
};
use proptest::prelude::*;

proptest! {
    // Real proofs dominate runtime; PROPTEST_CASES can increase this locally.
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn grant_issue_spend_recover_and_consume(
        anchor_count in 0usize..=3,
        anchor_index in any::<usize>(),
        epoch in prop::collection::vec(any::<u8>(), 1..65),
        context in prop::collection::vec(any::<u8>(), 0..65),
        bits in 1u8..=16,
        initial in any::<u16>(),
        now in 0u64..1_000_000,
        retention in 61u64..121,
        contenders in 2usize..=4,
        steps in prop::collection::vec(
            (any::<u16>(), any::<u16>(), any::<u16>(),
             prop::collection::vec(any::<u8>(), 0..65), 0u64..=30),
            1..4,
        ),
    ) {
        let anchors: Vec<_> = (0..anchor_count)
            .map(|_| Anchor::generate(epoch.clone()).unwrap())
            .collect();
        let policy = if anchors.is_empty() {
            EndorsementPolicy::NotRequired
        } else {
            EndorsementPolicy::Required(AnchorSet::new(
                &anchors.iter().map(|a| a.configuration().clone()).collect::<Vec<_>>()
            ).unwrap())
        };
        let moderator = Moderator::generate(
            "https://moderator.example/", bits, context, policy, retention,
        ).unwrap();
        let config = moderator.configuration();
        let store = MemoryStore::default();
        let input = if anchors.is_empty() {
            IssuanceInput::WithoutEndorsement
        } else {
            let anchor = &anchors[anchor_index % anchors.len()];
            let (request, pending) = Client.start_grant(anchor.configuration(), NonZeroU16::MIN, &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"));
            let response = anchor.grant(&store, &request, now, now + 30, NonZeroU16::MIN).unwrap();
            let GrantStep::Continue { request, pending } = pending.advance(&response).unwrap() else {
                panic!("expected grant challenge");
            };
            let response = anchor.grant(&store, &request, now, now + 30, NonZeroU16::MIN).unwrap();
            prop_assert!(matches!(
                anchor.grant(&store, &request, now, now + 30, NonZeroU16::MIN), Err(Error::Replay)
            ));
            let GrantStep::Complete(mut endorsements) = pending.advance(&response).unwrap() else {
                panic!("expected endorsement");
            };
            prop_assert_eq!(endorsements.len(), 1);
            IssuanceInput::Endorsement(endorsements.pop().unwrap())
        };
        let max = (1u64 << bits) - 1;
        let mut balance = u64::from(initial) % (max + 1);
        let challenge = moderator.redemption_challenge(now).unwrap();
        let (request, pending) = Client.request_credential(input, config, &challenge).unwrap();
        let response = moderator.issue(&store, &request, balance, now).unwrap();
        if anchor_count > 0 {
            prop_assert!(matches!(
                moderator.issue(&store, &request, balance, now), Err(Error::Replay)
            ));
        }
        let response = CredentialResponse::from_bytes(&response.to_bytes()).unwrap();
        let mut credential = pending.finish(&response).unwrap();
        prop_assert_eq!(credential.balance(), balance);

        let mut now = now;
        for (cost, allowance, refund, binding, delay) in steps {
            if balance < max {
                let challenge = moderator.presentation_challenge(balance + 1, 0, &binding, now).unwrap();
                let error = Client.present(credential, &challenge).unwrap_err();
                prop_assert!(matches!(error.error, Error::Amount));
                credential = error.credential;
                prop_assert_eq!(credential.balance(), balance);
            }
            let cost = u64::from(cost) % (balance + 1);
            let allowance = u64::from(allowance) % (max - balance + 1);
            let refund = u64::from(refund) % (cost + allowance + 1);
            credential = Credential::from_storage_bytes(&credential.to_storage_bytes(), config).unwrap();
            let challenge = moderator.presentation_challenge(cost, allowance, &binding, now).unwrap();
            let pending = Client.present(credential, &challenge).unwrap();
            let pending = PendingPresentation::from_storage_bytes(&pending.to_storage_bytes(), config).unwrap();
            let presentation = CredentialPresentation::from_bytes(&pending.presentation().to_bytes()).unwrap();

            let mut wrong_binding = binding.clone();
            wrong_binding.push(0);
            prop_assert!(matches!(moderator.process(
                &store, &presentation, cost, allowance, &wrong_binding,
                UpdatePolicy::ReturnCredits(refund), now + delay,
            ), Err(Error::Credential(_))));
            let barrier = std::sync::Barrier::new(contenders);
            let outcomes = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..contenders).map(|_| scope.spawn(|| {
                    barrier.wait();
                    moderator.process(
                        &store, &presentation, cost, allowance, &binding,
                        UpdatePolicy::ReturnCredits(refund), now + delay,
                    ).unwrap()
                })).collect();
                handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
            });
            prop_assert_eq!(outcomes.iter().filter(|outcome|
                matches!(outcome, PresentationOutcome::Accepted(_))
            ).count(), 1);
            prop_assert_eq!(outcomes.iter().filter(|outcome|
                matches!(outcome, PresentationOutcome::Recovered(_))
            ).count(), contenders - 1);
            let committed_update = outcomes[0].update();
            for outcome in &outcomes {
                prop_assert_eq!(outcome.update(), committed_update);
            }

            // Recovery ignores the new binding but must never authorize again.
            let recovered = moderator.process(
                &store, &presentation, cost, allowance, &wrong_binding,
                UpdatePolicy::Consume, now + delay,
            ).unwrap();
            prop_assert!(matches!(&recovered, PresentationOutcome::Recovered(_)));
            prop_assert_eq!(recovered.update(), committed_update);

            // A lost response must recover the committed update, even with another policy.
            let recovered = moderator.process(
                &store, &presentation, cost, allowance, &binding,
                UpdatePolicy::Consume, now + delay + retention - 1,
            ).unwrap();
            prop_assert!(matches!(&recovered, PresentationOutcome::Recovered(_)));
            prop_assert_eq!(recovered.update(), committed_update);
            prop_assert!(matches!(moderator.process(
                &store, &presentation, cost, allowance, &binding,
                UpdatePolicy::Consume, now + delay + retention,
            ), Err(Error::Replay)));

            let update = CredentialUpdate::from_bytes(&recovered.update().to_bytes()).unwrap();
            let CredentialOutcome::Replaced(next) = pending.finish(&update).unwrap() else {
                panic!("expected replacement credential");
            };
            balance = balance - cost + refund;
            prop_assert_eq!(next.balance(), balance);
            credential = next;
            now += delay + retention;
        }

        let challenge = moderator.presentation_challenge(balance, 0, b"consume", now).unwrap();
        let pending = Client.present(credential, &challenge).unwrap();
        let accepted = moderator.process(
            &store, pending.presentation(), balance, 0, b"consume", UpdatePolicy::Consume, now,
        ).unwrap();
        prop_assert!(matches!(&accepted, PresentationOutcome::Accepted(_)));
        let recovered = moderator.process(
            &store, pending.presentation(), balance, 0, b"consume", UpdatePolicy::ReturnCredits(0), now,
        ).unwrap();
        prop_assert!(matches!(&recovered, PresentationOutcome::Recovered(_)));
        prop_assert_eq!(recovered.update(), accepted.update());
        prop_assert!(matches!(pending.finish(recovered.update()).unwrap(), CredentialOutcome::Consumed));
    }
}
