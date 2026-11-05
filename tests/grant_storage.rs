use std::{cell::RefCell, num::NonZeroU16};

use guac::{
    Anchor, Client, Error, GrantStep, PendingGrant,
    protocol::{EndorsementRequest, EndorsementResponse, GrantRequest, MAX_GRANT_COUNT},
    storage::{GrantClaim, GrantStore, MemoryStore},
};

/// One session's bytes, as a host persists them between requests. Like a
/// store keyed by host object, it ignores the session id.
#[derive(Default)]
struct Saved(RefCell<Option<Vec<u8>>>);

impl GrantStore for Saved {
    fn insert_grant(&self, _: [u8; 32], state: &[u8], _: u64) -> Result<bool, Error> {
        *self.0.borrow_mut() = Some(state.to_vec());
        Ok(true)
    }

    fn take_grant(&self, _: &[u8; 32]) -> Result<Option<GrantClaim>, Error> {
        Ok(self.0.take().map(GrantClaim::Pending))
    }
}

fn open(anchor: &Anchor, store: &impl GrantStore, now: u64) -> (EndorsementRequest, PendingGrant) {
    let (initial, client) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MIN,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    assert_eq!(initial.to_bytes(), [0, 1]);
    let client =
        PendingGrant::from_storage_bytes(&client.to_storage_bytes(), anchor.configuration())
            .unwrap();
    let commitment = anchor
        .grant(store, &initial, now, now + 30, NonZeroU16::MIN)
        .unwrap();
    let GrantStep::Continue { request, pending } = client.advance(&commitment).unwrap() else {
        panic!("challenge");
    };
    (request, pending)
}

fn complete(pending: PendingGrant, response: &EndorsementResponse) {
    let GrantStep::Complete(endorsements) = pending.advance(response).unwrap() else {
        panic!("endorsements")
    };
    assert!(
        endorsements
            .iter()
            .all(|e| e.scope().moderator_domain() == "moderator.example")
    );
}

#[test]
fn grant_sessions_are_single_use() {
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let store = MemoryStore::default();
    let (request, pending) = open(&anchor, &store, 10);
    let pending =
        PendingGrant::from_storage_bytes(&pending.to_storage_bytes(), anchor.configuration())
            .unwrap();
    complete(
        pending,
        &anchor
            .grant(&store, &request, 11, 0, NonZeroU16::MIN)
            .unwrap(),
    );
    assert!(matches!(
        anchor.grant(&store, &request, 11, 0, NonZeroU16::MIN),
        Err(Error::Replay)
    ));

    // Both zero and noncanonical scalars consume the session.
    for byte in [0, 0xff] {
        let (request, _) = open(&anchor, &store, 10);
        let mut corrupt = request.to_bytes();
        let len = corrupt.len();
        corrupt[len - 32..].fill(byte);
        let corrupt = EndorsementRequest::from_bytes(&corrupt).unwrap();
        assert!(matches!(
            anchor.grant(&store, &corrupt, 11, 0, NonZeroU16::MIN),
            Err(Error::Endorsement(_) | Error::Malformed)
        ));
        // The failed response consumed the session.
        assert!(matches!(
            anchor.grant(&store, &request, 11, 0, NonZeroU16::MIN),
            Err(Error::Replay)
        ));
    }

    assert!(matches!(
        anchor.grant(
            &store,
            &EndorsementRequest::from_bytes(&[0, 0]).unwrap(),
            11,
            0,
            NonZeroU16::MIN
        ),
        Err(Error::Malformed)
    ));
    let unknown = MemoryStore::default();
    let (request, _) = open(&anchor, &store, 10);
    assert!(matches!(
        anchor.grant(&unknown, &request, 11, 0, NonZeroU16::MIN),
        Err(Error::Session)
    ));
}

#[test]
fn grant_sessions_need_a_future_expiry() {
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let store = MemoryStore::default();
    let (initial, _) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MIN,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    assert!(matches!(
        anchor.grant(&store, &initial, 100, 100, NonZeroU16::MIN),
        Err(Error::Session)
    ));
    let (request, _) = open(&anchor, &store, 100);
    assert!(matches!(
        anchor.grant(&store, &request, 130, 0, NonZeroU16::MIN),
        Err(Error::Session)
    ));
    assert!(matches!(
        anchor.grant(&store, &request, 100, 0, NonZeroU16::MIN),
        Err(Error::Replay)
    ));
}

#[test]
fn restarted_anchor_completes_from_stored_bytes() {
    let secret = Anchor::generate(b"epoch".to_vec())
        .unwrap()
        .to_secret_bytes();
    let anchor = Anchor::from_secret(&secret, b"epoch".to_vec()).unwrap();
    let saved = Saved::default();
    let (request, pending) = open(&anchor, &saved, 10);
    let restarted = Anchor::from_secret(&secret, b"epoch".to_vec()).unwrap();
    complete(
        pending,
        &restarted
            .grant(&saved, &request, 11, 0, NonZeroU16::MIN)
            .unwrap(),
    );
    assert!(matches!(
        restarted.grant(&saved, &request, 11, 0, NonZeroU16::MIN),
        Err(Error::Session)
    ));
}

#[test]
fn stored_state_is_bound_to_the_anchor_key_epoch_and_session() {
    let anchor = Anchor::generate(b"epoch-1".to_vec()).unwrap();
    let secret = anchor.to_secret_bytes();
    let other_key = Anchor::generate(b"epoch-1".to_vec()).unwrap();
    let other_epoch = Anchor::from_secret(&secret, b"epoch-2".to_vec()).unwrap();
    for other in [&other_key, &other_epoch] {
        let saved = Saved::default();
        let (request, _) = open(&anchor, &saved, 10);
        assert!(matches!(
            other.grant(&saved, &request, 11, 0, NonZeroU16::MIN),
            Err(Error::Mismatch)
        ));
    }

    // A store returning another session's state.
    let first = Saved::default();
    let (request, _) = open(&anchor, &first, 10);
    let second = Saved::default();
    let _ = open(&anchor, &second, 10);
    first.0.swap(&second.0);
    assert!(matches!(
        anchor.grant(&first, &request, 11, 0, NonZeroU16::MIN),
        Err(Error::Mismatch)
    ));
}

#[test]
fn grant_requests_name_their_batch() {
    #[derive(Default)]
    struct Ids(RefCell<Option<[u8; 32]>>, Saved);
    impl GrantStore for Ids {
        fn insert_grant(&self, id: [u8; 32], state: &[u8], at: u64) -> Result<bool, Error> {
            *self.0.borrow_mut() = Some(id);
            self.1.insert_grant(id, state, at)
        }
        fn take_grant(&self, id: &[u8; 32]) -> Result<Option<GrantClaim>, Error> {
            self.1.take_grant(id)
        }
    }
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let (initial, _) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MIN,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    assert_eq!(
        initial.grant().unwrap(),
        GrantRequest::Open(NonZeroU16::MIN)
    );
    let store = Ids::default();
    let (request, _) = open(&anchor, &store, 10);
    let session = store.0.borrow().unwrap();
    assert_eq!(request.grant().unwrap(), GrantRequest::Continue(session));
    assert!(!format!("{anchor:?}").contains(&format!("{:?}", *anchor.to_secret_bytes())));
}

#[test]
fn batches_grant_at_most_the_count_and_the_limit() {
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let store = MemoryStore::default();
    let count = NonZeroU16::new(3).unwrap();
    let (initial, pending) = Client.start_grant(
        anchor.configuration(),
        count,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    let limit = NonZeroU16::new(2).unwrap();
    let commitments = anchor.grant(&store, &initial, 10, 40, limit).unwrap();
    let GrantStep::Continue { request, pending } = pending.advance(&commitments).unwrap() else {
        panic!("challenges");
    };
    let response = anchor.grant(&store, &request, 11, 0, limit).unwrap();
    let GrantStep::Complete(endorsements) = pending.advance(&response).unwrap() else {
        panic!("endorsements");
    };
    assert_eq!(endorsements.len(), 2);

    // A Client asking for one rejects a batch of two.
    let (initial, _) = Client.start_grant(
        anchor.configuration(),
        count,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    let commitments = anchor.grant(&store, &initial, 10, 40, limit).unwrap();
    let (_, one) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MIN,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    assert!(matches!(one.advance(&commitments), Err(Error::Malformed)));

    // Dropping a challenge consumes the batch without signing.
    let (_, pending) = Client.start_grant(
        anchor.configuration(),
        count,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    let GrantStep::Continue { request, .. } = pending.advance(&commitments).unwrap() else {
        panic!("challenges");
    };
    let bytes = request.to_bytes();
    let short = [&bytes[..32], &[32], &bytes[34..66]].concat();
    let short = EndorsementRequest::from_bytes(&short).unwrap();
    assert!(matches!(
        anchor.grant(&store, &short, 11, 0, limit),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        anchor.grant(&store, &request, 11, 0, limit),
        Err(Error::Replay)
    ));
}

#[test]
fn batches_fit_the_message_cap() {
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let store = MemoryStore::default();
    let (initial, pending) = Client.start_grant(
        anchor.configuration(),
        NonZeroU16::MAX,
        &guac::RedemptionScope::for_moderator_domain("moderator.example").expect("valid domain"),
    );
    let commitments = anchor
        .grant(&store, &initial, 10, 40, NonZeroU16::MAX)
        .unwrap();
    let GrantStep::Continue { request, pending } = pending.advance(&commitments).unwrap() else {
        panic!("challenges");
    };
    let response = anchor
        .grant(&store, &request, 11, 0, NonZeroU16::MAX)
        .unwrap();
    let GrantStep::Complete(endorsements) = pending.advance(&response).unwrap() else {
        panic!("endorsements");
    };
    assert_eq!(endorsements.len(), usize::from(MAX_GRANT_COUNT.get()));
}

#[test]
fn restored_grant_rejects_changed_or_malformed_scope() {
    let anchor = Anchor::generate(b"epoch".to_vec()).unwrap();
    let store = MemoryStore::default();
    let (request, pending) = open(&anchor, &store, 10);
    let mut bytes = pending.to_storage_bytes();
    let offset = bytes
        .windows(17)
        .position(|b| b == b"moderator.example")
        .unwrap();
    bytes[offset] = b'_';
    assert!(matches!(
        PendingGrant::from_storage_bytes(&bytes, anchor.configuration()),
        Err(Error::Malformed)
    ));
    bytes[offset..offset + 17].copy_from_slice(b"different.example");
    let pending = PendingGrant::from_storage_bytes(&bytes, anchor.configuration()).unwrap();
    let response = anchor
        .grant(&store, &request, 11, 0, NonZeroU16::MIN)
        .unwrap();
    assert!(matches!(
        pending.advance(&response),
        Err(Error::Endorsement(_))
    ));
}
