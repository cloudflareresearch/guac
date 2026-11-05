#![no_main]

use std::{num::NonZeroU16, sync::OnceLock};

use guac::{
    Anchor, Client, GrantStep, PendingGrant,
    protocol::{EndorsementRequest, EndorsementResponse},
    storage::MemoryStore,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    static ANCHOR: OnceLock<Anchor> = OnceLock::new();
    let anchor = ANCHOR
        .get_or_init(|| Anchor::from_secret(&[7; 48], b"fuzz".to_vec()).expect("fuzz Anchor"));
    let config = anchor.configuration();
    let store = MemoryStore::default();

    if let Ok(request) = EndorsementRequest::from_bytes(bytes) {
        let _ = request.grant();
        let _ = anchor.grant(&store, &request, 0, 30, NonZeroU16::MIN);
    }
    let _ = PendingGrant::from_storage_bytes(bytes, config);
    let _ = guac::Endorsement::from_storage_bytes(bytes, config);

    let scope =
        guac::RedemptionScope::for_moderator_domain("moderator.example").expect("fuzz domain");
    let (request, pending) = Client.start_grant(config, NonZeroU16::MIN, &scope);
    if let Ok(response) = EndorsementResponse::from_bytes(bytes) {
        let restored = PendingGrant::from_storage_bytes(&pending.to_storage_bytes(), config)
            .expect("valid commitments state");
        let _ = restored.advance(&response);

        let commitments = anchor
            .grant(&store, &request, 0, 30, NonZeroU16::MIN)
            .expect("valid grant request");
        let GrantStep::Continue { pending, .. } =
            pending.advance(&commitments).expect("commitments")
        else {
            panic!("grant needs a second exchange");
        };
        let restored = PendingGrant::from_storage_bytes(&pending.to_storage_bytes(), config)
            .expect("valid responses state");
        let _ = restored.advance(&response);
    }
});
