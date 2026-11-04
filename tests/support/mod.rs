#![allow(dead_code)]

use std::num::NonZeroU16;

use guac::{
    Anchor, AnchorSet, Client, CredentialOutcome, EndorsementPolicy, GrantStep, IssuanceInput,
    Moderator, UpdatePolicy,
    http::{Authorization, Challenge},
    storage::MemoryStore,
};
use serde::{Deserialize, Serialize};

pub const ACT_REV: &str = "f1bd64b90408677662bb9f96915d8dc0e58e1ad6";
pub const IHAT_REV: &str = "ed756147ac9a1cc530d718e749c0fae8090fda7c";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub version: u8,
    pub draft: String,
    pub act_revision: String,
    pub ihat_revision: String,
    pub generation: String,
    pub cases: Vec<Transcript>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorVector {
    pub public_key: String,
    pub epoch: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub name: String,
    pub anchors: Vec<AnchorVector>,
    pub grant_exchanges: Vec<(String, String)>,
    pub endorsement_storage: Option<String>,
    pub moderator_secret: String,
    pub moderator_public: String,
    pub endpoint: String,
    pub balance_bits: u8,
    pub credential_context: String,
    pub retention_seconds: String,
    /// `WWW-Authenticate` value.
    pub redemption_challenge: String,
    /// `Authorization` value.
    pub issuance_request: String,
    pub issuance_state_raw: String,
    pub issuance_state: String,
    pub issuance_response: String,
    pub credential_storage: String,
    pub credential_raw: String,
    pub presentation_challenge: String,
    pub pending_presentation: String,
    pub presentation_state_raw: String,
    pub presentation: String,
    pub update: String,
    pub expected_balance: Option<String>,
}

pub fn capture(
    name: &str,
    anchor_index: Option<usize>,
    policy: UpdatePolicy,
) -> Result<Transcript, Box<dyn std::error::Error>> {
    let client = Client;
    let anchors = [
        Anchor::generate(b"epoch-1".to_vec())?,
        Anchor::generate(b"epoch-1".to_vec())?,
    ];
    let configurations: Vec<_> = anchors
        .iter()
        .map(|anchor| anchor.configuration().clone())
        .collect();
    let endorsements = match anchor_index {
        Some(_) => EndorsementPolicy::Required(AnchorSet::new(&configurations)?),
        None => EndorsementPolicy::NotRequired,
    };
    let store = MemoryStore::default();
    let moderator = Moderator::generate(
        "https://moderator.example/",
        4,
        b"credits-1".to_vec(),
        endorsements,
        60,
    )?;
    let mut exchanges = Vec::new();
    let endorsement = if let Some(index) = anchor_index {
        let anchor = anchors.get(index).ok_or("invalid Anchor index")?;
        let (request, pending) = client.start_grant(
            anchor.configuration(),
            NonZeroU16::MIN,
            &guac::RedemptionScope::for_moderator_domain("moderator.example")
                .expect("valid domain"),
        );
        let response = anchor.grant(&store, &request, 100, 130, NonZeroU16::MIN)?;
        exchanges.push((
            hex::encode(request.to_bytes()),
            hex::encode(response.to_bytes()),
        ));
        let GrantStep::Continue { request, pending } = pending.advance(&response)? else {
            return Err("grant ended after the commitment".into());
        };
        let response = anchor.grant(&store, &request, 100, 130, NonZeroU16::MIN)?;
        exchanges.push((
            hex::encode(request.to_bytes()),
            hex::encode(response.to_bytes()),
        ));
        let GrantStep::Complete(mut endorsements) = pending.advance(&response)? else {
            return Err("grant needs another exchange".into());
        };
        Some(endorsements.pop().ok_or("grant produced no endorsement")?)
    } else {
        None
    };
    let endorsement_storage = endorsement
        .as_ref()
        .map(|endorsement| hex::encode(endorsement.to_storage_bytes()));
    let input = match endorsement {
        Some(endorsement) => IssuanceInput::Endorsement(endorsement),
        None => IssuanceInput::WithoutEndorsement,
    };
    let challenge = moderator.redemption_challenge(100)?;
    let (request, pending) =
        client.request_credential(input, moderator.configuration(), &challenge)?;
    let issuance_state = pending.to_storage_bytes();
    let response = moderator.issue(&store, &request, 8, 100)?;
    let credential = pending.finish(&response)?;
    let credential_storage = credential.to_storage_bytes();
    let presentation_challenge = moderator.presentation_challenge(2, 1, b"operation-1", 100)?;
    let pending = client.present(credential, &presentation_challenge)?;
    let pending_storage = pending.to_storage_bytes();
    let presentation = pending.presentation().to_bytes();
    let update = moderator
        .process(
            &store,
            pending.presentation(),
            2,
            1,
            b"operation-1",
            policy,
            100,
        )?
        .update()
        .clone();
    let expected_balance = match pending.finish(&update)? {
        CredentialOutcome::Replaced(credential) => Some(credential.balance().to_string()),
        CredentialOutcome::Consumed => None,
    };
    Ok(Transcript {
        name: name.into(),
        anchors: if anchor_index.is_some() {
            configurations
                .iter()
                .map(|config| AnchorVector {
                    public_key: hex::encode(config.public_key()),
                    epoch: hex::encode(config.epoch()),
                })
                .collect()
        } else {
            Vec::new()
        },
        grant_exchanges: exchanges,
        endorsement_storage,
        moderator_secret: hex::encode(moderator.to_secret_bytes()),
        moderator_public: hex::encode(moderator.configuration().public_key()),
        endpoint: moderator.configuration().endpoint().to_string(),
        balance_bits: 4,
        credential_context: hex::encode(moderator.configuration().credential_context()),
        retention_seconds: "60".into(),
        redemption_challenge: Challenge::Redeem(challenge).to_string(),
        issuance_request: Authorization::Issue(request).to_string(),
        issuance_state_raw: hex::encode(secret_payload(&issuance_state)),
        issuance_state: hex::encode(issuance_state),
        issuance_response: hex::encode(response.to_bytes()),
        credential_raw: hex::encode(secret_payload(&credential_storage)),
        credential_storage: hex::encode(credential_storage),
        presentation_challenge: hex::encode(presentation_challenge.to_bytes()),
        presentation_state_raw: hex::encode(vector(secret_payload(&pending_storage)).0),
        pending_presentation: hex::encode(pending_storage),
        presentation: hex::encode(presentation),
        update: hex::encode(update.to_bytes()),
        expected_balance,
    })
}

// Extract backend-independent ACT state bytes from guac's trusted test exports.
// No production API exposes these upstream types or depends on this extractor.
fn secret_payload(bytes: &[u8]) -> &[u8] {
    assert_eq!(&bytes[..5], b"GUAC\x02");
    let (payload, rest) = vector(&bytes[40..]);
    assert!(rest.is_empty());
    payload
}

pub fn vector(bytes: &[u8]) -> (&[u8], &[u8]) {
    let first = bytes[0];
    let size = 1usize << (first >> 6);
    let mut length = u64::from(first & 0x3f);
    for byte in &bytes[1..size] {
        length = (length << 8) | u64::from(*byte);
    }
    let length = usize::try_from(length).expect("test vector length");
    bytes[size..].split_at(length)
}
