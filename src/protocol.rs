//! MOLE payloads. [`crate::http`] carries them over HTTP.
//!
//! HTTP carries type-specific payloads without outer type or length wrappers;
//! the type travels in the parameter name or media type. Challenge digests
//! still cover the canonical `type || vector(payload)` encodings (MOLE
//! protocols, Message Types), so transcripts are unchanged.

use std::num::NonZeroU16;

use sha2::{Digest, Sha256};

use crate::Error;

pub(crate) const NO_ENDORSEMENT: u16 = 1;
pub(crate) const EC_IHAT: u16 = 2;
pub(crate) const ACT: u16 = 1;
/// Local input limit, checked before copying message payloads.
pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Largest length prefix `put_vector` writes, for exact preallocation.
pub(crate) const VECTOR_PREFIX: usize = 4;

pub(crate) fn put_vector(out: &mut Vec<u8>, value: &[u8]) {
    // All callers validate sizes against MAX_MESSAGE_BYTES or u16::MAX.
    let length = value.len();
    let (size, tag) = if length < 64 {
        (1, 0)
    } else if length < 16384 {
        (2, 0x40)
    } else {
        (4, 0x80)
    };
    let bytes = length.to_be_bytes();
    let start = bytes.len() - size;
    out.push(bytes[start] | tag);
    out.extend_from_slice(&bytes[start + 1..]);
    out.extend_from_slice(value);
}

/// SHA-256 of the canonical `type || vector(payload)` challenge encoding.
fn canonical_digest(kind: u16, payload: &[u8]) -> [u8; 32] {
    let mut out = kind.to_be_bytes().to_vec();
    put_vector(&mut out, payload);
    digest(&out)
}

/// Rejects the reserved type 0 and types outside `supported`.
pub(crate) fn check_type(value: u16, supported: &[u16]) -> Result<u16, Error> {
    if value == 0 {
        return Err(Error::Malformed);
    }
    if !supported.contains(&value) {
        return Err(Error::Unsupported(value));
    }
    Ok(value)
}

fn bounded(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Malformed);
    }
    Ok(bytes.to_vec())
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Trusted local storage: unbounded, since batches of states and long
    /// epochs exceed the network cap.
    pub(crate) fn trusted(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (value, rest) = self.0.split_at_checked(length).ok_or(Error::Malformed)?;
        self.0 = rest;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }

    pub(crate) fn protocol(&mut self, supported: &[u16]) -> Result<u16, Error> {
        check_type(u16::from_be_bytes(self.array()?), supported)
    }

    pub(crate) fn vector(&mut self) -> Result<&'a [u8], Error> {
        let first = self.take(1)?[0];
        let size = 1usize << (first >> 6);
        let mut length = u64::from(first & 0x3f);
        for byte in self.take(size - 1)? {
            length = (length << 8) | u64::from(*byte);
        }
        if size > 1 && length < 1 << (8 * (size / 2) - 2) {
            return Err(Error::Malformed);
        }
        self.take(usize::try_from(length).map_err(|_| Error::Malformed)?)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

// Opaque payloads: role operations validate their content.
macro_rules! payload {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            pub(crate) body: Vec<u8>,
        }

        impl $name {
            pub fn to_bytes(&self) -> Vec<u8> {
                self.body.clone()
            }

            /// Checks only the size; role operations validate the content.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Ok(Self {
                    body: bounded(bytes)?,
                })
            }
        }
    };
}

payload!(
    EndorsementRequest,
    "An EC-IHAT (0x0002) grant request body: `GrantRequest`, then `GrantChallenges`."
);
payload!(
    EndorsementResponse,
    "An EC-IHAT (0x0002) grant response body: `GrantCommitments`, then `GrantResponses`."
);

/// What a grant request asks for (MOLE protocols, EC-IHAT grant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantRequest {
    /// Opens a batch of at most this many Endorsements.
    Open(NonZeroU16),
    /// Answers the batch this session identifier names.
    Continue([u8; 32]),
}

impl EndorsementRequest {
    /// Errors: `Malformed` for a zero count or a body of neither shape.
    pub fn grant(&self) -> Result<GrantRequest, Error> {
        let mut reader = Reader::new(&self.body)?;
        if self.body.len() == 2 {
            let count = u16::from_be_bytes(reader.array()?);
            return NonZeroU16::new(count)
                .map(GrantRequest::Open)
                .ok_or(Error::Malformed);
        }
        Ok(GrantRequest::Continue(reader.array()?))
    }
}

/// Length of a draft `CommitMessage`: `Element A || Element C`.
pub(crate) const COMMITMENT_LENGTH: usize = 2 * ec_ihat::backend::POINT_LENGTH;
/// Length of a draft `ChallengeMessage`: `Scalar challenge`.
pub(crate) const CHALLENGE_LENGTH: usize = ec_ihat::backend::SCALAR_LENGTH;
/// Length of a `ResponseMessage`: `Scalar s || Scalar y || Scalar t`.
pub(crate) const RESPONSE_LENGTH: usize = 3 * ec_ihat::backend::SCALAR_LENGTH;

/// Largest batch whose `GrantResponses`, the biggest grant message, fits
/// `MAX_MESSAGE_BYTES`. Anchors grant at most this many.
pub const MAX_GRANT_COUNT: NonZeroU16 =
    match NonZeroU16::new(((MAX_MESSAGE_BYTES - VECTOR_PREFIX) / RESPONSE_LENGTH) as u16) {
        Some(count) => count,
        None => panic!("MAX_MESSAGE_BYTES fits a response"),
    };

/// Splits a vector of fixed-size items, requiring one to `u16::MAX` items.
pub(crate) fn batch(bytes: &[u8], size: usize) -> Result<Vec<&[u8]>, Error> {
    let items: Vec<&[u8]> = bytes.chunks(size).collect();
    if items.is_empty() || items.len() > usize::from(u16::MAX) || !bytes.len().is_multiple_of(size)
    {
        return Err(Error::Malformed);
    }
    Ok(items)
}
payload!(CredentialResponse, "An ACT IssuanceResponse.");
payload!(
    CredentialPresentation,
    "An ACT PresentationAndUpdate: `key_id || SpendMessage`."
);

impl CredentialPresentation {
    /// The credential key it names, so hosts holding several keys can route
    /// it. `None` when too short; the Moderator rejects it then anyway.
    pub fn key_id(&self) -> Option<[u8; 32]> {
        self.body.get(..32)?.try_into().ok()
    }
}

/// A Redemption and an ACT IssuanceRequest, carried together as `redeem-E`
/// and `credential-request-0001`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    pub(crate) endorsement_type: u16,
    pub(crate) redemption: Vec<u8>,
    pub(crate) issuance: Vec<u8>,
}

impl CredentialRequest {
    pub fn from_parts(
        endorsement_type: u16,
        redemption: &[u8],
        issuance: &[u8],
    ) -> Result<Self, Error> {
        let endorsement_type = check_type(endorsement_type, &[NO_ENDORSEMENT, EC_IHAT])?;
        if endorsement_type == NO_ENDORSEMENT && !redemption.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            endorsement_type,
            redemption: bounded(redemption)?,
            issuance: bounded(issuance)?,
        })
    }

    pub fn endorsement_type(&self) -> u16 {
        self.endorsement_type
    }
    /// Empty for endorsement type 0x0001.
    pub fn redemption(&self) -> &[u8] {
        &self.redemption
    }
    pub fn issuance(&self) -> &[u8] {
        &self.issuance
    }
}

/// An unpredictable Moderator-issued redemption challenge (`redeem-E`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeratorChallenge {
    pub(crate) endorsement_type: u16,
    pub(crate) redemption_context: [u8; 32],
}

impl ModeratorChallenge {
    /// `payload` is the 32-byte RedemptionChallenge.
    pub fn from_parts(endorsement_type: u16, payload: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            endorsement_type: check_type(endorsement_type, &[NO_ENDORSEMENT, EC_IHAT])?,
            redemption_context: payload.try_into().map_err(|_| Error::Malformed)?,
        })
    }

    pub fn endorsement_type(&self) -> u16 {
        self.endorsement_type
    }
    pub fn payload(&self) -> &[u8; 32] {
        &self.redemption_context
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        canonical_digest(self.endorsement_type, &self.redemption_context)
    }
}

/// An ACT Challenge (`challenge-0001`): credit amounts and the contexts a
/// presentation must answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialChallenge {
    pub(crate) cost: u64,
    pub(crate) allowance: u64,
    pub(crate) context: Vec<u8>,
    pub(crate) request_context: Vec<u8>,
}

impl CredentialChallenge {
    pub fn cost(&self) -> u64 {
        self.cost
    }
    pub fn allowance(&self) -> u64 {
        self.allowance
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = self.cost.to_be_bytes().to_vec();
        body.extend_from_slice(&self.allowance.to_be_bytes());
        put_vector(&mut body, &self.context);
        put_vector(&mut body, &self.request_context);
        body
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut body = Reader::new(bytes)?;
        let cost = u64::from_be_bytes(body.array()?);
        let allowance = u64::from_be_bytes(body.array()?);
        let context = body.vector()?.to_vec();
        let request_context = body.vector()?.to_vec();
        body.finish()?;
        if context.len() > usize::from(u16::MAX) - 1 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            cost,
            allowance,
            context,
            request_context,
        })
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        canonical_digest(ACT, &self.to_bytes())
    }
}

/// An ACT Update: a refund, or empty for a recorded NoUpdate, which ends the
/// credential chain. A missing `Mole-Credential` field is not an update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialUpdate {
    pub(crate) response: Option<Vec<u8>>,
}

impl CredentialUpdate {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.response.clone().unwrap_or_default()
    }

    /// Empty bytes are explicit consumption.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bounded(bytes)?;
        Ok(Self {
            response: (!bytes.is_empty()).then_some(bytes),
        })
    }
}

/// ACT recovery handle: `key_id || nullifier || SHA-256(PresentationAndUpdate)`.
///
/// Sent as `recovery-0001` to the Redeem & Issue endpoint, it recovers a
/// recorded update without another protected operation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryHandle {
    pub(crate) key_id: [u8; 32],
    pub(crate) nullifier: [u8; 32],
    pub(crate) digest: [u8; 32],
}

impl RecoveryHandle {
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
    /// The replay-store key of the presentation's record.
    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.key_id, self.nullifier, self.digest].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes)?;
        let handle = Self {
            key_id: reader.array()?,
            nullifier: reader.array()?,
            digest: reader.array()?,
        };
        reader.finish()?;
        Ok(handle)
    }
}
