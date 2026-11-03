use std::num::NonZeroU16;

use crate::{
    AnchorConfig, Error,
    client::{anchor_fingerprint, read_secret, secret_envelope},
    protocol::{
        CHALLENGE_LENGTH, COMMITMENT_LENGTH, EndorsementRequest, EndorsementResponse, GrantRequest,
        MAX_GRANT_COUNT, RESPONSE_LENGTH, Reader, VECTOR_PREFIX, batch, put_vector,
    },
    storage::{GrantClaim, GrantStore},
};

/// Secret, single-use batch continuation, stored as opaque bytes in a `GrantStore`.
struct PendingAnchorGrant {
    config: AnchorConfig,
    expires_at: u64,
    session: [u8; 32],
    states: Vec<ec_ihat::AnchorState>,
}

impl PendingAnchorGrant {
    fn to_storage_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let states: Vec<_> = self.states.iter().map(|state| state.to_bytes()).collect();
        // Reserve before writing secrets: growth could free an unwiped copy.
        let capacity = 8
            + 32
            + states
                .iter()
                .map(|state| VECTOR_PREFIX + state.len())
                .sum::<usize>();
        let mut payload = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
        payload.extend_from_slice(&self.expires_at.to_be_bytes());
        payload.extend_from_slice(&self.session);
        for state in states {
            put_vector(&mut payload, &state);
        }
        secret_envelope(6, anchor_fingerprint(&self.config), &payload)
    }

    fn from_storage_bytes(bytes: &[u8], configuration: &AnchorConfig) -> Result<Self, Error> {
        let mut reader = Reader::trusted(read_secret(bytes, 6, anchor_fingerprint(configuration))?);
        let expires_at = u64::from_be_bytes(reader.array()?);
        let session = reader.array()?;
        let mut states = Vec::new();
        while !reader.is_empty() {
            states.push(ec_ihat::AnchorState::from_bytes(reader.vector()?)?);
        }
        Ok(Self {
            config: configuration.clone(),
            expires_at,
            session,
            states,
        })
    }
}

/// Native Anchor. Holds no mutable state: grant sessions live in the caller's
/// `GrantStore`.
///
/// The caller authenticates clients and limits grants before opening one.
pub struct Anchor {
    seed: zeroize::Zeroizing<[u8; ec_ihat::SEED_LENGTH]>,
    key: ec_ihat::SecretKey,
    config: AnchorConfig,
}

impl core::fmt::Debug for Anchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Anchor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Anchor {
    pub fn generate(epoch: Vec<u8>) -> Result<Self, Error> {
        let mut seed = zeroize::Zeroizing::new([0; ec_ihat::SEED_LENGTH]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Entropy)?;
        Self::from_secret(&seed, epoch)
    }

    /// Restores an Anchor from the key seed returned by `to_secret_bytes`.
    pub fn from_secret(seed: &[u8; ec_ihat::SEED_LENGTH], epoch: Vec<u8>) -> Result<Self, Error> {
        let key = ec_ihat::SecretKey::from_seed(seed)?;
        let config = AnchorConfig::new(&key.public_key().to_bytes(), epoch)?;
        Ok(Self {
            seed: zeroize::Zeroizing::new(*seed),
            key,
            config,
        })
    }

    pub fn configuration(&self) -> &AnchorConfig {
        &self.config
    }

    /// Secret key seed export for host-managed secure storage.
    pub fn to_secret_bytes(&self) -> zeroize::Zeroizing<[u8; ec_ihat::SEED_LENGTH]> {
        self.seed.clone()
    }

    /// Processes one grant exchange. Times are Unix seconds supplied by the host.
    ///
    /// A `GrantRequest` opens a batch of `min(count, limit, MAX_GRANT_COUNT)` sessions, stored
    /// until `expires_at` before the commitments are released. Hosts read the
    /// count with `EndorsementRequest::grant` to charge the Client's budget.
    /// `GrantChallenges` consume their batch before signing, so a failed
    /// response also uses it up; they use the stored expiry and ignore
    /// `expires_at` and `limit`.
    ///
    /// Errors: `Session` for an unknown or expired batch, `Replay` for a
    /// consumed one, `Mismatch` for state of another Anchor key, epoch or
    /// batch, `Malformed` for undecodable input or a challenge count unlike
    /// the batch's, `Endorsement` for an invalid challenge.
    pub fn grant(
        &self,
        store: &impl GrantStore,
        request: &EndorsementRequest,
        now: u64,
        expires_at: u64,
        limit: NonZeroU16,
    ) -> Result<EndorsementResponse, Error> {
        let session = match request.grant()? {
            GrantRequest::Open(count) => {
                return self.open(
                    store,
                    count.min(limit).min(MAX_GRANT_COUNT),
                    now,
                    expires_at,
                );
            }
            GrantRequest::Continue(session) => session,
        };
        let stored = match store.take_grant(&session)? {
            Some(GrantClaim::Pending(stored)) => zeroize::Zeroizing::new(stored),
            Some(GrantClaim::Consumed) => return Err(Error::Replay),
            None => return Err(Error::Session),
        };
        let mut reader = Reader::new(&request.body)?;
        reader.take(32)?;
        let challenges = batch(reader.vector()?, CHALLENGE_LENGTH)?
            .into_iter()
            .map(ec_ihat::ChallengeMessage::from_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        reader.finish()?;
        let pending = PendingAnchorGrant::from_storage_bytes(&stored, &self.config)?;
        // Stores keyed by something else (one batch per host object) may
        // return another batch's state.
        if pending.session != session {
            return Err(Error::Mismatch);
        }
        if pending.config != self.config || pending.expires_at <= now {
            return Err(Error::Session);
        }
        if pending.states.len() != challenges.len() {
            return Err(Error::Malformed);
        }
        let mut responses = Vec::with_capacity(challenges.len() * RESPONSE_LENGTH);
        for (state, challenge) in pending.states.into_iter().zip(&challenges) {
            responses.extend_from_slice(&ec_ihat::respond(&self.key, state, challenge)?.to_bytes());
        }
        let mut body = Vec::new();
        put_vector(&mut body, &responses);
        Ok(EndorsementResponse { body })
    }

    fn open(
        &self,
        store: &impl GrantStore,
        count: NonZeroU16,
        now: u64,
        expires_at: u64,
    ) -> Result<EndorsementResponse, Error> {
        if expires_at <= now {
            return Err(Error::Session);
        }
        let mut session = [0; 32];
        getrandom::fill(&mut session).map_err(|_| Error::Entropy)?;
        let mut states = Vec::with_capacity(count.get().into());
        let mut commitments = Vec::with_capacity(usize::from(count.get()) * COMMITMENT_LENGTH);
        for _ in 0..count.get() {
            let (state, message) = ec_ihat::commit(&self.config.epoch)?;
            commitments.extend_from_slice(&message.to_bytes());
            states.push(state);
        }
        let pending = PendingAnchorGrant {
            config: self.config.clone(),
            expires_at,
            session,
            states,
        };
        if !store.insert_grant(session, &pending.to_storage_bytes(), expires_at)? {
            return Err(Error::Session);
        }
        let mut body = session.to_vec();
        put_vector(&mut body, &commitments);
        Ok(EndorsementResponse { body })
    }
}
