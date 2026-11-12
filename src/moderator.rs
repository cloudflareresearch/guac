use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    AnchorSet, EndorsementPolicy, Error, ModeratorConfig,
    config::REDEMPTION_CONTEXT,
    protocol::{
        CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
        CredentialUpdate, ModeratorChallenge, Reader, RecoveryHandle, digest, put_vector,
    },
    storage::{PresentationRecord, Spent, Store},
};

/// Redemption and request-bound challenges are valid for the current and previous window,
/// so between one and two windows. See `Moderator::presentation_challenge`.
pub(crate) const CHALLENGE_WINDOW_SECONDS: u64 = 30;

/// The Moderator's decision after verifying a presentation.
#[derive(Clone, Copy, Debug)]
pub enum UpdatePolicy {
    /// Replace the credential, returning this many credits (bounded by cost + allowance).
    ReturnCredits(u64),
    /// Accept the presentation but end its credential chain.
    Consume,
}

/// Only a fresh acceptance authorizes an application-operation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentationOutcome {
    Accepted(CredentialUpdate),
    Recovered(CredentialUpdate),
}

impl PresentationOutcome {
    pub fn update(&self) -> &CredentialUpdate {
        match self {
            Self::Accepted(update) | Self::Recovered(update) => update,
        }
    }
}

/// A verified issuance. Release the response only after atomically inserting
/// `replay_id`, when present; if it was already present, drop this value.
#[must_use]
pub struct Issuance {
    /// The endorsement nullifier and the issuance epoch it was verified under.
    replay: Option<([u8; 32], Vec<u8>)>,
    response: CredentialResponse,
}

impl Issuance {
    /// No identifier when endorsements are not required; the host limits issuance.
    pub fn replay_id(&self) -> Option<[u8; 32]> {
        self.replay.as_ref().map(|(id, _)| *id)
    }
    /// The issuance epoch of the redeemed endorsement, which scopes `replay_id`.
    pub fn epoch(&self) -> Option<&[u8]> {
        self.replay.as_ref().map(|(_, epoch)| epoch.as_slice())
    }
    pub fn into_response(self) -> CredentialResponse {
        self.response
    }
}

/// A verified presentation. Its update is released only if inserting `record`
/// under `nullifier` succeeds; otherwise answer from the existing record.
#[must_use]
pub struct Acceptance {
    nullifier: [u8; 32],
    record: PresentationRecord,
}

impl Acceptance {
    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }
    pub fn record(&self) -> &PresentationRecord {
        &self.record
    }
}

/// One Moderator key and credential context. Holds no mutable state: replay
/// records live in a `Store`, and challenges are authenticated, not stored.
pub struct Moderator {
    seed: Zeroizing<[u8; act::SEED_LENGTH]>,
    key: act::SecretKey,
    config: ModeratorConfig,
    challenge_key: Zeroizing<[u8; 32]>,
    /// Also accepted for redemption, during an Anchor epoch rotation.
    previous: Option<AnchorSet>,
    policy_digest: std::sync::OnceLock<[u8; 32]>,
}

impl Moderator {
    pub fn generate(
        endpoint: &str,
        balance_bits: u8,
        context: Vec<u8>,
        endorsements: EndorsementPolicy,
        result_retention_seconds: u64,
    ) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; act::SEED_LENGTH]);
        getrandom::fill(&mut *seed).map_err(|_| Error::Entropy)?;
        Self::from_secret(
            &seed,
            endpoint,
            balance_bits,
            context,
            endorsements,
            result_retention_seconds,
        )
    }

    /// Derives the public configuration from a host-held key seed.
    pub fn from_secret(
        seed: &[u8; act::SEED_LENGTH],
        endpoint: &str,
        balance_bits: u8,
        context: Vec<u8>,
        endorsements: EndorsementPolicy,
        result_retention_seconds: u64,
    ) -> Result<Self, Error> {
        let key: act::SecretKey = act::SecretKey::from_seed(seed)?;
        let config = ModeratorConfig::new(
            endpoint,
            &key.public_key().to_bytes(),
            balance_bits,
            context,
            endorsements,
            result_retention_seconds,
        )?;
        Self::new(seed, config)
    }

    pub fn new(
        seed: &[u8; act::SEED_LENGTH],
        configuration: ModeratorConfig,
    ) -> Result<Self, Error> {
        let key = act::SecretKey::from_seed(seed)?;
        if key.public_key() != configuration.key {
            return Err(Error::Mismatch);
        }
        let challenge_key = Zeroizing::new(mac(seed, &[b"guac challenge key v1"]));
        Ok(Self {
            seed: Zeroizing::new(*seed),
            key,
            config: configuration,
            challenge_key,
            previous: None,
            policy_digest: std::sync::OnceLock::new(),
        })
    }

    /// Also redeems endorsements from `set`, the previous issuance epoch's
    /// Anchors, so endorsements issued just before a rotation stay usable.
    /// Redemption challenges then bind both sets. The configured set must be
    /// required and have a different epoch.
    pub fn accept_previous(mut self, set: AnchorSet) -> Result<Self, Error> {
        match &self.config.endorsements {
            EndorsementPolicy::Required(current) if current.epoch != set.epoch => {
                self.previous = Some(set);
                self.policy_digest = std::sync::OnceLock::new();
                Ok(self)
            }
            _ => Err(Error::Configuration(
                "previous Anchor set needs a required set with another epoch",
            )),
        }
    }

    pub fn configuration(&self) -> &ModeratorConfig {
        &self.config
    }

    /// Secret key seed export for host-managed secure storage.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; act::SEED_LENGTH]> {
        self.seed.clone()
    }

    /// Deterministic, policy-scoped challenge for the window containing `now`.
    /// Endorsement nullifiers, not challenges, enforce single use.
    pub fn redemption_challenge(&self, now: u64) -> Result<ModeratorChallenge, Error> {
        Ok(self.redemption_challenge_for(now / CHALLENGE_WINDOW_SECONDS))
    }

    fn redemption_challenge_for(&self, window: u64) -> ModeratorChallenge {
        let endorsement_type = self.config.endorsements.protocol_type();
        let policy_digest = self.policy_digest.get_or_init(|| {
            let mut policy = Vec::new();
            put_vector(&mut policy, &self.config.context);
            policy.push(self.config.balance_bits());
            if let EndorsementPolicy::Required(set) = &self.config.endorsements {
                for set in std::iter::once(set).chain(&self.previous) {
                    put_vector(&mut policy, &set.epoch);
                    for key in &set.keys {
                        policy.extend_from_slice(&key.to_bytes());
                    }
                }
            }
            digest(&policy)
        });
        ModeratorChallenge {
            endorsement_type,
            redemption_context: mac(
                &*self.challenge_key,
                &[
                    b"redeem v2",
                    self.config.endpoint.as_str().as_bytes(),
                    &endorsement_type.to_be_bytes(),
                    policy_digest,
                    &window.to_be_bytes(),
                ],
            ),
        }
    }

    /// Verifies the issuance proof and the redemption against the challenge
    /// recomputed for the current or previous window, then signs. No client
    /// echo or challenge state is needed. Nothing is recorded: see `Issuance`.
    ///
    /// A redemption under a stale or foreign challenge fails verification:
    /// `Error::Endorsement`, indistinguishable from an invalid proof.
    pub fn prepare_issuance(
        &self,
        request: &CredentialRequest,
        initial_credits: u64,
        now: u64,
    ) -> Result<Issuance, Error> {
        let window = now / CHALLENGE_WINDOW_SECONDS;
        let challenge = self.redemption_challenge_for(window);
        match self.prepare_issuance_with(request, &challenge, initial_credits) {
            Err(Error::Endorsement(_)) if window > 0 => {
                let challenge = self.redemption_challenge_for(window - 1);
                self.prepare_issuance_with(request, &challenge, initial_credits)
            }
            result => result,
        }
    }

    fn prepare_issuance_with(
        &self,
        request: &CredentialRequest,
        challenge: &ModeratorChallenge,
        initial_credits: u64,
    ) -> Result<Issuance, Error> {
        if request.endorsement_type != challenge.endorsement_type {
            return Err(Error::Mismatch);
        }
        let mut reader = Reader::new(&request.issuance)?;
        if reader.take(1)?[0] != self.config.key_id[31] || reader.vector()? != self.config.context {
            return Err(Error::Mismatch);
        }
        let issuance = act::IssueRequestMessage::from_bytes(&self.config.params, reader.rest())?;
        let replay = match &self.config.endorsements {
            EndorsementPolicy::NotRequired => {
                if !request.redemption.is_empty() {
                    return Err(Error::Malformed);
                }
                None
            }
            EndorsementPolicy::Required(set) => {
                let verify = |set: &AnchorSet| -> Result<_, Error> {
                    let redemption =
                        ec_ihat::Redemption::from_bytes(&request.redemption, set.keys.len())?;
                    let id = ec_ihat::verify_redemption(
                        &set.keys,
                        &redemption,
                        &set.epoch,
                        REDEMPTION_CONTEXT,
                        &challenge.digest(),
                    )?;
                    Ok((id, set.epoch.clone()))
                };
                // The current epoch's error wins when neither set verifies, unless
                // the redemption only decodes under the previous set's proof depth.
                Some(verify(set).or_else(|error| match &self.previous {
                    Some(previous) => verify(previous).map_err(|other| match error {
                        Error::Malformed => other,
                        error => error,
                    }),
                    None => Err(error),
                })?)
            }
        };
        let verified = act::verify_issue_request(&self.config.params, &issuance)?;
        let response = act::issue_response(
            &self.key,
            &self.config.credential_context_bytes(),
            initial_credits,
            verified,
        )?;
        Ok(Issuance {
            replay,
            response: CredentialResponse {
                body: response.to_bytes(),
            },
        })
    }

    /// `prepare_issuance` followed by the atomic replay insertion, when required.
    /// Lost issuance responses have no recovery mechanism in the current draft.
    pub fn issue(
        &self,
        store: &impl Store,
        request: &CredentialRequest,
        initial_credits: u64,
        now: u64,
    ) -> Result<CredentialResponse, Error> {
        let issuance = self.prepare_issuance(request, initial_credits, now)?;
        if let Some(id) = issuance.replay_id()
            && !store.insert_redemption(id)?
        {
            return Err(Error::Replay);
        }
        Ok(issuance.into_response())
    }

    /// Builds the challenge for `binding`, which the host derives from the
    /// request being authorized and recomputes on presentation.
    ///
    /// Empty `binding` is the policy-scoped profile: a one-use bearer
    /// authorization. Otherwise request_context is a MAC over the binding and
    /// the current time window (request-bound profile, MOLE protocols, EC-ACT Challenge Binding).
    pub fn presentation_challenge(
        &self,
        cost: u64,
        allowance: u64,
        binding: &[u8],
        now: u64,
    ) -> Result<CredentialChallenge, Error> {
        if cost > self.config.params.max_amount() || allowance > self.config.params.max_amount() {
            return Err(Error::Amount);
        }
        Ok(self.challenge_for(cost, allowance, binding, now / CHALLENGE_WINDOW_SECONDS))
    }

    fn challenge_for(
        &self,
        cost: u64,
        allowance: u64,
        binding: &[u8],
        window: u64,
    ) -> CredentialChallenge {
        let request_context = if binding.is_empty() {
            Vec::new()
        } else {
            mac(
                &*self.challenge_key,
                &[b"present", &window.to_be_bytes(), &digest(binding)],
            )
            .to_vec()
        };
        CredentialChallenge {
            cost,
            allowance,
            context: self.config.context.clone(),
            request_context,
        }
    }

    /// Parses the presentation for this key and returns its nullifier.
    pub fn nullifier(&self, presentation: &CredentialPresentation) -> Result<[u8; 32], Error> {
        Ok(self.spend(presentation)?.nullifier())
    }

    fn spend(&self, presentation: &CredentialPresentation) -> Result<act::SpendMessage, Error> {
        let mut reader = Reader::new(&presentation.body)?;
        if reader.array::<32>()? != self.config.key_id {
            return Err(Error::Mismatch);
        }
        Ok(act::SpendMessage::from_bytes(
            &self.config.params,
            reader.rest(),
        )?)
    }

    /// Verifies against the challenge recomputed from `binding`, then decides
    /// the update. Nothing is recorded: see `Acceptance`.
    ///
    /// Request-bound presentations are tried against the current window, then
    /// the previous one; a boundary-straddling presentation costs two verifies.
    pub fn verify(
        &self,
        presentation: &CredentialPresentation,
        cost: u64,
        allowance: u64,
        binding: &[u8],
        policy: UpdatePolicy,
        now: u64,
    ) -> Result<Acceptance, Error> {
        let spend = self.spend(presentation)?;
        self.accept(presentation, spend, cost, allowance, binding, policy, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn accept(
        &self,
        presentation: &CredentialPresentation,
        spend: act::SpendMessage,
        cost: u64,
        allowance: u64,
        binding: &[u8],
        policy: UpdatePolicy,
        now: u64,
    ) -> Result<Acceptance, Error> {
        if spend.amount() != cost || spend.allowance() != allowance {
            return Err(Error::Mismatch);
        }
        let window = now / CHALLENGE_WINDOW_SECONDS;
        let windows: &[u64] = if binding.is_empty() || window == 0 {
            &[window]
        } else {
            &[window, window - 1]
        };
        let context = self.config.credential_context_bytes();
        let mut result = Err(Error::Challenge);
        for window in windows {
            let challenge = self.challenge_for(cost, allowance, binding, *window);
            result = act::verify_spend(
                &self.config.params,
                &self.key,
                &context,
                &challenge.digest(),
                &spend,
            )
            .map_err(Error::from);
            if result.is_ok() {
                break;
            }
        }
        let verified = result?;
        let response = match policy {
            UpdatePolicy::Consume => None,
            UpdatePolicy::ReturnCredits(amount) => {
                Some(act::issue_refund(verified, amount)?.to_bytes())
            }
        };
        let expires_at = now
            .checked_add(self.config.retention)
            .ok_or(Error::Configuration("retention overflow"))?;
        Ok(Acceptance {
            nullifier: spend.nullifier(),
            record: PresentationRecord {
                digest: digest(&presentation.body),
                expires_at,
                update: CredentialUpdate { response },
            },
        })
    }

    /// Recovery of the exact committed result, or `verify` followed by the
    /// atomic record insertion. Recovery works after challenge expiry; answer
    /// `Recovered` with 409 and its update, without the protected operation.
    ///
    /// The record is looked up first, so retries skip verification and
    /// signing; this costs one store read per fresh presentation.
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &self,
        store: &impl Store,
        presentation: &CredentialPresentation,
        cost: u64,
        allowance: u64,
        binding: &[u8],
        policy: UpdatePolicy,
        now: u64,
    ) -> Result<PresentationOutcome, Error> {
        let spend = self.spend(presentation)?;
        let existing = match store.presentation(&spend.nullifier())? {
            Some(existing) => existing,
            None => {
                let acceptance =
                    self.accept(presentation, spend, cost, allowance, binding, policy, now)?;
                // A concurrent acceptance may have committed since the lookup.
                match store.insert_presentation(acceptance.nullifier, &acceptance.record)? {
                    None => return Ok(PresentationOutcome::Accepted(acceptance.record.update)),
                    Some(existing) => existing,
                }
            }
        };
        match existing {
            Spent::Retained(record) => Ok(PresentationOutcome::Recovered(
                record.recover(presentation, now)?,
            )),
            Spent::Expired => Err(Error::Replay),
        }
    }

    /// Lookup-only recovery (`recovery-0001` at the Redeem & Issue endpoint).
    /// Verifies no proof, signs nothing, records nothing, and never authorizes
    /// a protected operation. `Error::Replay` means unavailable: answer 404
    /// whether or not a record exists.
    pub fn recover(
        &self,
        store: &impl Store,
        handle: &RecoveryHandle,
        now: u64,
    ) -> Result<CredentialUpdate, Error> {
        match store.presentation(&handle.nullifier)? {
            Some(Spent::Retained(record)) => self.recover_from(handle, &record, now),
            _ => Err(Error::Replay),
        }
    }

    /// `recover` for async hosts, with the record found under
    /// `handle.nullifier()`. Without a retained record, answer 404.
    pub fn recover_from(
        &self,
        handle: &RecoveryHandle,
        record: &PresentationRecord,
        now: u64,
    ) -> Result<CredentialUpdate, Error> {
        if handle.key_id != self.config.key_id {
            return Err(Error::Replay);
        }
        record.recover_handle(handle, now)
    }
}

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        unreachable!("HMAC accepts any key length")
    };
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
