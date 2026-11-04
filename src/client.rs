use std::{fmt, num::NonZeroU16, sync::Arc};

use zeroize::Zeroizing;

use crate::{
    AnchorConfig, EndorsementPolicy, Error, ModeratorConfig, RedemptionScope,
    protocol::{
        ACT, CHALLENGE_LENGTH, COMMITMENT_LENGTH, CredentialChallenge, CredentialPresentation,
        CredentialRequest, CredentialResponse, CredentialUpdate, EC_IHAT, EndorsementRequest,
        EndorsementResponse, ModeratorChallenge, RESPONSE_LENGTH, Reader, RecoveryHandle,
        VECTOR_PREFIX, batch, digest, put_vector,
    },
};

/// Stateless client operations. Each exchange owns its own continuation.
#[derive(Debug, Default)]
pub struct Client;

enum GrantPhase {
    Commitments(NonZeroU16),
    Responses(Vec<ec_ihat::ClientState>),
}

/// State awaiting the next Anchor response; not a network request.
#[must_use]
pub struct PendingGrant {
    config: AnchorConfig,
    scope: RedemptionScope,
    phase: GrantPhase,
}

/// A grant either needs another exchange or has produced its endorsements.
#[derive(Debug)]
pub enum GrantStep {
    Continue {
        request: EndorsementRequest,
        pending: PendingGrant,
    },
    /// One to `count` endorsements, as many as the Anchor granted.
    Complete(Vec<Endorsement>),
}

/// A single-use client secret bound to an Anchor key, issuance epoch and Moderator domain.
#[must_use]
pub struct Endorsement {
    config: AnchorConfig,
    scope: RedemptionScope,
    token: Box<ec_ihat::Endorsement>,
}

/// The input selected for the Moderator's advertised endorsement policy.
#[derive(Debug)]
pub enum IssuanceInput {
    Endorsement(Endorsement),
    WithoutEndorsement,
}

/// State awaiting a credential issuance response.
#[must_use]
pub struct PendingIssuance {
    config: Arc<ModeratorConfig>,
    state: act::ClientIssuanceState,
}

/// A usable client credential, bound to its issuing Moderator and context.
#[must_use]
pub struct Credential {
    config: Arc<ModeratorConfig>,
    token: Box<act::Credential>,
}

/// A spent credential's continuation and exact presentation bytes.
///
/// Persist this plus the original HTTP request before sending. Restoration does
/// not make the spent credential usable; only a valid replacement does that.
#[must_use]
pub struct PendingPresentation {
    config: Arc<ModeratorConfig>,
    state: act::ClientSpendState,
    presentation: CredentialPresentation,
    nullifier: [u8; 32],
}

#[derive(Debug)]
pub enum CredentialOutcome {
    Replaced(Credential),
    Consumed,
}

/// A failed update leaves its pending presentation available for recovery.
#[derive(Debug)]
pub struct UpdateError {
    pub error: Error,
    pub pending: Box<PendingPresentation>,
}

/// A failed presentation returns the credential unspent; nothing was sent.
#[derive(Debug)]
pub struct PresentError {
    pub error: Error,
    pub credential: Credential,
}

/// A failed credential request returns its input; the endorsement is unspent.
#[derive(Debug)]
pub struct RequestError {
    pub error: Error,
    pub input: Box<IssuanceInput>,
}

macro_rules! returned_error {
    ($($name:ident),+) => { $(
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.error.fmt(f)
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.error)
            }
        }
    )+ };
}

returned_error!(UpdateError, PresentError, RequestError);

impl Client {
    /// Asks for up to `count` endorsements bound to `scope`; the Anchor may grant fewer.
    pub fn start_grant(
        &self,
        configuration: &AnchorConfig,
        count: NonZeroU16,
        scope: &RedemptionScope,
    ) -> (EndorsementRequest, PendingGrant) {
        (
            EndorsementRequest {
                body: count.get().to_be_bytes().to_vec(),
            },
            PendingGrant {
                config: configuration.clone(),
                scope: scope.clone(),
                phase: GrantPhase::Commitments(count),
            },
        )
    }

    /// Starts issuance under exactly the advertised endorsement policy.
    /// The endorsement is consumed only on success; errors return it unspent.
    pub fn request_credential(
        &self,
        input: IssuanceInput,
        configuration: &ModeratorConfig,
        challenge: &ModeratorChallenge,
    ) -> Result<(CredentialRequest, PendingIssuance), RequestError> {
        request(&input, configuration, challenge).map_err(|error| RequestError {
            error,
            input: Box::new(input),
        })
    }

    /// Consumes the credential immediately, before transmission. Errors return
    /// it unspent, e.g. `Error::Amount` when the balance cannot cover the cost.
    pub fn present(
        &self,
        credential: Credential,
        challenge: &CredentialChallenge,
    ) -> Result<PendingPresentation, PresentError> {
        present(&credential, challenge).map_err(|error| PresentError { error, credential })
    }
}

fn request(
    input: &IssuanceInput,
    configuration: &ModeratorConfig,
    challenge: &ModeratorChallenge,
) -> Result<(CredentialRequest, PendingIssuance), Error> {
    if challenge.endorsement_type != configuration.endorsements.protocol_type() {
        return Err(Error::Mismatch);
    }
    let redemption = match (input, &configuration.endorsements) {
        (IssuanceInput::WithoutEndorsement, EndorsementPolicy::NotRequired) => Vec::new(),
        (IssuanceInput::Endorsement(endorsement), EndorsementPolicy::Required(set)) => {
            if endorsement.scope != configuration.redemption_scope()?
                || endorsement.config.epoch != set.epoch
            {
                return Err(Error::Mismatch);
            }
            let index = set
                .keys
                .iter()
                .position(|key| *key == endorsement.config.key)
                .ok_or(Error::Mismatch)?;
            // Redeem consumes its input: redeem a copy so failure leaves the
            // caller's endorsement intact; success drops the original.
            let token = ec_ihat::Endorsement::from_bytes(&endorsement.token.to_bytes())?;
            ec_ihat::redeem(
                &set.keys,
                index,
                token,
                &set.epoch,
                &endorsement.scope.context(),
                &challenge.digest(),
            )?
            .to_bytes()
        }
        _ => return Err(Error::Mismatch),
    };
    let (state, request) = act::issue_request(&configuration.params)?;
    let mut issuance = vec![configuration.key_id[31]];
    put_vector(&mut issuance, &configuration.context);
    issuance.extend_from_slice(&request.to_bytes());
    Ok((
        CredentialRequest {
            endorsement_type: challenge.endorsement_type,
            redemption,
            issuance,
        },
        PendingIssuance {
            config: Arc::new(configuration.clone()),
            state,
        },
    ))
}

fn present(
    credential: &Credential,
    challenge: &CredentialChallenge,
) -> Result<PendingPresentation, Error> {
    let config = &credential.config;
    if challenge.context != config.context {
        return Err(Error::Mismatch);
    }
    // ProveSpend consumes its input: spend a copy so failure leaves the
    // caller's credential intact; success drops the original.
    let token = act::Credential::from_bytes(&config.params, &credential.token.to_bytes())?;
    let (state, spend) = act::prove_spend(
        &config.params,
        token,
        &config.credential_context_bytes(),
        challenge.cost,
        challenge.allowance,
        &challenge.digest(),
    )?;
    let mut body = config.key_id.to_vec();
    body.extend_from_slice(&spend.to_bytes());
    Ok(PendingPresentation {
        config: Arc::clone(config),
        state,
        presentation: CredentialPresentation { body },
        nullifier: spend.nullifier(),
    })
}

impl PendingGrant {
    /// Secret local state. The host atomically stores this with the exact request.
    pub fn to_storage_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut payload = Zeroizing::new(Vec::new());
        put_vector(&mut payload, self.scope.moderator_domain().as_bytes());
        match &self.phase {
            GrantPhase::Commitments(count) => {
                payload.push(0);
                payload.extend_from_slice(&count.get().to_be_bytes());
            }
            GrantPhase::Responses(states) => {
                let states: Vec<_> = states.iter().map(|state| state.to_bytes()).collect();
                // Reserve before writing secrets: growth could free an unwiped copy.
                payload.reserve(
                    1 + states
                        .iter()
                        .map(|state| VECTOR_PREFIX + state.len())
                        .sum::<usize>(),
                );
                payload.push(1);
                for state in states {
                    put_vector(&mut payload, &state);
                }
            }
        }
        secret_envelope(7, anchor_fingerprint(&self.config), &payload)
    }

    /// Reads trusted local storage; restoration never grants permission to reuse state.
    pub fn from_storage_bytes(bytes: &[u8], configuration: &AnchorConfig) -> Result<Self, Error> {
        let mut reader = Reader::trusted(read_secret(bytes, 7, anchor_fingerprint(configuration))?);
        let scope = RedemptionScope::for_moderator_domain(
            std::str::from_utf8(reader.vector()?).map_err(|_| Error::Malformed)?,
        )?;
        let phase = match reader.take(1)? {
            [0] => GrantPhase::Commitments(
                NonZeroU16::new(u16::from_be_bytes(reader.array()?)).ok_or(Error::Malformed)?,
            ),
            [1] => {
                let mut states = Vec::new();
                while !reader.is_empty() {
                    states.push(ec_ihat::ClientState::from_bytes(reader.vector()?)?);
                }
                if states.is_empty() {
                    return Err(Error::Malformed);
                }
                GrantPhase::Responses(states)
            }
            _ => return Err(Error::Malformed),
        };
        reader.finish()?;
        Ok(Self {
            config: configuration.clone(),
            scope,
            phase,
        })
    }

    /// Consumes this continuation even on invalid responses. Start a fresh grant
    /// if the final Anchor response is lost or invalid; one invalid response
    /// discards the whole batch.
    pub fn advance(self, response: &EndorsementResponse) -> Result<GrantStep, Error> {
        let mut reader = Reader::new(&response.body)?;
        match self.phase {
            GrantPhase::Commitments(count) => {
                let session: [u8; 32] = reader.array()?;
                let commitments = batch(reader.vector()?, COMMITMENT_LENGTH)?;
                reader.finish()?;
                if commitments.len() > usize::from(count.get()) {
                    return Err(Error::Malformed);
                }
                let mut states = Vec::with_capacity(commitments.len());
                let mut challenges = Vec::with_capacity(commitments.len() * CHALLENGE_LENGTH);
                for commitment in commitments {
                    let commitment = ec_ihat::CommitMessage::from_bytes(commitment)?;
                    let (state, challenge) = ec_ihat::challenge(
                        &self.config.key,
                        &self.config.epoch,
                        &self.scope.context(),
                        &commitment,
                    )?;
                    challenges.extend_from_slice(&challenge.to_bytes());
                    states.push(state);
                }
                let mut body = session.to_vec();
                put_vector(&mut body, &challenges);
                Ok(GrantStep::Continue {
                    request: EndorsementRequest { body },
                    pending: Self {
                        config: self.config,
                        scope: self.scope,
                        phase: GrantPhase::Responses(states),
                    },
                })
            }
            GrantPhase::Responses(states) => {
                let responses = batch(reader.vector()?, RESPONSE_LENGTH)?;
                reader.finish()?;
                if responses.len() != states.len() {
                    return Err(Error::Malformed);
                }
                states
                    .into_iter()
                    .zip(responses)
                    .map(|(state, response)| {
                        let response = ec_ihat::ResponseMessage::from_bytes(response)?;
                        Ok(Endorsement {
                            config: self.config.clone(),
                            scope: self.scope.clone(),
                            token: Box::new(ec_ihat::finalize(&self.config.key, state, &response)?),
                        })
                    })
                    .collect::<Result<_, Error>>()
                    .map(GrantStep::Complete)
            }
        }
    }
}

impl PendingIssuance {
    pub fn finish(self, response: &CredentialResponse) -> Result<Credential, Error> {
        let response = act::IssueResponseMessage::from_bytes(&self.config.params, &response.body)?;
        let token = act::finalize_issue(
            &self.config.params,
            &self.config.key,
            &self.config.credential_context_bytes(),
            self.state,
            &response,
        )?;
        Ok(Credential {
            config: self.config,
            token: Box::new(token),
        })
    }

    /// Whether `request` is the one that started this issuance: same Moderator
    /// key, context and issuance commitment `K`.
    #[cfg(feature = "browser")]
    pub(crate) fn binds(&self, request: &CredentialRequest) -> bool {
        // State is `k || r || K`, the request message `K || pok`.
        const STATE: usize = <act::ClientIssuanceState>::LENGTH;
        const MESSAGE: usize = <act::IssueRequestMessage>::LENGTH;
        const ELEMENT: usize = 3 * STATE - 2 * MESSAGE;
        let mut prefix = vec![self.config.key_id[31]];
        put_vector(&mut prefix, &self.config.context);
        let state = self.state.to_bytes();
        request.issuance.len() == prefix.len() + MESSAGE
            && request.issuance.starts_with(&prefix)
            && request.issuance[prefix.len()..][..ELEMENT] == state[STATE - ELEMENT..]
    }

    pub fn to_storage_bytes(&self) -> Zeroizing<Vec<u8>> {
        secret_envelope(4, self.config.fingerprint(), &self.state.to_bytes())
    }

    /// Reads trusted local secret storage, not an HTTP response.
    pub fn from_storage_bytes(
        bytes: &[u8],
        configuration: &ModeratorConfig,
    ) -> Result<Self, Error> {
        let payload = read_secret(bytes, 4, configuration.fingerprint())?;
        let state = act::ClientIssuanceState::from_bytes(&configuration.params, payload)?;
        Ok(Self {
            config: Arc::new(configuration.clone()),
            state,
        })
    }
}

impl Endorsement {
    pub fn scope(&self) -> &RedemptionScope {
        &self.scope
    }

    pub fn to_storage_bytes(&self) -> Zeroizing<Vec<u8>> {
        let token = self.token.to_bytes();
        let mut payload = Zeroizing::new(Vec::with_capacity(
            VECTOR_PREFIX + self.scope.moderator_domain().len() + token.len(),
        ));
        put_vector(&mut payload, self.scope.moderator_domain().as_bytes());
        payload.extend_from_slice(&token);
        secret_envelope(8, anchor_fingerprint(&self.config), &payload)
    }

    pub fn from_storage_bytes(bytes: &[u8], configuration: &AnchorConfig) -> Result<Self, Error> {
        let mut reader = Reader::trusted(read_secret(bytes, 8, anchor_fingerprint(configuration))?);
        let scope = RedemptionScope::for_moderator_domain(
            std::str::from_utf8(reader.vector()?).map_err(|_| Error::Malformed)?,
        )?;
        let token = ec_ihat::Endorsement::from_bytes(reader.rest())?;
        ec_ihat::verify(
            &configuration.key,
            &token,
            &configuration.epoch,
            &scope.context(),
        )?;
        Ok(Self {
            config: configuration.clone(),
            scope,
            token: Box::new(token),
        })
    }
}

impl Credential {
    pub fn balance(&self) -> u64 {
        self.token.balance()
    }
    pub fn configuration(&self) -> &ModeratorConfig {
        &self.config
    }

    pub fn to_storage_bytes(&self) -> Zeroizing<Vec<u8>> {
        secret_envelope(1, self.config.fingerprint(), &self.token.to_bytes())
    }

    /// Reads trusted local storage. Decoding is not cryptographic verification.
    /// The host must atomically remove usable storage when starting presentation.
    pub fn from_storage_bytes(
        bytes: &[u8],
        configuration: &ModeratorConfig,
    ) -> Result<Self, Error> {
        let payload = read_secret(bytes, 1, configuration.fingerprint())?;
        let token = act::Credential::from_bytes(&configuration.params, payload)?;
        Ok(Self {
            config: Arc::new(configuration.clone()),
            token: Box::new(token),
        })
    }
}

impl PendingPresentation {
    pub fn presentation(&self) -> &CredentialPresentation {
        &self.presentation
    }
    pub fn configuration(&self) -> &ModeratorConfig {
        &self.config
    }

    /// Recovers the recorded update from the Redeem & Issue endpoint
    /// (`configuration().endpoint()`) without resending the protected request.
    pub fn recovery_handle(&self) -> RecoveryHandle {
        RecoveryHandle {
            key_id: self.config.key_id,
            nullifier: self.nullifier,
            digest: digest(&self.presentation.body),
        }
    }

    pub fn finish(self, update: &CredentialUpdate) -> Result<CredentialOutcome, UpdateError> {
        let Some(response) = &update.response else {
            return Ok(CredentialOutcome::Consumed);
        };
        // Upstream consumes state on failure. Decode a temporary copy, retaining
        // the original only if verification fails; successful finish consumes it.
        let result = (|| {
            let response = act::RefundMessage::from_bytes(&self.config.params, response)?;
            let state_bytes = self.state.to_bytes();
            let state = act::ClientSpendState::from_bytes(&self.config.params, &state_bytes)?;
            Ok(act::finalize_refund(
                &self.config.params,
                &self.config.key,
                &self.config.credential_context_bytes(),
                state,
                &response,
            )?)
        })();
        match result {
            Ok(token) => Ok(CredentialOutcome::Replaced(Credential {
                config: self.config,
                token: Box::new(token),
            })),
            Err(error) => Err(UpdateError {
                error,
                pending: Box::new(self),
            }),
        }
    }

    pub fn to_storage_bytes(&self) -> Zeroizing<Vec<u8>> {
        let state = self.state.to_bytes();
        let presentation = self.presentation.to_bytes();
        // Full capacity up front: growth would free an unwiped copy of `state`.
        let mut payload = Zeroizing::new(Vec::with_capacity(
            2 * VECTOR_PREFIX + state.len() + presentation.len(),
        ));
        put_vector(&mut payload, &state);
        put_vector(&mut payload, &presentation);
        secret_envelope(2, self.config.fingerprint(), &payload)
    }

    pub fn from_storage_bytes(
        bytes: &[u8],
        configuration: &ModeratorConfig,
    ) -> Result<Self, Error> {
        let mut payload = Reader::trusted(read_secret(bytes, 2, configuration.fingerprint())?);
        let state = act::ClientSpendState::from_bytes(&configuration.params, payload.vector()?)?;
        let presentation = CredentialPresentation::from_bytes(payload.vector()?)?;
        payload.finish()?;
        let mut body = Reader::new(&presentation.body)?;
        if body.array::<32>()? != configuration.key_id {
            return Err(Error::Mismatch);
        }
        let spend: act::SpendMessage =
            act::SpendMessage::from_bytes(&configuration.params, body.rest())?;
        Ok(Self {
            config: Arc::new(configuration.clone()),
            state,
            presentation,
            nullifier: spend.nullifier(),
        })
    }
}

pub(crate) fn anchor_fingerprint(config: &AnchorConfig) -> [u8; 32] {
    let mut bytes = config.public_key().to_vec();
    put_vector(&mut bytes, &config.epoch);
    digest(&bytes)
}

pub(crate) fn secret_envelope(
    kind: u8,
    fingerprint: [u8; 32],
    secret: &[u8],
) -> Zeroizing<Vec<u8>> {
    // magic || kind || protocol || fingerprint || vector(secret), preallocated.
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        5 + 1 + 2 + 32 + VECTOR_PREFIX + secret.len(),
    ));
    bytes.extend_from_slice(b"GUAC\x02");
    bytes.push(kind);
    let protocol = if matches!(kind, 6..=8) { EC_IHAT } else { ACT };
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(&fingerprint);
    put_vector(&mut bytes, secret);
    bytes
}

pub(crate) fn read_secret(bytes: &[u8], kind: u8, fingerprint: [u8; 32]) -> Result<&[u8], Error> {
    let mut reader = Reader::trusted(bytes);
    if reader.take(5)? != b"GUAC\x02" || reader.take(1)? != [kind] {
        return Err(Error::Malformed);
    }
    reader.protocol(&[if matches!(kind, 6..=8) { EC_IHAT } else { ACT }])?;
    if reader.array::<32>()? != fingerprint {
        return Err(Error::Mismatch);
    }
    let payload = reader.vector()?;
    reader.finish()?;
    Ok(payload)
}

impl fmt::Debug for PendingGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            GrantPhase::Commitments(_) => "commitments",
            GrantPhase::Responses(_) => "responses",
        };
        f.debug_struct("PendingGrant")
            .field("phase", &phase)
            .finish_non_exhaustive()
    }
}

macro_rules! redacted_debug {
    ($($name:ident),+) => { $(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+ };
}

redacted_debug!(
    Endorsement,
    Credential,
    PendingIssuance,
    PendingPresentation
);
