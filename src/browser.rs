//! Browser client bindings. Secret storage and HTTP remain the host's responsibility.
//!
//! Protocol messages travel as HTTP header values: pass `WWW-Authenticate`
//! and `Mole-Credential` as received, send `authorization` as `Authorization`.
//! Grant bodies are bytes with `ENDORSEMENT_REQUEST`/`ENDORSEMENT_RESPONSE`
//! media types.
//!
//! Errors are `Error` objects with a stable string `code`: the `crate::Error`
//! variant in lower case (`amount`, `malformed`, `mismatch`, …), `consumed`
//! for a handle whose state was already used, `state` for a grant step
//! called in the wrong phase, or `missing` for an absent `Mole-Credential`.
//!
//! Every call is synchronous and CPU-bound (a presentation takes tens of
//! milliseconds): run the module in a Web Worker and reuse configurations.

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    Error,
    http::{self, Authorization, Challenge, CredentialField},
    protocol,
};

fn code(error: &Error) -> &'static str {
    match error {
        Error::Configuration(_) => "configuration",
        Error::Malformed => "malformed",
        Error::Unsupported(_) => "unsupported",
        Error::Mismatch => "mismatch",
        Error::Challenge => "challenge",
        Error::Replay => "replay",
        Error::Retired => "retired",
        Error::Amount => "amount",
        Error::Session => "session",
        Error::Storage(_) => "storage",
        Error::Entropy => "entropy",
        Error::Endorsement(_) => "endorsement",
        Error::Credential(_) => "credential",
    }
}

fn js_error(message: &str, code: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    // Setting a data property on a fresh Error object cannot fail.
    let _ = js_sys::Reflect::set(&error, &"code".into(), &code.into());
    error.into()
}

impl From<Error> for JsValue {
    fn from(error: Error) -> Self {
        js_error(&error.to_string(), code(&error))
    }
}

fn consumed(what: &str) -> JsValue {
    js_error(&format!("{what} already consumed"), "consumed")
}

fn public_key(bytes: &[u8]) -> Result<[u8; 33], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Configuration("public key length"))
}

/// Takes ownership of wasm-bindgen's input copy so it is wiped on every path.
fn secret(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes)
}

/// `Mole-Credential` as returned by `Headers.get`; `null` carries no decision.
fn credential_field(value: Option<String>) -> Result<CredentialField, JsValue> {
    CredentialField::parse(value.as_deref())?.ok_or_else(|| {
        js_error(
            "response carries no Mole-Credential; pending state retained",
            "missing",
        )
    })
}

/// `Content-Type` of grant requests.
#[wasm_bindgen(js_name = endorsementRequestType)]
pub fn endorsement_request_type() -> String {
    http::ENDORSEMENT_REQUEST.into()
}

#[wasm_bindgen]
pub struct AnchorConfig(crate::AnchorConfig);

#[wasm_bindgen]
impl AnchorConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], epoch: Vec<u8>) -> Result<AnchorConfig, JsValue> {
        Ok(Self(crate::AnchorConfig::new(&public_key(key)?, epoch)?))
    }
}

#[wasm_bindgen]
pub struct ModeratorConfig(crate::ModeratorConfig);

#[wasm_bindgen]
impl ModeratorConfig {
    #[wasm_bindgen(js_name = withoutEndorsement)]
    pub fn without_endorsement(
        endpoint: &str,
        key: &[u8],
        balance_bits: u8,
        context: Vec<u8>,
        retention: u64,
    ) -> Result<ModeratorConfig, JsValue> {
        Ok(Self(crate::ModeratorConfig::new(
            endpoint,
            &public_key(key)?,
            balance_bits,
            context,
            crate::EndorsementPolicy::NotRequired,
            retention,
        )?))
    }

    /// Anchor keys are concatenated 33-byte public keys in their advertised order.
    #[wasm_bindgen(js_name = withEndorsements)]
    pub fn with_endorsements(
        endpoint: &str,
        key: &[u8],
        balance_bits: u8,
        context: Vec<u8>,
        retention: u64,
        anchor_keys: &[u8],
        epoch: &[u8],
    ) -> Result<ModeratorConfig, JsValue> {
        let (keys, remainder) = anchor_keys.as_chunks::<33>();
        if !remainder.is_empty() {
            return Err(Error::Configuration("Anchor public key length").into());
        }
        if keys.len() > usize::from(u16::MAX)
            || epoch.len().saturating_mul(keys.len()) > protocol::MAX_MESSAGE_BYTES
        {
            return Err(Error::Configuration("Anchor configuration too large").into());
        }
        let anchors = keys
            .iter()
            .map(|key| crate::AnchorConfig::new(&public_key(key)?, epoch.to_vec()))
            .collect::<Result<Vec<_>, Error>>()?;
        let policy = crate::EndorsementPolicy::Required(crate::AnchorSet::new(&anchors)?);
        Ok(Self(crate::ModeratorConfig::new(
            endpoint,
            &public_key(key)?,
            balance_bits,
            context,
            policy,
            retention,
        )?))
    }

    #[wasm_bindgen(getter, js_name = moderatorDomain)]
    pub fn moderator_domain(&self) -> Result<String, JsValue> {
        Ok(self.0.redemption_scope()?.moderator_domain().to_owned())
    }

    /// The Redeem & Issue endpoint, which also answers recovery.
    #[wasm_bindgen(getter)]
    pub fn endpoint(&self) -> String {
        self.0.endpoint().to_string()
    }
}

#[wasm_bindgen]
pub struct PendingGrant {
    request: protocol::EndorsementRequest,
    pending: Option<crate::PendingGrant>,
}

/// Asks for up to `count` (1 to 65535) endorsements scoped to `moderator_domain`.
#[wasm_bindgen(js_name = startGrant)]
pub fn start_grant(
    configuration: &AnchorConfig,
    count: u16,
    moderator_domain: &str,
) -> Result<PendingGrant, JsValue> {
    let count = std::num::NonZeroU16::new(count).ok_or(crate::Error::Malformed)?;
    let (request, pending) = crate::Client.start_grant(
        &configuration.0,
        count,
        &crate::RedemptionScope::for_moderator_domain(moderator_domain)?,
    );
    Ok(PendingGrant {
        request,
        pending: Some(pending),
    })
}

#[wasm_bindgen]
impl PendingGrant {
    #[wasm_bindgen(js_name = toStorageBytes)]
    pub fn to_storage_bytes(&self) -> Result<Uint8Array, JsValue> {
        let pending = self.pending.as_ref().ok_or_else(|| consumed("grant"))?;
        Ok(Uint8Array::from(pending.to_storage_bytes().as_slice()))
    }

    #[wasm_bindgen(js_name = fromStorageBytes)]
    pub fn from_storage_bytes(
        bytes: Vec<u8>,
        original_request: &[u8],
        configuration: &AnchorConfig,
    ) -> Result<PendingGrant, JsValue> {
        let bytes = secret(bytes);
        Ok(Self {
            request: protocol::EndorsementRequest::from_bytes(original_request)?,
            pending: Some(crate::PendingGrant::from_storage_bytes(
                &bytes,
                &configuration.0,
            )?),
        })
    }

    /// The request body; send it with `endorsementRequestType()`.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.to_bytes()
    }

    /// A wrong `Content-Type` or malformed body retains this continuation; an
    /// invalid response consumes it.
    pub fn advance(&mut self, response: &[u8], content_type: &str) -> Result<GrantStep, JsValue> {
        http::check_content_type(content_type, http::ENDORSEMENT_RESPONSE)?;
        let response = protocol::EndorsementResponse::from_bytes(response)?;
        let pending = self.pending.take().ok_or_else(|| consumed("grant"))?;
        Ok(GrantStep(pending.advance(&response)?))
    }
}

#[wasm_bindgen]
pub struct GrantStep(crate::GrantStep);

#[wasm_bindgen]
impl GrantStep {
    #[wasm_bindgen(getter, js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        matches!(self.0, crate::GrantStep::Complete(_))
    }

    #[wasm_bindgen(js_name = continueGrant)]
    pub fn continue_grant(self) -> Result<PendingGrant, JsValue> {
        match self.0 {
            crate::GrantStep::Continue { request, pending } => Ok(PendingGrant {
                request,
                pending: Some(pending),
            }),
            crate::GrantStep::Complete(_) => Err(js_error("grant already complete", "state")),
        }
    }

    pub fn finish(self) -> Result<Vec<Endorsement>, JsValue> {
        match self.0 {
            crate::GrantStep::Complete(endorsements) => Ok(endorsements
                .into_iter()
                .map(|endorsement| Endorsement(Some(endorsement)))
                .collect()),
            crate::GrantStep::Continue { .. } => {
                Err(js_error("grant needs another exchange", "state"))
            }
        }
    }
}

/// Emptied only by a successful `requestCredential`.
#[wasm_bindgen]
pub struct Endorsement(Option<crate::Endorsement>);

#[wasm_bindgen]
impl Endorsement {
    #[wasm_bindgen(getter, js_name = moderatorDomain)]
    pub fn moderator_domain(&self) -> Result<String, JsValue> {
        let endorsement = self.0.as_ref().ok_or_else(|| consumed("endorsement"))?;
        Ok(endorsement.scope().moderator_domain().to_owned())
    }

    #[wasm_bindgen(js_name = toStorageBytes)]
    pub fn to_storage_bytes(&self) -> Result<Uint8Array, JsValue> {
        let endorsement = self.0.as_ref().ok_or_else(|| consumed("endorsement"))?;
        Ok(Uint8Array::from(endorsement.to_storage_bytes().as_slice()))
    }

    #[wasm_bindgen(js_name = fromStorageBytes)]
    pub fn from_storage_bytes(
        bytes: Vec<u8>,
        configuration: &AnchorConfig,
    ) -> Result<Endorsement, JsValue> {
        let bytes = secret(bytes);
        Ok(Self(Some(crate::Endorsement::from_storage_bytes(
            &bytes,
            &configuration.0,
        )?)))
    }
}

/// Emptied by `finish` once the response field parses.
#[wasm_bindgen]
pub struct PendingIssuance {
    authorization: String,
    pending: Option<crate::PendingIssuance>,
}

impl PendingIssuance {
    fn pending(&self) -> Result<&crate::PendingIssuance, JsValue> {
        self.pending.as_ref().ok_or_else(|| consumed("issuance"))
    }
}

/// Requests a credential from a Moderator that requires no endorsement.
/// `www_authenticate` is the Redeem & Issue endpoint's challenge field.
#[wasm_bindgen(js_name = requestCredential)]
pub fn request_credential(
    configuration: &ModeratorConfig,
    www_authenticate: &str,
) -> Result<PendingIssuance, JsValue> {
    request(configuration, www_authenticate, None)
}

#[wasm_bindgen]
impl Endorsement {
    /// Redeems this endorsement. Consumed only on success; on error it stays usable.
    #[wasm_bindgen(js_name = requestCredential)]
    pub fn request_credential(
        &mut self,
        configuration: &ModeratorConfig,
        www_authenticate: &str,
    ) -> Result<PendingIssuance, JsValue> {
        request(configuration, www_authenticate, Some(self))
    }
}

// wasm-bindgen cannot take `Option<&mut Endorsement>`, hence two entry points.
fn request(
    configuration: &ModeratorConfig,
    www_authenticate: &str,
    endorsement: Option<&mut Endorsement>,
) -> Result<PendingIssuance, JsValue> {
    let challenges = Challenge::parse([www_authenticate]);
    let challenge = Challenge::redemption(&challenges, &configuration.0).ok_or(Error::Challenge)?;
    let (input, slot) = match endorsement {
        Some(handle) => {
            let endorsement = handle.0.take().ok_or_else(|| consumed("endorsement"))?;
            (crate::IssuanceInput::Endorsement(endorsement), Some(handle))
        }
        None => (crate::IssuanceInput::WithoutEndorsement, None),
    };
    match crate::Client.request_credential(input, &configuration.0, challenge) {
        Ok((request, pending)) => Ok(PendingIssuance {
            authorization: Authorization::Issue(request).to_string(),
            pending: Some(pending),
        }),
        Err(failure) => {
            if let (Some(handle), crate::IssuanceInput::Endorsement(endorsement)) =
                (slot, *failure.input)
            {
                handle.0 = Some(endorsement);
            }
            Err(failure.error.into())
        }
    }
}

#[wasm_bindgen]
impl PendingIssuance {
    /// The `Authorization` value to POST to the Redeem & Issue endpoint.
    #[wasm_bindgen(getter)]
    pub fn authorization(&self) -> String {
        self.authorization.clone()
    }

    /// `mole_credential` is the response's `Mole-Credential` field. A missing
    /// or malformed field retains the pending state; an invalid issuance
    /// response consumes it, since issuance has no recovery.
    pub fn finish(&mut self, mole_credential: Option<String>) -> Result<Credential, JsValue> {
        let CredentialField::Response(response) = credential_field(mole_credential)? else {
            return Err(Error::Malformed.into());
        };
        let pending = self.pending.take().ok_or_else(|| consumed("issuance"))?;
        Ok(Credential(Some(pending.finish(&response)?)))
    }

    #[wasm_bindgen(js_name = toStorageBytes)]
    pub fn to_storage_bytes(&self) -> Result<Uint8Array, JsValue> {
        Ok(Uint8Array::from(
            self.pending()?.to_storage_bytes().as_slice(),
        ))
    }

    #[wasm_bindgen(js_name = fromStorageBytes)]
    pub fn from_storage_bytes(
        bytes: Vec<u8>,
        authorization: &str,
        configuration: &ModeratorConfig,
    ) -> Result<PendingIssuance, JsValue> {
        let bytes = secret(bytes);
        let Some(Authorization::Issue(request)) = Authorization::parse(authorization)? else {
            return Err(Error::Malformed.into());
        };
        let pending = crate::PendingIssuance::from_storage_bytes(&bytes, &configuration.0)?;
        if !pending.binds(&request) {
            return Err(Error::Mismatch.into());
        }
        Ok(Self {
            authorization: authorization.to_owned(),
            pending: Some(pending),
        })
    }
}

/// Emptied only by a successful `present`.
#[wasm_bindgen]
pub struct Credential(Option<crate::Credential>);

impl Credential {
    fn credential(&self) -> Result<&crate::Credential, JsValue> {
        self.0.as_ref().ok_or_else(|| consumed("credential"))
    }
}

#[wasm_bindgen]
impl Credential {
    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> Result<u64, JsValue> {
        Ok(self.credential()?.balance())
    }

    /// Answers the protected resource's `WWW-Authenticate` field. Consumes
    /// this credential only on success; on error it stays usable.
    pub fn present(&mut self, www_authenticate: &str) -> Result<PendingPresentation, JsValue> {
        let challenges = Challenge::parse([www_authenticate]);
        let challenge = Challenge::presentation(&challenges, self.credential()?.configuration())
            .ok_or(Error::Challenge)?;
        let credential = self.0.take().ok_or_else(|| consumed("credential"))?;
        match crate::Client.present(credential, challenge) {
            Ok(pending) => Ok(PendingPresentation {
                pending: Some(pending),
            }),
            Err(failure) => {
                self.0 = Some(failure.credential);
                Err(failure.error.into())
            }
        }
    }

    #[wasm_bindgen(js_name = toStorageBytes)]
    pub fn to_storage_bytes(&self) -> Result<Uint8Array, JsValue> {
        Ok(Uint8Array::from(
            self.credential()?.to_storage_bytes().as_slice(),
        ))
    }

    #[wasm_bindgen(js_name = fromStorageBytes)]
    pub fn from_storage_bytes(
        bytes: Vec<u8>,
        configuration: &ModeratorConfig,
    ) -> Result<Credential, JsValue> {
        let bytes = secret(bytes);
        Ok(Self(Some(crate::Credential::from_storage_bytes(
            &bytes,
            &configuration.0,
        )?)))
    }
}

#[wasm_bindgen]
pub struct PendingPresentation {
    pending: Option<crate::PendingPresentation>,
}

impl PendingPresentation {
    fn pending(&self) -> Result<&crate::PendingPresentation, JsValue> {
        self.pending
            .as_ref()
            .ok_or_else(|| consumed("presentation"))
    }
}

#[wasm_bindgen]
impl PendingPresentation {
    /// The `Authorization` value for the protected request.
    #[wasm_bindgen(getter)]
    pub fn authorization(&self) -> Result<String, JsValue> {
        Ok(Authorization::Present(self.pending()?.presentation().clone()).to_string())
    }

    /// The `Authorization` value for an empty POST to the Redeem & Issue
    /// endpoint: recovers the recorded update without repeating the operation.
    #[wasm_bindgen(getter, js_name = recoveryAuthorization)]
    pub fn recovery_authorization(&self) -> Result<String, JsValue> {
        Ok(Authorization::Recover(self.pending()?.recovery_handle()).to_string())
    }

    /// `mole_credential` is the response's `Mole-Credential` field, whatever
    /// its status. Returns a replacement, or undefined for explicit
    /// consumption. Failure, including a missing field, retains pending state.
    pub fn finish(
        &mut self,
        mole_credential: Option<String>,
    ) -> Result<Option<Credential>, JsValue> {
        let CredentialField::Update(update) = credential_field(mole_credential)? else {
            return Err(Error::Malformed.into());
        };
        let pending = self
            .pending
            .take()
            .ok_or_else(|| consumed("presentation"))?;
        match pending.finish(&update) {
            Ok(crate::CredentialOutcome::Replaced(credential)) => {
                Ok(Some(Credential(Some(credential))))
            }
            Ok(crate::CredentialOutcome::Consumed) => Ok(None),
            Err(error) => {
                self.pending = Some(*error.pending);
                Err(error.error.into())
            }
        }
    }

    #[wasm_bindgen(js_name = toStorageBytes)]
    pub fn to_storage_bytes(&self) -> Result<Uint8Array, JsValue> {
        Ok(Uint8Array::from(
            self.pending()?.to_storage_bytes().as_slice(),
        ))
    }

    #[wasm_bindgen(js_name = fromStorageBytes)]
    pub fn from_storage_bytes(
        bytes: Vec<u8>,
        configuration: &ModeratorConfig,
    ) -> Result<PendingPresentation, JsValue> {
        let bytes = secret(bytes);
        Ok(Self {
            pending: Some(crate::PendingPresentation::from_storage_bytes(
                &bytes,
                &configuration.0,
            )?),
        })
    }
}
