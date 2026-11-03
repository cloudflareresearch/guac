//! HTTP carriage (draft-jms-mole-http-transport): the `Mole` authentication
//! scheme, the `Mole-Credential` field, and grant media types.
//!
//! `http-auth` parses the auth-param grammar (RFC 9110 §11); this module adds
//! MOLE's typed parameters. Header values are produced with `Display`.
//!
//! ```
//! use guac::http::{Authorization, Challenge};
//!
//! let challenges = Challenge::parse(["Basic realm=\"x\", Mole endorse-0002=\"\""]);
//! assert_eq!(challenges, [Challenge::Endorse]);
//! assert!(Authorization::parse("Basic dXNlcg==").unwrap().is_none());
//! ```

use std::{collections::HashSet, fmt};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_auth::{ChallengeRef, parser::ChallengeParser};

use crate::{
    Error, ModeratorConfig,
    protocol::{
        ACT, CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialResponse,
        CredentialUpdate, EC_IHAT, MAX_MESSAGE_BYTES, ModeratorChallenge, RecoveryHandle,
        check_type,
    },
};

pub(crate) const SCHEME: &str = "Mole";
/// `Content-Type` of EC-IHAT grant requests.
pub const ENDORSEMENT_REQUEST: &str = "application/mole-endorsement-request; type=0002";
/// `Content-Type` of EC-IHAT grant responses.
pub const ENDORSEMENT_RESPONSE: &str = "application/mole-endorsement-response; type=0002";

/// Base64url grows payloads by a third; quoting and names add little.
const MAX_FIELD_BYTES: usize = 2 * MAX_MESSAGE_BYTES;

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical unpadded base64url only.
fn decode(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Malformed)?;
    if encode(&bytes) != value {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Endorse,
    Redeem,
    Challenge,
    CredentialRequest,
    Presentation,
    Recovery,
    Response,
    Update,
}

const OPERATIONS: [(&str, Op); 8] = [
    ("endorse", Op::Endorse),
    ("redeem", Op::Redeem),
    ("challenge", Op::Challenge),
    ("credential-request", Op::CredentialRequest),
    ("presentation", Op::Presentation),
    ("recovery", Op::Recovery),
    ("response", Op::Response),
    ("update", Op::Update),
];

/// `Ok(None)` for unreserved names, which are ignored. A reserved prefix
/// without exactly four hexadecimal digits is malformed.
fn operation(name: &str) -> Result<Option<(Op, u16)>, Error> {
    let name = name.to_ascii_lowercase();
    for (prefix, op) in OPERATIONS {
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        if !rest.is_empty() && !rest.starts_with('-') {
            continue;
        }
        let digits = rest.strip_prefix('-').ok_or(Error::Malformed)?;
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Malformed);
        }
        let kind = u16::from_str_radix(digits, 16).map_err(|_| Error::Malformed)?;
        if kind == 0 {
            return Err(Error::Malformed);
        }
        return Ok(Some((op, kind)));
    }
    Ok(None)
}

struct Payload {
    op: Op,
    kind: u16,
    value: Vec<u8>,
}

/// Payload parameters, rejecting duplicate names and noncanonical values.
fn payloads(challenge: &ChallengeRef<'_>) -> Result<Vec<Payload>, Error> {
    let mut names = HashSet::with_capacity(challenge.params.len());
    let mut out = Vec::new();
    for (name, value) in &challenge.params {
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(Error::Malformed);
        }
        if let Some((op, kind)) = operation(name)? {
            out.push(Payload {
                op,
                kind,
                value: decode(&value.to_unescaped())?,
            });
        }
    }
    Ok(out)
}

/// The single scheme-prefixed item in `value`, or `None` for another scheme.
fn single(value: &str) -> Result<Option<ChallengeRef<'_>>, Error> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(Error::Malformed);
    }
    let scheme = value.trim_start().split([' ', '\t']).next().unwrap_or("");
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return Ok(None);
    }
    let mut parser = ChallengeParser::new(value.trim());
    match (parser.next(), parser.next()) {
        (Some(Ok(item)), None) => Ok(Some(item)),
        _ => Err(Error::Malformed),
    }
}

/// A supported `Mole` challenge from `WWW-Authenticate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// `endorse-0002`: the resource asks for a EC-IHAT grant.
    Endorse,
    /// `redeem-E`: Redeem & Issue under endorsement type `E`.
    Redeem(ModeratorChallenge),
    /// `challenge-0001`: present an ACT credential.
    Present(CredentialChallenge),
}

impl Challenge {
    /// Supported challenges from `WWW-Authenticate` field values, in order.
    /// Malformed, unknown-type and other-scheme challenges are skipped.
    pub fn parse<'a>(fields: impl IntoIterator<Item = &'a str>) -> Vec<Self> {
        fields
            .into_iter()
            .filter(|field| field.len() <= MAX_FIELD_BYTES)
            // A syntax error ends the field; earlier challenges stay usable.
            .flat_map(|field| ChallengeParser::new(field).map_while(Result::ok))
            .filter(|challenge| challenge.scheme.eq_ignore_ascii_case(SCHEME))
            .filter_map(|challenge| Self::from_ref(&challenge).ok())
            .collect()
    }

    /// The redemption challenge for `configuration`'s endorsement policy.
    pub fn redemption<'a>(
        challenges: &'a [Self],
        configuration: &ModeratorConfig,
    ) -> Option<&'a ModeratorChallenge> {
        challenges.iter().find_map(|challenge| match challenge {
            Self::Redeem(c) if c.endorsement_type == configuration.endorsements.protocol_type() => {
                Some(c)
            }
            _ => None,
        })
    }

    /// The credential challenge for `configuration`'s credential context.
    pub fn presentation<'a>(
        challenges: &'a [Self],
        configuration: &ModeratorConfig,
    ) -> Option<&'a CredentialChallenge> {
        challenges.iter().find_map(|challenge| match challenge {
            Self::Present(c) if c.context == configuration.context => Some(c),
            _ => None,
        })
    }

    fn from_ref(challenge: &ChallengeRef<'_>) -> Result<Self, Error> {
        let [payload]: [Payload; 1] = payloads(challenge)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        match payload.op {
            Op::Endorse => {
                check_type(payload.kind, &[EC_IHAT])?;
                if !payload.value.is_empty() {
                    return Err(Error::Malformed);
                }
                Ok(Self::Endorse)
            }
            Op::Redeem => {
                ModeratorChallenge::from_parts(payload.kind, &payload.value).map(Self::Redeem)
            }
            Op::Challenge => {
                check_type(payload.kind, &[ACT])?;
                CredentialChallenge::from_bytes(&payload.value).map(Self::Present)
            }
            _ => Err(Error::Malformed),
        }
    }
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endorse => write!(f, "{SCHEME} endorse-{EC_IHAT:04x}=\"\""),
            Self::Redeem(challenge) => write!(
                f,
                "{SCHEME} redeem-{:04x}=\"{}\"",
                challenge.endorsement_type,
                encode(&challenge.redemption_context)
            ),
            Self::Present(challenge) => write!(
                f,
                "{SCHEME} challenge-{ACT:04x}=\"{}\"",
                encode(&challenge.to_bytes())
            ),
        }
    }
}

/// A `Mole` credential from the `Authorization` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorization {
    /// `redeem-E` with `credential-request-0001`.
    Issue(CredentialRequest),
    /// `presentation-0001`.
    Present(CredentialPresentation),
    /// `recovery-0001`, sent to the Redeem & Issue endpoint.
    Recover(RecoveryHandle),
}

impl Authorization {
    /// `Ok(None)`: another scheme, so MOLE is not attempted. An unknown
    /// presentation type is `Error::Unsupported`; a host for which
    /// presentation is optional treats it as absent.
    pub fn parse(field: &str) -> Result<Option<Self>, Error> {
        let Some(credential) = single(field)? else {
            return Ok(None);
        };
        let payloads = payloads(&credential)?;
        fn act(payload: &Payload) -> Result<&[u8], Error> {
            check_type(payload.kind, &[ACT]).map(|_| payload.value.as_slice())
        }
        Ok(Some(match payloads.as_slice() {
            [p] if p.op == Op::Presentation => {
                Self::Present(CredentialPresentation::from_bytes(act(p)?)?)
            }
            [p] if p.op == Op::Recovery => Self::Recover(RecoveryHandle::from_bytes(act(p)?)?),
            [a, b] => {
                let (redeem, request) = match (a.op, b.op) {
                    (Op::Redeem, Op::CredentialRequest) => (a, b),
                    (Op::CredentialRequest, Op::Redeem) => (b, a),
                    _ => return Err(Error::Malformed),
                };
                Self::Issue(CredentialRequest::from_parts(
                    redeem.kind,
                    &redeem.value,
                    act(request)?,
                )?)
            }
            _ => return Err(Error::Malformed),
        }))
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issue(request) => write!(
                f,
                "{SCHEME} redeem-{:04x}=\"{}\", credential-request-{ACT:04x}=\"{}\"",
                request.endorsement_type,
                encode(&request.redemption),
                encode(&request.issuance)
            ),
            Self::Present(presentation) => write!(
                f,
                "{SCHEME} presentation-{ACT:04x}=\"{}\"",
                encode(&presentation.body)
            ),
            Self::Recover(handle) => write!(
                f,
                "{SCHEME} recovery-{ACT:04x}=\"{}\"",
                encode(&handle.to_bytes())
            ),
        }
    }
}

/// The `Mole-Credential` response field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialField {
    /// `response-0001`: an issued credential.
    Response(CredentialResponse),
    /// `update-0001`: the recorded presentation result, empty for consumption.
    Update(CredentialUpdate),
}

impl CredentialField {
    /// Parses every `Mole-Credential` field value of a response. `Ok(None)`:
    /// absent, which carries no credential decision. Process the field
    /// whatever the response status.
    pub fn parse<'a>(fields: impl IntoIterator<Item = &'a str>) -> Result<Option<Self>, Error> {
        let mut fields = fields.into_iter();
        let Some(field) = fields.next() else {
            return Ok(None);
        };
        if fields.next().is_some() {
            return Err(Error::Malformed);
        }
        let scoped = format!("{SCHEME} {}", field.trim());
        let item = single(&scoped)?.ok_or(Error::Malformed)?;
        if item.params.len() != 1 {
            return Err(Error::Malformed);
        }
        let [payload]: [Payload; 1] = payloads(&item)?.try_into().map_err(|_| Error::Malformed)?;
        let value = match payload.op {
            Op::Response | Op::Update => check_type(payload.kind, &[ACT]).map(|_| payload.value)?,
            _ => return Err(Error::Malformed),
        };
        Ok(Some(match payload.op {
            Op::Response => Self::Response(CredentialResponse::from_bytes(&value)?),
            _ => Self::Update(CredentialUpdate::from_bytes(&value)?),
        }))
    }
}

impl fmt::Display for CredentialField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(response) => {
                write!(f, "response-{ACT:04x}=\"{}\"", encode(&response.body))
            }
            Self::Update(update) => {
                write!(f, "update-{ACT:04x}=\"{}\"", encode(&update.to_bytes()))
            }
        }
    }
}

/// Checks a grant `Content-Type` value against `ENDORSEMENT_REQUEST` or
/// `ENDORSEMENT_RESPONSE`, including its required `type` parameter.
pub fn check_content_type(value: &str, expected: &str) -> Result<(), Error> {
    let essence = expected.split(';').next().unwrap_or(expected);
    let mut parts = value.split(';');
    if !parts
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case(essence)
    {
        return Err(Error::Mismatch);
    }
    let types: Vec<&str> = parts
        .filter_map(|part| part.split_once('='))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("type"))
        .map(|(_, value)| value.trim().trim_matches('"'))
        .collect();
    match types.as_slice() {
        [kind] if kind.eq_ignore_ascii_case("0002") => Ok(()),
        _ => Err(Error::Mismatch),
    }
}
