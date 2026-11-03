//! Anchor and Moderator configurations: discovery, validation, and snapshots.
//!
//! JSON per MOLE protocols, Key Rotation and Discovery. Unknown members are
//! ignored; entries of unknown types or ciphersuites are skipped.

use anyhow::{Context, Result, bail};
use guac::{AnchorConfig, AnchorSet, EndorsementPolicy, ModeratorConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::http::{self, Access};

const NO_ENDORSEMENT: u64 = 1;
const EC_IHAT: u64 = 2;
const ACT: u64 = 1;
const CIPHERSUITE: &str = "P256-SHA256";

/// Base64url serde for byte fields in stored JSON.
pub(crate) mod b64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::http::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        crate::http::decode(&String::deserialize(d)?)
            .ok_or_else(|| D::Error::custom("invalid base64url"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorKey {
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    #[serde(with = "b64")]
    pub epoch: Vec<u8>,
}

impl AnchorKey {
    pub fn config(&self) -> Result<AnchorConfig> {
        let key: &[u8; 33] = self
            .key
            .as_slice()
            .try_into()
            .context("Anchor key length")?;
        Ok(AnchorConfig::new(key, self.epoch.clone())?)
    }
}

/// Public Anchor configuration, as fetched from its directory URL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorDirectory {
    pub url: Url,
    pub access: Access,
    pub grant_uri: Url,
    /// Present when grants need browser approval first.
    pub authorization_uri: Option<Url>,
    pub anchor: AnchorKey,
}

/// One accepted endorsement entry from Moderator configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accepted {
    /// Type 1: issuance without an endorsement.
    NoEndorsement,
    /// Type 2: one Anchor set sharing an epoch. Ordered: redemption proofs
    /// match keys by position.
    EcIhat(Vec<AnchorKey>),
}

/// Public Moderator configuration for one credential key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModeratorDirectory {
    pub url: Url,
    pub access: Access,
    pub issuance_uri: Url,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    pub balance_width: u8,
    #[serde(with = "b64")]
    pub context: Vec<u8>,
    pub retention: u64,
    /// Supported entries, in published order.
    pub endorsements: Vec<Accepted>,
}

impl ModeratorDirectory {
    /// For credentials and presentations, which the endorsement policy does
    /// not affect.
    pub fn config(&self) -> Result<ModeratorConfig> {
        self.config_for(&Accepted::NoEndorsement)
    }

    /// For Redeem & Issue under one accepted entry.
    pub fn config_for(&self, accepted: &Accepted) -> Result<ModeratorConfig> {
        let key: &[u8; 33] = self
            .key
            .as_slice()
            .try_into()
            .context("credential key length")?;
        let policy = match accepted {
            Accepted::NoEndorsement => EndorsementPolicy::NotRequired,
            Accepted::EcIhat(anchors) => {
                let anchors = anchors
                    .iter()
                    .map(AnchorKey::config)
                    .collect::<Result<Vec<_>>>()?;
                EndorsementPolicy::Required(AnchorSet::new(&anchors)?)
            }
        };
        Ok(ModeratorConfig::new(
            self.issuance_uri.as_str(),
            key,
            self.balance_width,
            self.context.clone(),
            policy,
            self.retention,
        )?)
    }
}

fn get(url: &Url, access: Access) -> Result<Value> {
    let response = http::request(
        "GET",
        url,
        access,
        &["Accept: application/json".into()],
        None,
    )?;
    if response.head.status != 200 {
        bail!("{url} returned HTTP {}", response.head.status);
    }
    serde_json::from_slice(&response.body).with_context(|| format!("{url} is not a JSON directory"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .with_context(|| format!("directory lacks `{name}`"))
}

fn bytes(value: &Value, name: &str) -> Result<Vec<u8>> {
    field(value, name)?
        .as_str()
        .and_then(http::decode)
        .with_context(|| format!("`{name}` is not canonical base64url"))
}

fn link(base: &Url, value: &Value, name: &str) -> Result<Url> {
    let text = field(value, name)?
        .as_str()
        .with_context(|| format!("`{name}` is not a string"))?;
    let url = base
        .join(text)
        .with_context(|| format!("`{name}` is not a URL"))?;
    http::check_url(&url)?;
    Ok(url)
}

/// Whether `entry` has type `kind` and, when it names one, our ciphersuite.
/// Entries of other types or ciphersuites are skipped.
fn supported(entry: &Value, type_field: &str, kind: u64) -> bool {
    entry.get(type_field).and_then(Value::as_u64) == Some(kind)
        && entry.get("ciphersuite").and_then(Value::as_str) == Some(CIPHERSUITE)
}

fn accepted(entry: &Value) -> Result<Option<Accepted>> {
    if entry.get("endorsement-type").and_then(Value::as_u64) == Some(NO_ENDORSEMENT) {
        return Ok(Some(Accepted::NoEndorsement));
    }
    if !supported(entry, "endorsement-type", EC_IHAT) {
        return Ok(None);
    }
    let epoch = bytes(entry, "issuance-epoch")?;
    let keys = field(entry, "anchor-set")?
        .as_array()
        .context("`anchor-set` is not a list")?;
    if keys.len() > usize::from(u16::MAX)
        || epoch.len().saturating_mul(keys.len()) > guac::protocol::MAX_MESSAGE_BYTES
    {
        bail!("Anchor configuration too large");
    }
    let anchors = keys
        .iter()
        .map(|key| {
            let key = AnchorKey {
                key: key
                    .as_str()
                    .and_then(http::decode)
                    .context("`anchor-set` entry is not canonical base64url")?,
                epoch: epoch.clone(),
            };
            key.config()?;
            Ok(key)
        })
        .collect::<Result<Vec<_>>>()?;
    AnchorSet::new(
        &anchors
            .iter()
            .map(AnchorKey::config)
            .collect::<Result<Vec<_>>>()?,
    )?;
    Ok(Some(Accepted::EcIhat(anchors)))
}

pub fn fetch_anchor(url: &Url, access: Access) -> Result<AnchorDirectory> {
    http::check_url(url)?;
    let value = get(url, access)?;
    if !supported(&value, "endorsement-type", EC_IHAT) {
        bail!("Anchor configuration uses an unsupported endorsement type or ciphersuite");
    }
    let anchor = AnchorKey {
        key: bytes(&value, "anchor-key")?,
        epoch: bytes(&value, "issuance-epoch")?,
    };
    anchor.config()?;
    let authorization_uri = match value.get("authorization-uri") {
        None | Some(Value::Null) => None,
        Some(_) => Some(link(url, &value, "authorization-uri")?),
    };
    Ok(AnchorDirectory {
        url: url.clone(),
        access,
        grant_uri: link(url, &value, "grant-uri")?,
        authorization_uri,
        anchor,
    })
}

pub fn fetch_moderator(url: &Url, access: Access) -> Result<ModeratorDirectory> {
    http::check_url(url)?;
    let value = get(url, access)?;
    let entry = field(&value, "credential-keys")?
        .as_array()
        .context("`credential-keys` is not a list")?
        .iter()
        .find(|entry| supported(entry, "credential-type", ACT))
        .context("Moderator configuration has no supported credential key")?;
    let number = |name| {
        field(entry, name)?
            .as_u64()
            .with_context(|| format!("`{name}` is not an integer"))
    };
    let endorsements = field(&value, "endorsements")?
        .as_array()
        .context("`endorsements` is not a list")?
        .iter()
        .filter_map(|entry| accepted(entry).transpose())
        .collect::<Result<Vec<_>>>()?;
    if endorsements.is_empty() {
        bail!("Moderator configuration accepts no supported endorsement type");
    }
    let directory = ModeratorDirectory {
        url: url.clone(),
        access,
        issuance_uri: link(url, &value, "issuance-uri")?,
        key: bytes(entry, "credential-key")?,
        balance_width: u8::try_from(number("balance-width")?)
            .context("`balance-width` out of range")?,
        context: bytes(entry, "credential-context")?,
        retention: number("result-retention")?,
        endorsements,
    };
    directory.config()?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_epoch_amplification_before_copying_keys() {
        let anchor = guac::Anchor::generate(vec![1]).unwrap();
        let key = http::encode(&anchor.configuration().public_key());
        let entry = serde_json::json!({
            "endorsement-type": EC_IHAT,
            "ciphersuite": CIPHERSUITE,
            "issuance-epoch": http::encode(&vec![0; u16::MAX as usize]),
            "anchor-set": [key, key, key],
        });
        assert_eq!(
            accepted(&entry).unwrap_err().to_string(),
            "Anchor configuration too large"
        );
    }
}
