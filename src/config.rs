use std::sync::{Arc, Mutex};

use url::Url;

use crate::{
    Error,
    protocol::{EC_IHAT, NO_ENDORSEMENT, digest, put_vector},
};

/// Experimental domain-scoped redemption audience; its encoding may change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedemptionScope(String);

impl RedemptionScope {
    /// Accepts an ASCII DNS name (including punycode), without a scheme or port.
    pub fn for_moderator_domain(domain: &str) -> Result<Self, Error> {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        if domain.is_empty()
            || domain.len() > 253
            || !domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || !matches!(url::Host::parse(domain), Ok(url::Host::Domain(_)))
        {
            return Err(Error::Configuration("Moderator scope must be a DNS name"));
        }
        Ok(Self(domain.to_ascii_lowercase()))
    }

    pub fn moderator_domain(&self) -> &str {
        &self.0
    }

    pub(crate) fn context(&self) -> Vec<u8> {
        let mut context = b"MOLE-EC-IHAT-ctx_red-v2".to_vec();
        put_vector(&mut context, self.0.as_bytes());
        context
    }
}

/// Authenticated Anchor key and the canonical issuance epoch bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorConfig {
    pub(crate) key: ec_ihat::PublicKey,
    pub(crate) epoch: Vec<u8>,
}

impl AnchorConfig {
    /// Epoch encoding and its validity are deployment policy, not discovery.
    pub fn new(public_key: &[u8; 33], epoch: Vec<u8>) -> Result<Self, Error> {
        if epoch.is_empty() || epoch.len() > usize::from(u16::MAX) {
            return Err(Error::Configuration("issuance epoch length"));
        }
        Ok(Self {
            key: ec_ihat::PublicKey::from_bytes(public_key)?,
            epoch,
        })
    }

    pub fn public_key(&self) -> [u8; 33] {
        self.key.to_bytes()
    }
    pub fn epoch(&self) -> &[u8] {
        &self.epoch
    }
}

/// An ordered, nonempty set of distinct keys sharing an issuance epoch.
#[derive(Clone, Debug)]
pub struct AnchorSet {
    pub(crate) keys: Vec<ec_ihat::PublicKey>,
    pub(crate) epoch: Vec<u8>,
}

impl AnchorSet {
    pub fn new(anchors: &[AnchorConfig]) -> Result<Self, Error> {
        let first = anchors
            .first()
            .ok_or(Error::Configuration("empty Anchor set"))?;
        if anchors.len() > usize::from(u16::MAX) {
            return Err(Error::Configuration("Anchor set too large"));
        }
        let mut keys = Vec::with_capacity(anchors.len());
        let mut seen = std::collections::HashSet::new();
        for anchor in anchors {
            if anchor.epoch != first.epoch || !seen.insert(anchor.public_key()) {
                return Err(Error::Configuration(
                    "mixed epochs or duplicate Anchor keys",
                ));
            }
            keys.push(anchor.key.clone());
        }
        Ok(Self {
            keys,
            epoch: first.epoch.clone(),
        })
    }
}

/// The endorsement requirement for this Moderator configuration.
#[derive(Clone, Debug)]
pub enum EndorsementPolicy {
    Required(AnchorSet),
    NotRequired,
}

impl EndorsementPolicy {
    pub(crate) fn protocol_type(&self) -> u16 {
        match self {
            Self::Required(_) => EC_IHAT,
            Self::NotRequired => NO_ENDORSEMENT,
        }
    }
}

/// Authenticated public configuration for one Moderator key and context.
#[derive(Clone, Debug)]
pub struct ModeratorConfig {
    pub(crate) endpoint: Url,
    pub(crate) key: act::PublicKey,
    pub(crate) key_id: [u8; 32],
    pub(crate) context: Vec<u8>,
    pub(crate) params: Arc<act::Params>,
    pub(crate) endorsements: EndorsementPolicy,
    pub(crate) retention: u64,
}

impl ModeratorConfig {
    pub fn new(
        endpoint: &str,
        public_key: &[u8; 33],
        balance_bits: u8,
        context: Vec<u8>,
        endorsements: EndorsementPolicy,
        result_retention_seconds: u64,
    ) -> Result<Self, Error> {
        if endpoint.len() > usize::from(u16::MAX) {
            return Err(Error::Configuration("Moderator endpoint length"));
        }
        let endpoint =
            Url::parse(endpoint).map_err(|_| Error::Configuration("Moderator endpoint"))?;
        // Loopback HTTP is potentially trustworthy (W3C Secure Contexts §3.2)
        // and lets clients reach local development Moderators.
        let loopback = match endpoint.host() {
            Some(url::Host::Domain(host)) => host == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
        {
            return Err(Error::Configuration(
                "Moderator endpoint must be an HTTPS or loopback HTTP URL",
            ));
        }
        if context.len() > usize::from(u16::MAX) - 1 || result_retention_seconds == 0 {
            return Err(Error::Configuration("context length or result retention"));
        }
        let config = Self {
            endpoint,
            key: act::PublicKey::from_bytes(public_key)?,
            key_id: digest(public_key),
            context,
            params: parameters(balance_bits)?,
            endorsements,
            retention: result_retention_seconds,
        };
        if matches!(config.endorsements, EndorsementPolicy::Required(_)) {
            config.redemption_scope()?;
        }
        Ok(config)
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }
    pub fn redemption_scope(&self) -> Result<RedemptionScope, Error> {
        RedemptionScope::for_moderator_domain(self.endpoint.domain().ok_or(
            Error::Configuration("Moderator scope requires a domain endpoint"),
        )?)
    }
    pub fn public_key(&self) -> [u8; 33] {
        self.key.to_bytes()
    }
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
    pub fn credential_context(&self) -> &[u8] {
        &self.context
    }
    pub fn balance_bits(&self) -> u8 {
        self.params.balance_width()
    }

    pub(crate) fn credential_context_bytes(&self) -> Vec<u8> {
        let mut context = self.context.clone();
        context.push(self.balance_bits());
        context
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut out = self.key_id.to_vec();
        put_vector(&mut out, self.endpoint.as_str().as_bytes());
        put_vector(&mut out, &self.credential_context_bytes());
        digest(&out)
    }
}

// Public deterministic parameters are expensive to build. Retain only the
// most recently used width; live configurations own their own Arc references.
fn parameters(width: u8) -> Result<Arc<act::Params>, Error> {
    static CACHE: Mutex<Option<Arc<act::Params>>> = Mutex::new(None);
    {
        let cache = CACHE
            .lock()
            .map_err(|_| Error::Configuration("parameter cache poisoned"))?;
        if let Some(params) = cache
            .as_ref()
            .filter(|params| params.balance_width() == width)
        {
            return Ok(Arc::clone(params));
        }
    }
    // Derive outside the lock. Concurrent misses may duplicate work, but never
    // block other widths for the duration of parameter generation.
    let params = Arc::new(act::Params::new(width)?);
    *CACHE
        .lock()
        .map_err(|_| Error::Configuration("parameter cache poisoned"))? = Some(Arc::clone(&params));
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderator_scope_domains() {
        let scope = RedemptionScope::for_moderator_domain("Moderator.Example.").unwrap();
        assert_eq!(scope.moderator_domain(), "moderator.example");
        for domain in [
            "",
            "https://example.com",
            "example.com:443",
            "a/b",
            "a..b",
            "-a.example",
            "a_.example",
            "127.0.0.1",
            "[::1]",
            "é.example",
            "a.example..",
        ] {
            assert!(
                RedemptionScope::for_moderator_domain(domain).is_err(),
                "{domain}"
            );
        }
    }

    #[test]
    fn parameter_reuse_preserves_width_and_live_configurations() {
        let narrow = parameters(4).unwrap();
        assert_eq!(narrow.max_amount(), 15);
        let wide = parameters(64).unwrap();
        assert_eq!(wide.max_amount(), u64::MAX);
        assert_eq!(narrow.max_amount(), 15);
        assert!(parameters(0).is_err());
        assert!(parameters(65).is_err());
        assert_eq!(parameters(4).unwrap().max_amount(), 15);
    }
}
