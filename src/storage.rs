//! Replay records for one Moderator key and credential context, and Anchor
//! grant sessions.
//!
//! Records are independent, so a store can shard them by identifier across
//! any number of atomic partitions: only insert-if-absent and take must be
//! atomic.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use zeroize::Zeroizing;

use crate::{
    Error,
    protocol::{
        ACT, CredentialPresentation, CredentialUpdate, Reader, RecoveryHandle, digest, put_vector,
    },
};

/// The committed result of an accepted presentation (MOLE protocols, EC-ACT Spending and Refunds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationRecord {
    pub(crate) digest: [u8; 32],
    pub(crate) expires_at: u64,
    pub(crate) update: CredentialUpdate,
}

impl PresentationRecord {
    /// Recovery rules: only a byte-identical presentation, while retained.
    /// Recovery never authorizes another protected operation.
    pub fn recover(
        &self,
        presentation: &CredentialPresentation,
        now: u64,
    ) -> Result<CredentialUpdate, Error> {
        self.recover_digest(digest(&presentation.body), now)
    }

    /// As `recover`, from a recovery handle. The caller looked the record up
    /// by `handle.nullifier()`; `Moderator::recover_from` also checks the key.
    pub(crate) fn recover_handle(
        &self,
        handle: &RecoveryHandle,
        now: u64,
    ) -> Result<CredentialUpdate, Error> {
        self.recover_digest(handle.digest, now)
    }

    fn recover_digest(&self, digest: [u8; 32], now: u64) -> Result<CredentialUpdate, Error> {
        if self.expires_at > now && self.digest == digest {
            Ok(self.update.clone())
        } else {
            Err(Error::Replay)
        }
    }

    /// The accepted update, released only after the record commits.
    pub fn update(&self) -> &CredentialUpdate {
        &self.update
    }

    /// Recovery deadline. After it, stores delete the result, keeping
    /// `Spent::Expired` while the key and context are accepted.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Local storage encoding, not a protocol message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![2];
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        put_vector(&mut out, &self.update.to_bytes());
        out
    }

    /// Also reads version 1 records, written before HTTP carried raw payloads.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes)?;
        let version = reader.take(1)?[0];
        let digest = reader.array()?;
        let expires_at = u64::from_be_bytes(reader.array()?);
        let update = match version {
            2 => CredentialUpdate::from_bytes(reader.vector()?)?,
            1 => legacy_update(reader.vector()?)?,
            _ => return Err(Error::Malformed),
        };
        reader.finish()?;
        Ok(Self {
            digest,
            expires_at,
            update,
        })
    }
}

/// Version 1 OptionalCredentialUpdate: `0`, or `1 || type || vector(update)`.
fn legacy_update(bytes: &[u8]) -> Result<CredentialUpdate, Error> {
    let mut reader = Reader::new(bytes)?;
    let update = match reader.take(1)? {
        [0] => Vec::new(),
        [1] => {
            reader.protocol(&[ACT])?;
            reader.vector()?.to_vec()
        }
        _ => return Err(Error::Malformed),
    };
    reader.finish()?;
    CredentialUpdate::from_bytes(&update)
}

/// What a store holds for a spent nullifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spent {
    /// The result, recoverable until `expires_at`.
    Retained(PresentationRecord),
    /// The result was deleted; the nullifier stays spent.
    Expired,
}

/// Durable, atomic insert-if-absent over replay identifiers.
///
/// All servers accepting one key and credential context must share these
/// records (MOLE protocols, Security Considerations). Losing them re-admits spent credentials.
/// Retiring the key or context ends acceptance; inserts racing retirement
/// must fail.
pub trait Store {
    /// Returns `false` if `id` was already recorded. Keep the record while the
    /// endorsement epoch is accepted, independently of credential key or
    /// context rotation.
    fn insert_redemption(&self, id: [u8; 32]) -> Result<bool, Error>;
    /// Inserts `record`, or returns what is already recorded for `nullifier`.
    fn insert_presentation(
        &self,
        nullifier: [u8; 32],
        record: &PresentationRecord,
    ) -> Result<Option<Spent>, Error>;
    fn presentation(&self, nullifier: &[u8; 32]) -> Result<Option<Spent>, Error>;
}

/// What a `GrantStore` held for a grant session when it was taken.
pub enum GrantClaim {
    /// The stored continuation, now consumed. Opaque, secret, key/epoch-bound;
    /// the Anchor zeroizes it after use.
    Pending(Vec<u8>),
    /// Taken before.
    Consumed,
}

/// Durable, atomic grant sessions for one Anchor key and epoch.
///
/// Every server answering the Anchor's grants must share these records. A
/// session's state must be taken at most once: a second response over the
/// same nonce state leaks the Anchor key.
pub trait GrantStore {
    /// Stores `state` under `session_id`. Returns `false`, storing nothing, if
    /// the session exists. Records may be deleted after `expires_at`.
    fn insert_grant(
        &self,
        session_id: [u8; 32],
        state: &[u8],
        expires_at: u64,
    ) -> Result<bool, Error>;
    /// Atomically replaces a pending record with a consumed tombstone, kept
    /// until `expires_at`, and returns what was there. `None`: unknown or
    /// deleted.
    fn take_grant(&self, session_id: &[u8; 32]) -> Result<Option<GrantClaim>, Error>;
}

/// Volatile store for native examples and tests.
#[derive(Default)]
pub struct MemoryStore {
    redemptions: Mutex<HashSet<[u8; 32]>>,
    presentations: Mutex<HashMap<[u8; 32], PresentationRecord>>,
    grants: Mutex<HashMap<[u8; 32], GrantState>>,
}

/// `None` once consumed.
type GrantState = Option<Zeroizing<Vec<u8>>>;

fn poisoned<T>(_: T) -> Error {
    Error::Storage("poisoned store".into())
}

// shortcut: never evicts; expired results are unrecoverable through
// `PresentationRecord::recover`. Durable adapters delete them.
impl Store for MemoryStore {
    fn insert_redemption(&self, id: [u8; 32]) -> Result<bool, Error> {
        Ok(self.redemptions.lock().map_err(poisoned)?.insert(id))
    }

    fn insert_presentation(
        &self,
        nullifier: [u8; 32],
        record: &PresentationRecord,
    ) -> Result<Option<Spent>, Error> {
        let mut presentations = self.presentations.lock().map_err(poisoned)?;
        if let Some(existing) = presentations.get(&nullifier) {
            return Ok(Some(Spent::Retained(existing.clone())));
        }
        presentations.insert(nullifier, record.clone());
        Ok(None)
    }

    fn presentation(&self, nullifier: &[u8; 32]) -> Result<Option<Spent>, Error> {
        Ok(self
            .presentations
            .lock()
            .map_err(poisoned)?
            .get(nullifier)
            .cloned()
            .map(Spent::Retained))
    }
}

// shortcut: never evicts expired sessions or tombstones; durable adapters delete them after expiry.
impl GrantStore for MemoryStore {
    fn insert_grant(
        &self,
        session_id: [u8; 32],
        state: &[u8],
        _expires_at: u64,
    ) -> Result<bool, Error> {
        let mut grants = self.grants.lock().map_err(poisoned)?;
        if grants.contains_key(&session_id) {
            return Ok(false);
        }
        grants.insert(session_id, Some(Zeroizing::new(state.to_vec())));
        Ok(true)
    }

    fn take_grant(&self, session_id: &[u8; 32]) -> Result<Option<GrantClaim>, Error> {
        Ok(self
            .grants
            .lock()
            .map_err(poisoned)?
            .get_mut(session_id)
            .map(|state| {
                state.take().map_or(GrantClaim::Consumed, |mut state| {
                    GrantClaim::Pending(std::mem::take(&mut *state))
                })
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_version_1_records() {
        let mut v1 = vec![1];
        v1.extend_from_slice(&[7; 32]);
        v1.extend_from_slice(&9u64.to_be_bytes());
        let mut refund = vec![1, 0, 1];
        put_vector(&mut refund, &[5, 6]);
        let mut consumed = v1.clone();
        put_vector(&mut v1, &refund);
        put_vector(&mut consumed, &[0]);
        let record = PresentationRecord::from_bytes(&v1).unwrap();
        assert_eq!(record.update().to_bytes(), [5, 6]);
        assert_eq!(record.expires_at(), 9);
        assert_eq!(
            PresentationRecord::from_bytes(&record.to_bytes()).unwrap(),
            record
        );
        let consumed = PresentationRecord::from_bytes(&consumed).unwrap();
        assert!(consumed.update().to_bytes().is_empty());
        assert!(PresentationRecord::from_bytes(&[3; 49]).is_err());
    }
}
