//! Redeem & Issue: an endorsement (when required) becomes a named credential.
//!
//! Follows the HTTP draft's 401 challenge flow: an empty POST yields the
//! `redeem-E` challenge, answered with `redeem-E` and `credential-request-0001`.

use anyhow::{Context, Result, bail};
use guac::{
    Client, Endorsement as Token, IssuanceInput, PendingIssuance,
    http::{Authorization, Challenge, CredentialField},
};

use crate::{
    Output, held, hex_id, http,
    remote::{Accepted, ModeratorDirectory},
    store::{self, Credential, Endorsement, Pending, PendingRow, Put, Store, Take},
};

pub fn issue(
    store: &mut Store,
    moderator: &str,
    directory: ModeratorDirectory,
    endorsement: Option<&Endorsement>,
    name: &str,
    out: &Output,
) -> Result<Credential> {
    let (accepted, input) = match endorsement {
        None => {
            if !directory.endorsements.contains(&Accepted::NoEndorsement) {
                bail!(
                    "Moderator `{moderator}` requires an Anchor endorsement\nhint: run `guac endorsement request --anchor <name>`, then pass --endorsement"
                );
            }
            (Accepted::NoEndorsement, IssuanceInput::WithoutEndorsement)
        }
        Some(e) => {
            let accepted = directory
                .endorsements
                .iter()
                .find(|entry| matches!(entry, Accepted::EcIhat(set) if set.contains(&e.directory.anchor)))
                .with_context(|| {
                    format!(
                        "endorsement `{}` is from an Anchor key or epoch Moderator `{moderator}` does not accept",
                        e.id
                    )
                })?
                .clone();
            let token = Token::from_storage_bytes(&e.secret, &e.directory.anchor.config()?)?;
            (accepted, IssuanceInput::Endorsement(token))
        }
    };
    let config = directory.config_for(&accepted)?;
    let response = http::request("POST", &directory.issuance_uri, directory.access, &[], None)?;
    let challenges = response.head.challenges();
    let challenge = Challenge::redemption(&challenges, &config).with_context(|| {
        format!(
            "Moderator sent no usable redemption challenge (HTTP {})",
            response.head.status
        )
    })?;
    let (request, pending) = Client
        .request_credential(input, &config, challenge)
        .map_err(|e| anyhow::anyhow!("cannot redeem: {}", e.error))?;
    let row = PendingRow {
        id: hex_id("op")?,
        record: Pending::Issuance {
            credential: name.to_owned(),
            moderator: moderator.to_owned(),
            directory,
            authorization: Authorization::Issue(request).to_string(),
        },
        secret: pending.to_storage_bytes(),
        created_at: store::now(),
    };
    // The endorsement is consumed here, atomically with saving the request.
    store
        .transition(endorsement.map(Take::Endorsement), Some(Put::Pending(&row)))
        .context("cannot save the pending issuance; nothing was sent")?;
    out.progress("Redeeming with the Moderator…");
    finish(store, &row.id)
}

/// Sends the saved issuance request; stores the credential on success.
pub fn finish(store: &mut Store, id: &str) -> Result<Credential> {
    exchange(store, id).map_err(|e| held(id, e))
}

fn exchange(store: &mut Store, id: &str) -> Result<Credential> {
    let row = store.pending(id)?;
    let Pending::Issuance {
        credential,
        moderator,
        directory,
        authorization,
    } = &row.record
    else {
        bail!("`{id}` is not an issuance");
    };
    let response = http::request(
        "POST",
        &directory.issuance_uri,
        directory.access,
        &[format!("Authorization: {authorization}")],
        None,
    )?;
    let field = response.head.mole_credential()?;
    let Some(CredentialField::Response(issued)) = field.filter(|_| response.head.status == 200)
    else {
        bail!(
            "Moderator did not issue (HTTP {}); a redemption it already consumed cannot be retried",
            response.head.status
        );
    };
    let token = PendingIssuance::from_storage_bytes(&row.secret, &directory.config()?)?
        .finish(&issued)
        .context("invalid issuance response")?;
    let credential = Credential {
        name: credential.clone(),
        moderator: moderator.clone(),
        directory: directory.clone(),
        secret: token.to_storage_bytes(),
        balance: token.balance(),
        created_at: store::now(),
    };
    store.transition(Some(Take::Pending(id)), Some(Put::Credential(&credential)))?;
    Ok(credential)
}
