#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod anchor;
#[cfg(feature = "browser")]
pub mod browser;
mod client;
mod config;
mod error;
pub mod http;
mod moderator;
pub mod protocol;
pub mod storage;

pub use {act, ec_ihat, url, zeroize};
#[cfg(feature = "browser")]
pub use {js_sys, wasm_bindgen};

pub use anchor::Anchor;
pub use client::{
    Client, Credential, CredentialOutcome, Endorsement, GrantStep, IssuanceInput, PendingGrant,
    PendingIssuance, PendingPresentation, PresentError, RequestError, UpdateError,
};
pub use config::{AnchorConfig, AnchorSet, EndorsementPolicy, ModeratorConfig};
pub use error::Error;
pub use moderator::{Acceptance, Issuance, Moderator, PresentationOutcome, UpdatePolicy};
