//! Trusted DVBK1 backup, verification, and restore. No renderer authority.
#[allow(unsafe_code)]
mod activation;
mod dvbk1;
pub use dvbk1::*;
/// Gate that authorized this crate's behavior.
pub const AUTHORISED_FROM_GATE: &str = "G3";
