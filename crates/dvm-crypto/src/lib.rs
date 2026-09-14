//! G1 secret types and authenticated streaming storage primitives.

pub mod dvb1;
pub mod keys;
pub mod keyslots;

#[allow(unsafe_code)]
mod sodium;

pub use dvb1::{CHUNK_SIZE, DigestReceipt, PlaintextSink, decrypt, encrypt};
pub use keys::{BlobKey, BlobRootKey, DbKey, VaultMasterKey, random_id};
