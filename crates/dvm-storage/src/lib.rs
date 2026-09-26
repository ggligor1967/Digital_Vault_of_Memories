//! Native encrypted storage, keyslot lifecycle and OS credentials. No renderer commands.
pub mod credentials;
pub mod database;
pub mod header;
pub mod security;

mod jobs;
pub mod migrations;
mod vault;
pub use vault::{Vault, blob_storage_relpath, validate_blob_storage_relpath};
#[cfg(test)]
mod tests;
