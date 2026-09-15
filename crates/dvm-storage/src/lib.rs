//! Native encrypted storage, keyslot lifecycle and OS credentials. No renderer commands.
pub mod credentials;
pub mod database;
pub mod header;
pub mod security;

mod jobs;
mod vault;
pub use vault::Vault;
#[cfg(test)]
mod tests;
