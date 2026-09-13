//! Lexical (`FTS5`), vector and hybrid retrieval for Digital Vault of Memories.
//!
//! # Gate status
//!
//! This crate is a **reserved workspace member** established by
//! `DVM-V2 / G0 — REPOSITORY FOUNDATION` so that the canonical repository
//! topology of Blueprint v2 §7 survives a clean `git clone` and so that the
//! dependency direction of Blueprint v2 §6.2 is fixed before any feature work
//! begins.
//!
//! It intentionally contains **no implementation**. Its behaviour is specified
//! by Blueprint v2 and is authorised only from **G4** onwards. Adding
//! implementation here before G4 is authorised would violate the gate
//! sequencing rule of Blueprint v2 §36.

/// Identifier of the mandatory Blueprint v2 gate that first authorises
/// implementation inside this crate.
///
/// Exposed so that architectural tests can assert that reserved crates are
/// still reserved, rather than relying on a documentation comment.
pub const AUTHORISED_FROM_GATE: &str = "G4";
