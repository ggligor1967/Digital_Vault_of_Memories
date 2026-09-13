//! Domain contracts for Digital Vault of Memories.
//!
//! This crate is the innermost layer of the dependency rule stated in
//! Blueprint v2 §6.2:
//!
//! ```text
//! presentation -> application -> domain/ports <- infrastructure
//! ```
//!
//! It therefore depends on no infrastructure, no Tauri types, no database and
//! no cryptography. It defines *what the boundary says*, not *how anything is
//! done*.
//!
//! # Scope at gate G0
//!
//! `DVM-V2 / G0 — REPOSITORY FOUNDATION` establishes exactly three contract
//! surfaces here:
//!
//! * [`AppError`] — the canonical typed error envelope of Blueprint v2 §23.1,
//!   including the full required error-class set of Blueprint v2 §23.2;
//! * [`FoundationStatus`] — the payload of the single G0 IPC command,
//!   `foundation_status`;
//! * [`codegen`] — the repository-local generator that derives the TypeScript
//!   mirror of both types from their *actual* Serde wire representation, so
//!   that the Rust and TypeScript definitions cannot silently diverge
//!   (Blueprint v2 §40.2).
//!
//! No vault, storage, crypto, search, AI, media or backup behaviour is
//! implemented here; those are authorised from G1 onwards.

pub mod codegen;
pub mod error;
pub mod foundation;

pub use error::{AppError, ErrorCode};
pub use foundation::{FoundationHealth, FoundationStatus};

/// Version of the renderer-facing IPC contract defined by this crate.
///
/// This is deliberately independent of the application version: the desktop
/// application may be rebuilt many times without the boundary changing shape,
/// and the renderer verifies compatibility against *this* value rather than
/// against the product version.
///
/// Blueprint v2 §40.2 requires explicit versioned IPC shapes; the renderer
/// refuses to report a healthy foundation when the value it was compiled
/// against differs from the value the trusted backend reports.
pub const API_CONTRACT_VERSION: &str = "1.0.0";
