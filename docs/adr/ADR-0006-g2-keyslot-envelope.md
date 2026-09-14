# ADR-0006: G2 keyslot envelope and AAD

Status: accepted for G2 implementation; evidence pending.

Preserve G1 storage versions and HKDF domains. Keyslot container version 1 gains
typed bounded slots; empty lists remain accepted only by the explicitly named
injected-key fixture boundary. Production requires exactly one passphrase slot
and zero or one recovery/device slots. Default creation includes recovery;
declining it requires an explicit typed acknowledgement in trusted Rust.

Each slot wraps the same random 32-byte VMK with the existing exactly pinned
RustCrypto chacha20poly1305 0.11.0 XChaCha20-Poly1305. Every wrap has a fresh
24-byte OS-random nonce. JSON byte arrays encode salts/nonces/ciphertext; wrapped
VMK is 32 ciphertext bytes followed by the 16-byte tag. Slot version is 1 and
wrap algorithm is `XChaCha20-Poly1305`. Unknown types/versions/fields fail closed.

AAD is independent of JSON serialization: ASCII `DVM/keyslot/aad/v1` followed
by u32 little-endian length-prefixed fields, in this order: vault UUID UTF-8,
slot type UTF-8, slot version u32 LE, slot ID UTF-8, wrap algorithm UTF-8,
KDF algorithm UTF-8, KDF memory/iterations/parallelism (each u32 LE), salt,
nonce, credential reference UTF-8. Absent KDF numbers are zero; absent strings
and salt are empty. Each slot type has strict required/forbidden fields.

Recovery is 256 OS-random bits, represented as 64 lowercase hex characters only
at a trusted presentation boundary. HKDF-SHA-256 with salt `DVM/v2/recovery`
and label `DVM/v2/recovery-kek` produces its KEK. Device KEK is independently
OS-random. Neither is derived from a passphrase. No raw root secret is serialized.

Header replacement validates first, writes a uniquely named same-directory
envelope with create-new, flushes/syncs it, then atomically renames over
`vault.header`; the old header remains authoritative until activation. Failure
injection uses test-only seams. Process crash atomicity is tested; total hardware
power-loss durability and external rollback prevention are not claimed.

Sources inspected: [AEAD](https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/),
[Rust rename](https://doc.rust-lang.org/std/fs/fn.rename.html),
[zeroize](https://docs.rs/zeroize/1.9.0/zeroize/).
