# ADR-0003: G1 storage subkeys and injected key boundary

Status: G1 storage subset only. G2 keyslots/KDF lifecycle NOT STARTED.

VMK is 32 bytes from getrandom 0.4.3 OS CSPRNG. Raw secret types have no Debug,
Clone, Copy or Serialize implementation. Owned buffers use zeroize 1.9.0.
HKDF-SHA-256 (hkdf 0.13.0, sha2 0.11.0) uses salt ASCII DVM/v1 and these exact
ASCII info labels: DVM/v1/db, DVM/v1/blob-root. Per-blob derivation uses blob ID's
16 raw bytes as salt, blob root as IKM and DVM/v1/blob as info. Output is 32 bytes.
All labels and encodings are format contracts.

Only trusted internal test/integration callers supply the VMK. No Tauri command
creates/opens these test vaults. Harnesses may inject the same bytes across
process restarts. Nothing persists a VMK, DB key or blob key. An empty reserved
keyslot array is NOT a usable production vault. G2 must implement passphrase,
recovery and device wrapping before any production creation/unlock surface.

Memory hygiene reduces exposure but does not prove removal of all compiler,
register, OS swap or library-internal copies. No unlocked-host security claim.

Sources: https://docs.rs/hkdf/0.13.0/hkdf/,
https://docs.rs/sha2/0.11.0/sha2/,
https://docs.rs/getrandom/0.4.3/getrandom/,
https://docs.rs/zeroize/1.9.0/zeroize/.
