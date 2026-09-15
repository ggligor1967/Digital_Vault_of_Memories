# ADR-0007: Argon2id policy, native pin and accepted audit lineage

Status: selected under the project's explicit audit-provenance decision;
application acceptance still requires the complete G2 verification sequence.

## Selection and audit qualification

Select libsodium **1.0.22-RELEASE** through maintained Rust FFI binding
**libsodium-sys-stable =1.24.0**, default features disabled. Rust/Cargo 1.94.1
successfully compiles the binding and private adapter on Windows x64 MSVC.
RustCrypto argon2 0.6.0 is disqualified and removed, including from Cargo.lock.
Its public known-answer outputs are retained only as interoperability vectors,
not as audit evidence. No JavaScript cryptography dependency is introduced.

The project explicitly accepts the published
[libsodium v1.0.12/v1.0.13 security assessment](https://www.privateinternetaccess.com/blog/libsodium-v1-0-12-and-v1-0-13-security-assessment/)
as audit provenance for this Argon2id implementation lineage. The assessment's
scope includes key derivation/password hashing; section 3.5.8 reviews the 1.0.13
delta adding Argon2id and reports no new vulnerabilities from that delta.
This decision establishes the project's Blueprint section 9.1 audit requirement
for the selected lineage; application tests alone do not establish an audit.

- AUDITED_LINEAGE = YES
- EXACT_SELECTED_RELEASE_AUDITED = NO
- ACCEPTED_PROJECT_AUDIT_PROVENANCE = YES

The audited versions were 1.0.12/1.0.13, **not 1.0.22**. The Rust FFI binding and
DVM adapter are not represented as independently audited. Later native changes,
compiler/toolchain differences, the release binary supply chain and the small
FFI boundary remain audit-lineage limitations. Pinning, signature verification,
source inspection and interoperability tests reduce that gap; they do not turn
it into an exact-release audit or a compromised-host guarantee.

Source lineage evidence: both the
[1.0.13 implementation](https://github.com/jedisct1/libsodium/blob/1.0.13/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c)
and [1.0.22 implementation](https://github.com/jedisct1/libsodium/blob/1.0.22-RELEASE/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c)
call the inherited Argon2id implementation with iterations equal to opslimit,
memory equal to memlimit / 1024, and one lane. The explicit algorithm selector is
ARGON2ID13 (Argon2 version 0x13). This is continuity of implementation and cost
semantics, not a claim of identical source. Current release provenance:
[1.0.22 release](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE);
binding API/source: [libsodium-sys-stable 1.24.0](https://docs.rs/libsodium-sys-stable/1.24.0/libsodium_sys/).

## Exact credential and cost policy

Passphrases are exact UTF-8 bytes: no trimming, case folding, normalization or
NUL termination. Reject empty and over-1024-byte input before native work. Unicode
visually equivalent strings may be distinct credentials. Output is 32 bytes;
salt is 16 fresh OS-random bytes. Existing keyslot version, salt, parameter fields,
AAD, AEAD wrapping, VMK generation and G1 storage domains are unchanged.

Minimum profile: **19456 KiB / 2 iterations / parallelism 1**. Production reads
and writes reject weaker profiles. Bound hostile persisted costs at 262144 KiB
and 10 iterations before allocation. The selected API supports exactly one lane:
reject all persisted/requested parallelism values other than 1 rather than
silently ignoring the field. The field stays serialized and authenticated.
No previously published G2 vault uses a multi-lane profile; G1 had no slots.

Calibration targets 250 ms, starting at baseline and doubling memory to the cap.
Reaching the cap may finish below target; the baseline is never reduced. Trusted
callers/tests may select explicit validated profiles. Upgrades and passphrase
changes wrap the same random VMK, without content re-encryption. Public Unicode,
whitespace and embedded-NUL vectors at baseline and t=3 prove compatibility with
the replaced implementation; all ordinary tests retain production-strength costs.
Sources: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html),
[libsodium password hashing API](https://doc.libsodium.org/password_hashing/default_phf).

## Windows reproducibility and FFI boundary

Use the official, versioned `libsodium-1.0.22-msvc.zip` release archive, not the
moving `stable` archive used by the binding's default Windows download path.
The archive's Minisign signature and trusted comment were verified with Node's
Ed25519/BLAKE2b primitives against upstream public key
`RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`.
The signature framing was checked against upstream
[minisign-verify](https://github.com/jedisct1/rust-minisign-verify/blob/master/src/lib.rs).

- Archive SHA-256: `3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279`
- Signature-file SHA-256: `3210cf4d985f7b192bb8d5eb2ec7f481e0f47420f144cf1069921f714bfad1d1`
- Exact entry: `libsodium/x64/Release/v143/static/libsodium.lib`
- Static-library SHA-256: `62815491f5ef88e83a14194358d8e9a6cd01b7f43b646fcb59a647bd12c88621`

`scripts/prepare-sodium.mjs` downloads only that fixed HTTPS URL, verifies the
pinned archive hash, extracts exactly one entry, and verifies the library hash on
every gate invocation. Mismatch fails closed without a moving-version fallback.
Both G0 and G2 bootstrap this same prerequisite, so standalone G0/G1 workflows
remain operational. `.cargo/config.toml` forces the repository-owned library
directory; the binding takes its external static-library path and cannot silently
fetch another build. `SODIUM_SHARED` and pkg-config overrides fail preflight.
Missing prerequisites fail direct Cargo linking; contributors first run the
bootstrap. Native release identity is also checked at each KDF invocation.
Windows x64 MSVC is the mandatory G2 acceptance platform. To preserve the existing
G0 Linux job, the bootstrap also builds the same 1.0.22 release from its pinned
official source archive using the runner's C compiler, configure and make, with
static PIC linkage. This path adds no system package installation and changes
no G0/G1 workflow. Linux execution is unverified until the existing G0 job runs;
Windows credential acceptance is never inferred from that portability job.

- Source archive: `libsodium-1.0.22.tar.gz`
- Source SHA-256: `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349`
- Source signature SHA-256: `c0186d6cf8c9c2ec5c6dbb6d4ff4f701e5592376490e8ad97a4ceeecabbff0f3`

The source archive Minisign signature and trusted comment were independently
verified against the same upstream key. The Linux bootstrap validates the source
hash on every invocation. The resulting binary depends on the runner's C
toolchain; no bit-for-bit binary reproducibility claim is made for that build.

The binding has only libc as a normal dependency. Its locked archive/download
build dependencies (including zip, tar and ureq) are native compilation tooling,
not application backup or networking code. They remain excluded from the normal
DVM dependency graph. The workspace's future-gate direct dependency guard still
rejects archive/provider stacks. No provider SDK or renderer capability is added.

The private `dvm-crypto/src/sodium.rs` module is the only application unsafe-code
exception. Other workspace crates retain `forbid`; dvm-crypto uses `deny` with a
single module allowance. Each FFI call documents buffer validity, lifetime and
bounds. The safe entry point validates input, initializes sodium fallibly, checks
the linked release, and maps native failure to a secret-free typed error. Output
is zeroizing on success and failure. No default wrapper constructor/panic path or
native secret handle crosses IPC. Static security checks guard this boundary.

Considered maintained safe wrappers libsodium-rs 0.2.4 and sodoken 0.1.0 add
panic-based initialization paths; direct FFI keeps initialization failure typed.
Alkali 0.3.0 and sodiumoxide 0.2.7 did not establish suitable current maintenance
for this selection. The adapter implements no cryptographic primitive.
