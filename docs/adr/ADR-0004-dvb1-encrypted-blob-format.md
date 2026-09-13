# ADR-0004: DVB1 encrypted blob format

Status: G1 implementation decision; verification is recorded in the G1 evidence file.

Primitive: RustCrypto chacha20poly1305 0.11.0 XChaCha20Poly1305. All integers
unsigned little endian. Strict reference chunk size 4194304 bytes. No compression.

## Header (52 bytes plus 16-byte tag)

| Offset | Width | Meaning                                                |
| ------ | ----- | ------------------------------------------------------ |
| 0      | 4     | ASCII DVB1                                             |
| 4      | 2     | format version 1                                       |
| 6      | 2     | algorithm ID 1 = XChaCha20-Poly1305                    |
| 8      | 16    | random blob ID bytes                                   |
| 24     | 4     | chunk size 4194304                                     |
| 28     | 8     | original plaintext byte length                         |
| 36     | 16    | OS-random nonce prefix                                 |
| 52     | 16    | AEAD tag for empty plaintext; AAD = header bytes 0..52 |

Nonce = 16-byte prefix concatenated with u64 LE counter. Counter 0 authenticates
the header. Data chunk i uses counter i+1. Each blob has a separately derived
key. A writer never reuses a blob ID; retry creates a new random ID/prefix.

## Chunk frame

u64 LE index, u32 LE plaintext length, ciphertext of that length, 16-byte tag.
AAD = complete 52-byte header followed by the 12-byte frame prefix. Frame index
must equal the next expected index. Length must equal min(chunk size, remaining
original size). This binds algorithm, format, ID, total size, chunk index and
chunk length. Empty files have the authenticated header only. Exact multiples
have no extra empty data frame.

## Reader rules

Reject unknown versions/algorithms/chunk sizes, wrong externally expected blob
ID, wrong key, any tag failure, short frame, missing chunk, surplus frame or
trailing byte. Require exact declared length and EOF. Reordering, duplication
and cross-blob substitution fail. Never allocate from an unchecked file length.

A transactional plaintext sink receives provisional authenticated chunks. Its
commit method is called only after all tags, framing, EOF and any expected hash
have passed. On any failure abort clears/discards provisional state. The reader
returns only a verified digest/byte count on success; it cannot return a partial
plaintext buffer as success. No general Write-based plaintext export API exists
at G1. Test sinks explicitly stage bounded hashes/equality state or small fixtures.

Source is read once for hashing and encryption. Staging verification reads the
encrypted candidate independently. Crypto working buffers are chunk bounded and
zeroized where practical. No plaintext filesystem staging.

Sources: https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/,
https://doc.rust-lang.org/std/io/trait.Read.html.
