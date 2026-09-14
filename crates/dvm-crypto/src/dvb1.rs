//! DVB1 framing is specified byte-for-byte in ADR-0004.
use std::io::{Read, Write};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use dvm_domain::{AppError, ErrorCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{BlobKey, random_id};

/// Version 1 accepts exactly this plaintext frame capacity.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Authenticated bytes before the header's 16-byte tag.
pub const HEADER_SIZE: usize = 52;

/// A successful whole-stream authentication/hash receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestReceipt {
    /// SHA-256 over plaintext, lowercase hexadecimal.
    pub sha256_hex: String,
    /// Exact number of authenticated original bytes.
    pub size_bytes: u64,
}

/// A transactional consumer of provisional chunks, never a general plaintext writer.
/// Implementations must make provisional data inaccessible as valid content until
/// commit and discard it on abort. Methods must not panic.
pub trait PlaintextSink {
    /// Stages one authenticated chunk, which is not yet a valid whole original.
    /// # Errors
    /// Returns an error when staging cannot continue.
    fn stage(&mut self, chunk: &[u8]) -> Result<(), AppError>;
    /// Publishes only after the entire original has authenticated.
    /// # Errors
    /// Returns an error if publication fails; caller then invokes abort.
    fn commit(&mut self, receipt: &DigestReceipt) -> Result<(), AppError>;
    /// Discards all provisional results, including after a failed commit.
    fn abort(&mut self);
}

fn corrupt() -> AppError {
    AppError::new(ErrorCode::BlobAuthFailed)
}
/// Classifies a failure to read the stored DVB1 stream.
///
/// Truncation is a content failure: bytes the format requires are absent, so
/// the stream cannot authenticate and `BLOB_AUTH_FAILED` is the truthful
/// verdict. Every other read failure is operational — failing or disconnected
/// storage, a permission change, a transient fault — and says nothing about
/// the stored ciphertext, which may be entirely intact. Reporting those as an
/// authentication failure makes the caller condemn healthy canonical data, so
/// they keep an operational code and never accuse the bytes.
fn read_error(error: &std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        corrupt()
    } else {
        AppError::new(ErrorCode::Internal)
    }
}
fn output_error(error: &std::io::Error) -> AppError {
    AppError::new(if error.kind() == std::io::ErrorKind::StorageFull {
        ErrorCode::DiskFull
    } else {
        ErrorCode::Internal
    })
}
fn nonce(header: &[u8; HEADER_SIZE], counter: u64) -> XNonce {
    let mut value = [0; 24];
    value[..16].copy_from_slice(&header[36..52]);
    value[16..].copy_from_slice(&counter.to_le_bytes());
    value.into()
}
fn receipt(hash: Sha256, size_bytes: u64) -> DigestReceipt {
    DigestReceipt {
        sha256_hex: hex(hash.finalize().as_slice()),
        size_bytes,
    }
}

/// Streams exactly `size` source bytes into DVB1, hashing that same source pass.
/// The caller owns flush/sync/close and canonical activation.
/// # Errors
/// Returns `SOURCE_UNREADABLE` for short/long/unreadable input and typed output errors.
pub fn encrypt(
    source: &mut impl Read,
    output: &mut impl Write,
    key: &BlobKey,
    id: &[u8; 16],
    size: u64,
) -> Result<DigestReceipt, AppError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| corrupt())?;
    let mut header = [0; HEADER_SIZE];
    header[..4].copy_from_slice(b"DVB1");
    header[4..6].copy_from_slice(&1_u16.to_le_bytes());
    header[6..8].copy_from_slice(&1_u16.to_le_bytes());
    header[8..24].copy_from_slice(id);
    header[24..28].copy_from_slice(&4_194_304_u32.to_le_bytes());
    header[28..36].copy_from_slice(&size.to_le_bytes());
    header[36..].copy_from_slice(&random_id()?);
    let tag = cipher
        .encrypt(
            &nonce(&header, 0),
            Payload {
                msg: &[],
                aad: &header,
            },
        )
        .map_err(|_| corrupt())?;
    output
        .write_all(&header)
        .map_err(|error| output_error(&error))?;
    output
        .write_all(&tag)
        .map_err(|error| output_error(&error))?;
    let mut buffer = Zeroizing::new(vec![0; CHUNK_SIZE]);
    let mut hash = Sha256::new();
    let mut remaining = size;
    let mut index = 0_u64;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(CHUNK_SIZE as u64)).map_err(|_| corrupt())?;
        source
            .read_exact(&mut buffer[..length])
            .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?;
        hash.update(&buffer[..length]);
        let mut aad = [0; HEADER_SIZE + 12];
        aad[..HEADER_SIZE].copy_from_slice(&header);
        aad[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&index.to_le_bytes());
        aad[HEADER_SIZE + 8..]
            .copy_from_slice(&u32::try_from(length).map_err(|_| corrupt())?.to_le_bytes());
        let encrypted = cipher
            .encrypt(
                &nonce(&header, index + 1),
                Payload {
                    msg: &buffer[..length],
                    aad: &aad,
                },
            )
            .map_err(|_| corrupt())?;
        output
            .write_all(&aad[HEADER_SIZE..])
            .map_err(|error| output_error(&error))?;
        output
            .write_all(&encrypted)
            .map_err(|error| output_error(&error))?;
        remaining -= length as u64;
        index += 1;
    }
    let mut extra = [0];
    if source
        .read(&mut extra)
        .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?
        != 0
    {
        return Err(AppError::new(ErrorCode::SourceUnreadable));
    }
    Ok(receipt(hash, size))
}

/// Authenticates a complete DVB1 original before committing its sink.
/// `expected` binds recovery to the encrypted DB's independently stored identity.
/// # Errors
/// `BLOB_AUTH_FAILED` on any wrong context, malformed framing or authentication error.
/// Every failure aborts the sink; no successful receipt or partial content is returned.
pub fn decrypt(
    source: &mut impl Read,
    key: &BlobKey,
    id: &[u8; 16],
    expected: Option<&DigestReceipt>,
    sink: &mut impl PlaintextSink,
) -> Result<DigestReceipt, AppError> {
    let result = decrypt_frames(source, key, id, sink).and_then(|actual| {
        if expected.is_some_and(|value| value != &actual) {
            return Err(corrupt());
        }
        sink.commit(&actual)?;
        Ok(actual)
    });
    if result.is_err() {
        sink.abort();
    }
    result
}

fn decrypt_frames(
    source: &mut impl Read,
    key: &BlobKey,
    id: &[u8; 16],
    sink: &mut impl PlaintextSink,
) -> Result<DigestReceipt, AppError> {
    let mut header = [0; HEADER_SIZE];
    source
        .read_exact(&mut header)
        .map_err(|error| read_error(&error))?;
    if &header[..4] != b"DVB1"
        || header[4..6] != 1_u16.to_le_bytes()
        || header[6..8] != 1_u16.to_le_bytes()
        || &header[8..24] != id
        || header[24..28] != 4_194_304_u32.to_le_bytes()
    {
        return Err(corrupt());
    }
    let size = u64::from_le_bytes(header[28..36].try_into().map_err(|_| corrupt())?);
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| corrupt())?;
    let mut tag = [0; 16];
    source
        .read_exact(&mut tag)
        .map_err(|error| read_error(&error))?;
    cipher
        .decrypt(
            &nonce(&header, 0),
            Payload {
                msg: &tag,
                aad: &header,
            },
        )
        .map_err(|_| corrupt())?;
    let mut encrypted = vec![0; CHUNK_SIZE + 16];
    let mut remaining = size;
    let mut index = 0_u64;
    let mut hash = Sha256::new();
    while remaining > 0 {
        let mut aad = [0; HEADER_SIZE + 12];
        aad[..HEADER_SIZE].copy_from_slice(&header);
        source
            .read_exact(&mut aad[HEADER_SIZE..])
            .map_err(|error| read_error(&error))?;
        let length = usize::try_from(remaining.min(CHUNK_SIZE as u64)).map_err(|_| corrupt())?;
        if aad[HEADER_SIZE..HEADER_SIZE + 8] != index.to_le_bytes()
            || aad[HEADER_SIZE + 8..] != u32::try_from(length).map_err(|_| corrupt())?.to_le_bytes()
        {
            return Err(corrupt());
        }
        source
            .read_exact(&mut encrypted[..length + 16])
            .map_err(|error| read_error(&error))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce(&header, index + 1),
                    Payload {
                        msg: &encrypted[..length + 16],
                        aad: &aad,
                    },
                )
                .map_err(|_| corrupt())?,
        );
        hash.update(plain.as_slice());
        sink.stage(plain.as_slice())?;
        remaining -= length as u64;
        index += 1;
    }
    let mut extra = [0];
    if source
        .read(&mut extra)
        .map_err(|error| read_error(&error))?
        != 0
    {
        return Err(corrupt());
    }
    Ok(receipt(hash, size))
}

/// Encodes bytes without including them in logs or error details.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

/// SHA-256 for bounded metadata such as schema identity; originals use streaming APIs.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultMasterKey;

    #[derive(Default)]
    struct Sink {
        provisional: Vec<u8>,
        committed: Vec<u8>,
        aborted: bool,
    }
    impl PlaintextSink for Sink {
        fn stage(&mut self, chunk: &[u8]) -> Result<(), AppError> {
            self.provisional.extend_from_slice(chunk);
            Ok(())
        }
        fn commit(&mut self, _: &DigestReceipt) -> Result<(), AppError> {
            self.committed = std::mem::take(&mut self.provisional);
            Ok(())
        }
        fn abort(&mut self) {
            self.provisional.clear();
            self.committed.clear();
            self.aborted = true;
        }
    }
    fn key(id: &[u8; 16]) -> Result<BlobKey, AppError> {
        VaultMasterKey::from_injected_bytes(Zeroizing::new([7; 32]))
            .storage_keys()?
            .1
            .for_blob(id)
    }
    fn encoded(bytes: &[u8], id: &[u8; 16]) -> Result<Vec<u8>, AppError> {
        let mut output = vec![];
        encrypt(&mut &*bytes, &mut output, &key(id)?, id, bytes.len() as u64)?;
        Ok(output)
    }
    /// A deterministic reader that serves valid bytes up to `fail_at` and then
    /// fails with a chosen kind.
    ///
    /// Operational read failures must be provable at an exact DVB1 phase
    /// without damaging real storage or depending on a platform's filesystem
    /// behaviour, so the failure is injected in the reader rather than in the
    /// bytes.
    struct FaultyReader<'a> {
        bytes: &'a [u8],
        position: usize,
        fail_at: usize,
        kind: std::io::ErrorKind,
    }
    impl<'a> FaultyReader<'a> {
        fn new(bytes: &'a [u8], fail_at: usize, kind: std::io::ErrorKind) -> Self {
            Self {
                bytes,
                position: 0,
                fail_at,
                kind,
            }
        }
    }
    impl Read for FaultyReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.position >= self.fail_at {
                return Err(std::io::Error::from(self.kind));
            }
            let available = (self.fail_at - self.position)
                .min(self.bytes.len() - self.position)
                .min(buffer.len());
            buffer[..available]
                .copy_from_slice(&self.bytes[self.position..self.position + available]);
            self.position += available;
            Ok(available)
        }
    }

    /// Every DVB1 read phase, named by the byte offset at which that phase's
    /// first byte is consumed from the stored stream.
    fn read_phases(length: usize) -> [(&'static str, usize); 5] {
        [
            ("header", 10),
            ("header authentication tag", HEADER_SIZE + 4),
            ("frame index/length", HEADER_SIZE + 16 + 4),
            ("encrypted frame payload", HEADER_SIZE + 16 + 12 + 4),
            ("trailing byte", length),
        ]
    }

    fn reject(bytes: &[u8], id: &[u8; 16]) -> Result<(), Box<dyn std::error::Error>> {
        let mut sink = Sink::default();
        let error = decrypt(&mut &*bytes, &key(id)?, id, None, &mut sink)
            .err()
            .ok_or("corruption accepted")?;
        assert_eq!(error.code, ErrorCode::BlobAuthFailed);
        assert!(sink.aborted && sink.provisional.is_empty() && sink.committed.is_empty());
        Ok(())
    }
    #[test]
    fn exact_roundtrip_boundary_matrix() -> Result<(), Box<dyn std::error::Error>> {
        for length in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE + 19,
        ] {
            let source: Vec<u8> = (0..length).map(|i| i.to_le_bytes()[0]).collect();
            let bytes = encoded(&source, &[1; 16])?;
            let mut sink = Sink::default();
            let actual = decrypt(
                &mut bytes.as_slice(),
                &key(&[1; 16])?,
                &[1; 16],
                None,
                &mut sink,
            )?;
            assert_eq!(actual.sha256_hex, sha256(&source));
            assert_eq!(actual.size_bytes, length as u64);
            assert_eq!(sink.committed, source);
        }
        Ok(())
    }
    #[test]
    fn authenticated_corruption_matrix_aborts_all_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let id = [1; 16];
        let bytes = encoded(&vec![37; 2 * CHUNK_SIZE + 7], &id)?;
        let first_end = HEADER_SIZE + 16 + 12 + CHUNK_SIZE + 16;
        let second_end = first_end + 12 + CHUNK_SIZE + 16;
        for offset in [
            0,
            4,
            6,
            8,
            24,
            28,
            36,
            52,
            68,
            76,
            80,
            first_end - 1,
            bytes.len() - 1,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            reject(&changed, &id)?;
        }
        for length in [
            0,
            3,
            51,
            67,
            68,
            79,
            80,
            first_end - 1,
            first_end,
            second_end,
            bytes.len() - 1,
        ] {
            reject(&bytes[..length], &id)?;
        }
        let mut reordered = bytes.clone();
        reordered[68..first_end].copy_from_slice(&bytes[first_end..second_end]);
        reordered[first_end..second_end].copy_from_slice(&bytes[68..first_end]);
        reject(&reordered, &id)?;
        let mut duplicated = bytes.clone();
        duplicated[first_end..second_end].copy_from_slice(&bytes[68..first_end]);
        reject(&duplicated, &id)?;
        let other = encoded(&vec![37; 2 * CHUNK_SIZE + 7], &[2; 16])?;
        let mut substituted = bytes.clone();
        substituted[first_end..second_end].copy_from_slice(&other[first_end..second_end]);
        reject(&substituted, &id)?;
        reject(&bytes, &[2; 16])?;
        let wrong_key = VaultMasterKey::from_injected_bytes(Zeroizing::new([8; 32]))
            .storage_keys()?
            .1
            .for_blob(&id)?;
        let mut sink = Sink::default();
        assert!(decrypt(&mut bytes.as_slice(), &wrong_key, &id, None, &mut sink).is_err());
        assert!(sink.aborted && sink.committed.is_empty());
        let mut appended = bytes.clone();
        appended.push(0);
        reject(&appended, &id)?;
        let expected = DigestReceipt {
            sha256_hex: "0".repeat(64),
            size_bytes: 2 * CHUNK_SIZE as u64 + 7,
        };
        assert!(
            decrypt(
                &mut bytes.as_slice(),
                &key(&id)?,
                &id,
                Some(&expected),
                &mut sink
            )
            .is_err()
        );
        assert!(sink.committed.is_empty());
        Ok(())
    }
    /// T2: an operational read failure over an intact stored stream must never
    /// be reported as an authentication failure, because the caller condemns
    /// canonical data on that verdict.
    #[test]
    fn operational_read_failures_never_authenticate_as_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = [1; 16];
        let bytes = encoded(&[9; 3], &id)?;
        for (phase, offset) in read_phases(bytes.len()) {
            // `read_exact` retries `Interrupted` internally, so a reader that
            // returned it forever would spin: it is exercised at the trailing
            // single `read` phase, which has no retry loop.
            let kinds: &[std::io::ErrorKind] = if phase == "trailing byte" {
                &[
                    std::io::ErrorKind::PermissionDenied,
                    std::io::ErrorKind::Interrupted,
                    std::io::ErrorKind::BrokenPipe,
                    std::io::ErrorKind::TimedOut,
                    std::io::ErrorKind::Other,
                ]
            } else {
                &[
                    std::io::ErrorKind::PermissionDenied,
                    std::io::ErrorKind::BrokenPipe,
                    std::io::ErrorKind::TimedOut,
                    std::io::ErrorKind::ConnectionAborted,
                    std::io::ErrorKind::Other,
                ]
            };
            for &kind in kinds {
                let mut sink = Sink::default();
                let mut reader = FaultyReader::new(&bytes, offset, kind);
                let error = decrypt(&mut reader, &key(&id)?, &id, None, &mut sink)
                    .err()
                    .ok_or(format!("{phase}: operational {kind:?} accepted"))?;
                assert_eq!(
                    error.code,
                    ErrorCode::Internal,
                    "{phase}: {kind:?} must stay operational"
                );
                assert_ne!(error.code, ErrorCode::BlobAuthFailed, "{phase}: {kind:?}");
                assert_ne!(error.code, ErrorCode::MissingBlob, "{phase}: {kind:?}");
                // Reclassifying the code must not weaken the transactional sink.
                assert!(
                    sink.aborted && sink.provisional.is_empty() && sink.committed.is_empty(),
                    "{phase}: {kind:?} committed partial plaintext"
                );
            }
        }
        Ok(())
    }

    /// T2 control: a genuinely truncated stored stream is a content failure and
    /// must keep authenticating as corruption at every framing phase.
    #[test]
    fn truncation_still_authenticates_as_corruption() -> Result<(), Box<dyn std::error::Error>> {
        let id = [1; 16];
        let bytes = encoded(&[9; 3], &id)?;
        for (phase, offset) in read_phases(bytes.len()) {
            // An explicit UnexpectedEof from the reader.
            let mut sink = Sink::default();
            let mut reader = FaultyReader::new(&bytes, offset, std::io::ErrorKind::UnexpectedEof);
            let error = decrypt(&mut reader, &key(&id)?, &id, None, &mut sink)
                .err()
                .ok_or(format!("{phase}: truncation accepted"))?;
            assert_eq!(
                error.code,
                ErrorCode::BlobAuthFailed,
                "{phase}: truncation must stay an authentication failure"
            );
            assert!(sink.aborted && sink.provisional.is_empty() && sink.committed.is_empty());
            // And real truncation of the stored bytes, which reaches the same
            // phase through the ordinary end-of-stream path.
            if offset < bytes.len() {
                reject(&bytes[..offset], &id)?;
            }
        }
        // AEAD authentication failure and malformed framing are unchanged.
        let mut flipped = bytes.clone();
        flipped[HEADER_SIZE + 16 + 12] ^= 1;
        reject(&flipped, &id)?;
        let mut malformed = bytes.clone();
        malformed[0] ^= 1;
        reject(&malformed, &id)?;
        Ok(())
    }

    #[test]
    fn source_length_changes_never_succeed() -> Result<(), AppError> {
        for size in [0, 2] {
            assert!(encrypt(&mut &[1][..], &mut vec![], &key(&[1; 16])?, &[1; 16], size).is_err());
        }
        Ok(())
    }
}
