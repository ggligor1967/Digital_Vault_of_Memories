//! Real production-cost crypto oracles. Secret values never enter assertion text.
use super::*;

#[test]
fn argon2id13_matches_independent_public_vectors() -> Result<(), AppError> {
    // Public compatibility inputs, never a vault credential or root key.
    let phrase = Passphrase::new(Zeroizing::new(
        "  DVM public e\u{301} 🔑 \0 vector  ".into(),
    ))?;
    // Captured from the replaced RustCrypto 0.6.0 implementation before removal.
    // Public KATs establish byte compatibility, not audit provenance.
    for (iterations, expected) in [
        (
            2,
            [
                190, 44, 70, 132, 228, 124, 203, 80, 199, 5, 15, 227, 134, 4, 201, 221, 117, 31,
                99, 144, 48, 226, 42, 110, 144, 248, 91, 243, 237, 93, 14, 89,
            ],
        ),
        (
            3,
            [
                207, 141, 88, 148, 139, 119, 244, 78, 195, 165, 145, 90, 80, 86, 176, 173, 141,
                162, 172, 199, 100, 226, 163, 0, 234, 232, 237, 84, 138, 33, 147, 63,
            ],
        ),
    ] {
        let profile = ArgonProfile {
            iterations,
            ..ArgonProfile::BASELINE
        };
        let output = passphrase_kek(&phrase, b"DVM public salt!", profile)?;
        assert!(
            output.0.as_ref() == expected,
            "Argon2id v1.3 compatibility mismatch"
        );
    }
    Ok(())
}
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn pass(value: &str) -> Result<Passphrase, AppError> {
    Passphrase::new(Zeroizing::new(value.into()))
}
fn same(a: &VaultMasterKey, b: &VaultMasterKey) -> Result<(), AppError> {
    assert!(a.0.as_ref() == b.0.as_ref(), "VMK identity mismatch");
    assert!(
        a.storage_keys()?.0.as_bytes() == b.storage_keys()?.0.as_bytes(),
        "DB domain changed"
    );
    assert!(
        a.storage_keys()?.1.for_blob(&[7; 16])?.0.as_ref()
            == b.storage_keys()?.1.for_blob(&[7; 16])?.0.as_ref(),
        "blob domain changed"
    );
    Ok(())
}

#[test]
fn passphrase_policy_roundtrip_and_cost_floor() -> TestResult {
    let id = Uuid::new_v4().to_string();
    let vmk = VaultMasterKey::generate()?;
    let phrase = pass("  Amintiri e\u{301} 🔑 \0 exact  ")?;
    let first = wrap_passphrase(&id, &vmk, &phrase, ArgonProfile::BASELINE)?;
    let second = wrap_passphrase(&id, &vmk, &phrase, ArgonProfile::BASELINE)?;
    assert_ne!(first.salt, second.salt);
    assert_ne!(first.nonce, second.nonce);
    let reopened: Keyslot = serde_json::from_slice(&serde_json::to_vec(&first)?)?;
    same(&vmk, &unwrap_passphrase(&id, &reopened, &phrase)?)?;
    for wrong in [
        "wrong",
        "Amintiri e\u{301} 🔑 \0 exact",
        "  Amintiri é 🔑 \0 exact  ",
    ] {
        assert_eq!(
            unwrap_passphrase(&id, &first, &pass(wrong)?)
                .err()
                .ok_or("expected failure")?
                .code,
            ErrorCode::BadPassphrase
        );
    }
    for invalid in [
        ArgonProfile {
            memory_kib: 19455,
            ..ArgonProfile::BASELINE
        },
        ArgonProfile {
            iterations: 1,
            ..ArgonProfile::BASELINE
        },
        ArgonProfile {
            parallelism: 0,
            ..ArgonProfile::BASELINE
        },
        ArgonProfile {
            parallelism: 2,
            ..ArgonProfile::BASELINE
        },
        ArgonProfile {
            memory_kib: u32::MAX,
            ..ArgonProfile::BASELINE
        },
        ArgonProfile {
            iterations: u32::MAX,
            ..ArgonProfile::BASELINE
        },
    ] {
        assert!(wrap_passphrase(&id, &vmk, &phrase, invalid).is_err());
    }
    assert!(pass("").is_err());
    assert!(pass(&"x".repeat(1025)).is_err());
    Ok(())
}

#[test]
fn independent_slots_rewrap_and_subkey_domains() -> TestResult {
    let id = Uuid::new_v4().to_string();
    let vmk = VaultMasterKey::generate()?;
    let recovery = RecoverySecret::generate()?;
    let encoded = recovery.encode_for_trusted_presentation();
    assert_eq!(encoded.len(), 64);
    let restored = RecoverySecret::decode(encoded)?;
    let device = DeviceKey::generate()?;
    let r = wrap_recovery(&id, &vmk, &recovery)?;
    let d = wrap_device(
        &id,
        &vmk,
        &device,
        format!("dvm/device/{id}/{}", Uuid::new_v4()),
    )?;
    let p = wrap_passphrase(&id, &vmk, &pass("first phrase")?, ArgonProfile::BASELINE)?;
    let stronger = ArgonProfile {
        iterations: 3,
        ..ArgonProfile::BASELINE
    };
    let upgraded = wrap_passphrase(
        &id,
        &unwrap_passphrase(&id, &p, &pass("first phrase")?)?,
        &pass("new phrase")?,
        stronger,
    )?;
    same(
        &vmk,
        &unwrap_passphrase(&id, &upgraded, &pass("new phrase")?)?,
    )?;
    same(&vmk, &unwrap_recovery(&id, &r, &restored)?)?;
    same(&vmk, &unwrap_device(&id, &d, &device)?)?;
    assert!(unwrap_passphrase(&id, &upgraded, &pass("first phrase")?).is_err());
    assert!(unwrap_recovery(&id, &r, &RecoverySecret::generate()?).is_err());
    assert!(unwrap_device(&id, &d, &DeviceKey::generate()?).is_err());
    let (db, blob) = vmk.storage_keys()?;
    let (audit, backup) = vmk.auxiliary_keys()?;
    let blob = blob.for_blob(&[0; 16])?;
    let values = [
        db.as_bytes().as_slice(),
        blob.0.as_ref(),
        audit.as_bytes(),
        backup.as_bytes(),
    ];
    for i in 0..values.len() {
        for j in i + 1..values.len() {
            assert!(values[i] != values[j], "subkey domain collision");
        }
    }
    Ok(())
}

#[test]
fn tamper_matrix_every_aad_field_and_ciphertext() -> TestResult {
    let id = Uuid::new_v4().to_string();
    let vmk = VaultMasterKey::generate()?;
    let phrase = pass("tamper test production profile")?;
    let recovery = RecoverySecret::generate()?;
    let device = DeviceKey::generate()?;
    let slots = [
        wrap_passphrase(&id, &vmk, &phrase, ArgonProfile::BASELINE)?,
        wrap_recovery(&id, &vmk, &recovery)?,
        wrap_device(
            &id,
            &vmk,
            &device,
            format!("dvm/device/{id}/{}", Uuid::new_v4()),
        )?,
    ];
    for original in &slots {
        let unwrap_slot = |vault: &str, slot: &Keyslot| match original.slot_type.as_str() {
            "passphrase-v1" => unwrap_passphrase(vault, slot, &phrase),
            "recovery-v1" => unwrap_recovery(vault, slot, &recovery),
            _ => unwrap_device(vault, slot, &device),
        };
        same(&vmk, &unwrap_slot(&id, original)?)?;
        assert!(unwrap_slot(&Uuid::new_v4().to_string(), original).is_err());
        for mutation in 0..13 {
            let mut slot = original.clone();
            match mutation {
                0 => slot.slot_type = "unknown-v1".into(),
                1 => slot.version = 2,
                2 => slot.id = Uuid::new_v4().to_string(),
                3 => slot.kdf_algorithm.push('x'),
                4 => slot.wrap_algorithm.push('x'),
                5 => slot.nonce[0] ^= 1,
                6 => slot.wrapped_vmk[0] ^= 1,
                7 => slot.wrapped_vmk[47] ^= 1,
                8 => {
                    if let Some(p) = &mut slot.argon {
                        p.iterations += 1;
                    } else {
                        slot.argon = Some(ArgonProfile::BASELINE);
                    }
                }
                9 => {
                    if slot.salt.is_empty() {
                        slot.salt.push(0);
                    } else {
                        slot.salt[0] ^= 1;
                    }
                }
                10 => slot.credential_ref.push('a'),
                11 => {
                    if let Some(p) = &mut slot.argon {
                        p.memory_kib += 1024;
                    } else {
                        slot.argon = Some(ArgonProfile::BASELINE);
                    }
                }
                _ => {
                    if let Some(p) = &mut slot.argon {
                        p.parallelism += 1;
                    } else {
                        slot.argon = Some(ArgonProfile::BASELINE);
                    }
                }
            }
            assert!(
                unwrap_slot(&id, &slot).is_err(),
                "tampered field {mutation} was accepted"
            );
        }
    }
    Ok(())
}

#[test]
fn serialized_slots_contain_no_plaintext_credentials_or_roots() -> TestResult {
    let id = Uuid::new_v4().to_string();
    let vmk = VaultMasterKey::generate()?;
    let phrase = pass("DVM synthetic passphrase isolation input")?;
    let recovery = RecoverySecret::generate()?;
    let device = DeviceKey::generate()?;
    let slots = [
        wrap_passphrase(&id, &vmk, &phrase, ArgonProfile::BASELINE)?,
        wrap_recovery(&id, &vmk, &recovery)?,
        wrap_device(
            &id,
            &vmk,
            &device,
            format!("dvm/device/{id}/{}", Uuid::new_v4()),
        )?,
    ];
    let bytes = serde_json::to_vec(&slots)?;
    for secret in [
        vmk.0.as_ref(),
        phrase.0.as_bytes(),
        recovery.0.as_ref(),
        device.0.as_ref(),
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret),
            "raw secret in serialized slots"
        );
        let numeric_encoding = Zeroizing::new(serde_json::to_vec(secret)?);
        assert!(
            !bytes
                .windows(numeric_encoding.len())
                .any(|w| w == numeric_encoding.as_slice()),
            "numeric secret encoding in slots"
        );
    }
    let encoded = recovery.encode_for_trusted_presentation();
    assert!(
        !bytes
            .windows(encoded.len())
            .any(|w| w == encoded.as_bytes())
    );
    Ok(())
}

#[test]
fn calibration_records_only_public_parameters() -> TestResult {
    let (profile, elapsed) = calibrate()?;
    validate_profile(profile)?;
    println!(
        "G2_ARGON2_CALIBRATION memory_kib={} iterations={} parallelism={} elapsed_ms={}",
        profile.memory_kib,
        profile.iterations,
        profile.parallelism,
        elapsed.as_millis()
    );
    Ok(())
}
