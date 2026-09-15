/** Temporary, explicitly authorized violations; every byte is restored in finally. */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
function replaceOnce(source, before, after) {
  if (source.split(before).length !== 2) throw new Error('Negative control seam drifted.');
  return source.replace(before, after);
}
/** Joins multi-line seams with the newline the checkout actually uses. */
function replaceBlock(source, before, after) {
  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  return replaceOnce(source, before.join(eol), after.join(eol));
}
const cases = [
  {
    name: 'native-archive-pin',
    path: 'scripts/prepare-sodium.mjs',
    mutate: (s) => replaceOnce(s, '3e03a726', '4e03a726'),
    command: 'node',
    args: ['scripts/prepare-sodium.mjs'],
    exit: 1,
    marker: 'Cached libsodium archive hash mismatch.',
  },
  {
    name: 'argon2-iteration-mapping',
    path: 'crates/dvm-crypto/src/sodium.rs',
    mutate: (s) =>
      replaceOnce(s, 'u64::from(profile.iterations),', 'u64::from(profile.iterations) + 1,'),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-crypto',
      '--lib',
      'argon2id13_matches_independent_public_vectors',
    ],
    marker: 'Argon2id v1.3 compatibility mismatch',
  },
  {
    name: 'serialized-secret',
    path: 'crates/dvm-domain/src/security.rs',
    mutate: (s) =>
      `${s}\nimpl serde::Serialize for SecretValue {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
          self.as_bytes().serialize(serializer)
        }
      }\n`,
    args: ['test', '--locked', '-p', 'dvm-domain', '--doc', 'SecretValue'],
    marker: "Test compiled successfully, but it's marked `compile_fail`.",
  },
  {
    name: 'unauthenticated-slot-id',
    path: 'crates/dvm-crypto/src/keyslots.rs',
    mutate: (s) => replaceOnce(s, 'slot.id.as_bytes(),', 'b"",'),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-crypto',
      '--lib',
      'tamper_matrix_every_aad_field_and_ciphertext',
    ],
    marker: 'tampered field 2 was accepted',
  },
  {
    name: 'wrong-passphrase-mutation',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceOnce(
        s,
        'let envelope = read_header(&self.root)?;',
        `let envelope = read_header(&self.root)?;
         let _ = OpenOptions::new().create(true).append(true).open(self.root.join("negative-control"))
             .and_then(|mut f| f.write_all(b"x"));`,
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'wrong_passphrase_no_durable_mutation_and_locked_guard',
    ],
    marker: 'failed unlock changed durable bytes or file set',
  },
  {
    name: 'locked-content-admission',
    path: 'crates/dvm-application/src/session.rs',
    mutate: (s) => {
      const start = s.indexOf('pub fn with_open');
      const end = s.indexOf('pub fn lock');
      const check = `if inner.state != VaultState::Open {
            return Err(AppError::new(ErrorCode::VaultLocked));
        }`;
      const guarded = replaceOnce(s.slice(start, end), check, '');
      const locking = replaceOnce(
        s.slice(end),
        'inner.active = None;',
        '// negative control retains active owner',
      );
      return s.slice(0, start) + guarded + locking;
    },
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-application',
      '--lib',
      'locked_operation_guard_is_effective',
    ],
    marker: 'locked operation was admitted',
  },
  {
    name: 'activated-header-ambiguity',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceBlock(
        s,
        [
          '    if let Err(error) = checkpoint("after-activation") {',
          '        return Ok(HeaderDurability::Uncertain(error));',
          '    }',
        ],
        ['    checkpoint("after-activation")?;'],
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'header_failure_matrix_separates_pre_and_post_activation',
    ],
    marker: 'committed activation reported as failure',
  },
  {
    name: 'credential-reference-validator-drift',
    path: 'crates/dvm-crypto/src/keyslots.rs',
    mutate: (s) =>
      replaceOnce(
        s,
        '&& is_canonical_device_reference(&slot.credential_ref) => {}',
        '&& (is_canonical_device_reference(&slot.credential_ref) || slot.credential_ref.starts_with("dvm/device/")) => {}',
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'credential_reference_language_is_shared_by_keyslot_and_adapter',
    ],
    marker: 'keyslot admitted a reference the credential adapter refuses',
  },
  {
    name: 'cleanup-overrides-primary-failure',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceBlock(
        s,
        [
          '            // The store failure stays primary; cleanup is recorded beside it.',
          '            let cleanup = self.discard(&reference);',
          '            return Err(NotActivated::new(primary, cleanup));',
        ],
        [
          '            self.credentials.delete(&reference)?;',
          '            return Err(primary.into());',
        ],
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'cleanup_failure_is_recorded_without_replacing_the_primary_failure',
    ],
    marker: 'cleanup failure replaced the primary store error',
  },
  {
    name: 'stale-device-slot-unrecoverable',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceOnce(
        s,
        'let Some(secret) = self.credentials.retrieve(&slot.credential_ref)? else {',
        'let Some(secret) = self.credentials.retrieve(&slot.credential_ref).unwrap_or(None) else {',
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'stale_device_slot_is_re_enrolled_only_on_proven_absence',
    ],
    marker: 'an operational credential-store failure was mistaken for absence',
  },
  {
    // U1: presence of a credential treated as proof that the slot is usable,
    // without checking its length, authenticating it, or comparing the root it
    // unwraps with the active VMK.
    name: 'present-device-credential-assumed-healthy',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceBlock(
        s,
        [
          '        let Ok(root) = DeviceKey::from_credential(secret.as_bytes())',
          '            .and_then(|key| keyslots::unwrap_device(vault_id, slot, &key))',
          '        else {',
          '            return Ok(DeviceSlotHealth::Unusable);',
          '        };',
          '        // A trusted-memory comparison of derived roots, the same equality the',
          '        // passphrase rewrap path uses. No root or fingerprint is serialized,',
          '        // logged or returned.',
          '        if root.storage_keys()?.0.as_bytes() == self.vmk.storage_keys()?.0.as_bytes() {',
          '            Ok(DeviceSlotHealth::Healthy)',
          '        } else {',
          '            Ok(DeviceSlotHealth::Unusable)',
          '        }',
        ],
        ['        drop(secret);', '        Ok(DeviceSlotHealth::Healthy)'],
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'present_but_unusable_device_credential_is_re_enrolled',
    ],
    marker: 'a present but unusable device credential blocked re-enrollment',
  },
  {
    // U2: a completed cleanup treated as unfinished work.
    name: 'completed-cleanup-reported-unsettled',
    path: 'crates/dvm-domain/src/security.rs',
    mutate: (s) =>
      replaceOnce(
        s,
        'self.durability.is_durable() && !self.cleanup.is_failed()',
        'self.durability.is_durable() && matches!(self.cleanup, CleanupOutcome::NotRequired)',
      ),
    args: ['test', '--locked', '-p', 'dvm-domain', '--lib', 'settlement_truth_table_is_exhaustive'],
    marker: 'settlement is wrong for durable=true cleanup=Completed',
  },
  {
    // U3: the credential that set_secret already persisted left in place after
    // post-write persistence verification fails.
    name: 'post-write-verification-leaves-credential',
    path: 'crates/dvm-storage/src/credentials.rs',
    mutate: (s) =>
      replaceBlock(
        s,
        [
          '            if let Err(primary) = verify_persisted(reference, &entry) {',
          '                record(compensate(reference, &entry));',
          '                return Err(primary);',
          '            }',
        ],
        [
          '            if let Err(primary) = verify_persisted(reference, &entry) {',
          '                return Err(primary);',
          '            }',
        ],
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'post_write_persistence_failure_removes_the_credential_it_wrote',
    ],
    marker: 'no compensating delete was attempted after post-write verification failed',
  },
  {
    // U4: an absent device slot classified as a failed passphrase attempt.
    name: 'missing-device-slot-as-bad-passphrase',
    path: 'crates/dvm-storage/src/security.rs',
    mutate: (s) =>
      replaceOnce(
        s,
        'UnlockCredential::Device => ("device-v1", ErrorCode::ProviderUnavailable),',
        'UnlockCredential::Device => ("device-v1", ErrorCode::BadPassphrase),',
      ),
    args: [
      'test',
      '--locked',
      '-p',
      'dvm-storage',
      '--lib',
      'device_unlock_without_a_device_slot_reports_provider_unavailable',
    ],
    marker: 'a missing device slot was reported as a passphrase failure',
  },
];

for (const control of cases) {
  const path = join(root, control.path);
  const original = readFileSync(path);
  let failure;
  try {
    writeFileSync(path, control.mutate(original.toString('utf8')));
    const result = spawnSync(control.command ?? 'cargo', control.args, {
      cwd: root,
      env: process.env,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    const expectedExit = control.exit ?? 101;
    if (result.status !== expectedExit || !output.includes(control.marker)) {
      process.stdout.write(output);
      throw new Error(`${control.name}: expected security assertion did not fail`);
    }
    console.log(
      `NEGATIVE_CONTROL ${control.name}: detected by expected oracle; EXIT ${expectedExit}`,
    );
  } catch (error) {
    failure = error;
  } finally {
    writeFileSync(path, original);
  }
  if (!readFileSync(path).equals(original)) throw new Error('Source restoration failed.');
  if (failure) throw failure;
}
console.log('G2_NEGATIVE_CONTROLS=PASS; all source bytes restored');
