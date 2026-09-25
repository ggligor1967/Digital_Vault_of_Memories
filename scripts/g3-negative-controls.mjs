/** Temporary G3 violations; each exact source buffer is restored in finally. */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
function replaceOnce(source, before, after) {
  if (source.split(before).length !== 2) throw new Error('G3 negative-control seam drifted.');
  return source.replace(before, after);
}
function replaceIn(source, start, end, before, after) {
  const left = source.indexOf(start);
  const right = source.indexOf(end, left);
  if (left < 0 || right < 0) throw new Error('G3 negative-control scope drifted.');
  return (
    source.slice(0, left) +
    replaceOnce(source.slice(left, right), before, after) +
    source.slice(right)
  );
}
const storage = 'crates/dvm-storage/src/';
const backup = 'crates/dvm-backup/src/dvbk1.rs';
const activation = 'crates/dvm-backup/src/activation.rs';
const cases = [
  ...(process.platform === 'linux'
    ? [
        {
          name: 'restore-directory-noreplace-regression',
          path: activation,
          mutate: (source) =>
            replaceOnce(
              source,
              '    before_publish();\n    renameat_with(CWD, staging, CWD, destination, RenameFlags::NOREPLACE).map_err(Into::into)',
              '    if destination.exists() { return Err(std::io::ErrorKind::AlreadyExists.into()); }\n    before_publish();\n    std::fs::rename(staging, destination)',
            ),
          package: 'dvm-backup',
          test: 'competitor_at_publish_boundary_wins_without_replacement',
        },
      ]
    : []),
  {
    name: 'migration-checksum-ignored',
    path: `${storage}migrations.rs`,
    mutate: (source) => replaceOnce(source, ' || checksum != expected.1', ''),
    package: 'dvm-storage',
    test: 'g3_migration_atomicity_and_checksum_matrix',
  },
  {
    name: 'future-schema-mutated',
    path: `${storage}database.rs`,
    mutate: (source) =>
      replaceOnce(
        source,
        'if schema > CURRENT_SCHEMA_VERSION {',
        'if schema > CURRENT_SCHEMA_VERSION { db.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION).unwrap();',
      ),
    package: 'dvm-storage',
    test: 'g3_future_schema_refusal_preserves_database_wal_and_blobs',
  },
  {
    name: 'plaintext-snapshot',
    path: `${storage}database.rs`,
    mutate: (source) =>
      replaceIn(
        source,
        'pub(crate) fn snapshot_encrypted(',
        '/// Opens an existing encrypted snapshot',
        '        Ok(())',
        '        std::fs::write(path, b"SQLite format 3\\0").map_err(|error| crate::vault::io_error(&error))?;\n        Ok(())',
      ),
    package: 'dvm-storage',
    test: 'sqlcipher_online_backup_encrypts_destination_with_live_wal',
  },
  {
    name: 'archive-traversal-admitted',
    path: backup,
    mutate: (source) =>
      replaceOnce(
        source,
        'fn valid_member_name(name: &str) -> bool {',
        'fn valid_member_name(name: &str) -> bool { if name == "../escape" { return true; }',
      ),
    package: 'dvm-backup',
    test: 'archive_path_and_special_entry_matrix_is_rejected',
  },
  {
    name: 'public-format-aad-ignored',
    path: backup,
    mutate: (source) => {
      const before = 'aad: public,';
      if (source.split(before).length !== 3) throw new Error('G3 AAD seam drifted.');
      return source.replaceAll(before, 'aad: b"",');
    },
    package: 'dvm-backup',
    test: 'corruption_matrix_rejects_every_corrupted_archive',
  },
  {
    name: 'full-skips-canonical-blob',
    path: backup,
    mutate: (source) => replaceOnce(source, 'if mode == VerificationMode::Full {', 'if false {'),
    package: 'dvm-backup',
    test: 'authenticated_structural_backup_still_requires_every_plaintext_hash',
  },
  {
    name: 'restore-writes-final-directly',
    path: backup,
    mutate: (source) =>
      replaceOnce(
        source,
        'let staging = parent.join(format!(".dvm-restore-{}.stage", Uuid::new_v4()));',
        'let staging = destination.clone();',
      ),
    package: 'dvm-backup',
    test: 'restore_activation_crash_matrix',
  },
  {
    name: 'plaintext-hash-mismatch-accepted',
    path: backup,
    mutate: (source) => replaceOnce(source, 'Some(receipt),', 'None,'),
    package: 'dvm-backup',
    test: 'authenticated_structural_backup_still_requires_every_plaintext_hash',
  },
];

for (const control of cases) {
  const path = join(root, control.path);
  const original = readFileSync(path);
  let failure;
  try {
    writeFileSync(path, control.mutate(original.toString('utf8')));
    const result = spawnSync(
      'cargo',
      ['test', '--locked', '-p', control.package, '--lib', control.test, '--', '--nocapture'],
      { cwd: root, env: process.env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
    );
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    if (result.status !== 101 || !output.includes('test result: FAILED')) {
      process.stdout.write(output);
      throw new Error(`${control.name}: expected G3 oracle did not fail`);
    }
    console.log(`G3_NEGATIVE_CONTROL ${control.name}: oracle failed as expected`);
  } catch (error) {
    failure = error;
  } finally {
    writeFileSync(path, original);
  }
  if (!readFileSync(path).equals(original)) throw new Error('G3 source restoration failed.');
  if (failure) throw failure;
}
console.log('G3_NEGATIVE_CONTROLS=PASS; all source bytes restored');
