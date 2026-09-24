# ADR-0013: DVBK1 backup, verification, and restore

Status: G3 implementation candidate. Existing ADR identifiers are unchanged.

We use a pinned streaming tar implementation as the DVBK1 container, with an exact member whitelist and no extraction of arbitrary paths. The encrypted manifest binds the public-format bytes and every stored member. [DVBK1](../formats/DVBK1.md) specifies the byte-level contract. No compression or network dependency is added.

Backup holds the vault's DB write mutex while SQLCipher Online Backup creates a separately keyed encrypted snapshot. Blob enumeration then uses that snapshot. Canonical blobs are immutable once published by G1, so a later import cannot alter the snapshot's member set. Backup writes a sibling application-owned `.part`, FULL-verifies it, syncs the file, and activates with a same-volume no-replace move. Only after activation is `backup_history` written. A bookkeeping failure leaves a valid archive and returns `history_recorded=false`; it never claims the archive vanished. Verification is required before a backup is considered restorable.

Restore creates a unique sibling directory on the destination volume, accepts only known paths, runs STRUCTURAL and FULL verification, creates fresh runtime directories and local-state locks, then opens the staged vault through the normal G2 unlock/reconciliation path. Only then is it activated with a no-replace move. The source archive is not modified. Stale `.dvm-backup-*.part`, `.dvm-backup-*.snapshot`, and `.dvm-restore-*.stage` are recognizable application-owned residue; operators must inspect them before cleanup. No arbitrary user directory is automatically deleted.

The Windows activation path uses `MoveFileExW` without replace or cross-volume-copy flags. File contents are synced before publication. A hardware power-loss durability guarantee for the parent directory or storage controller is not claimed. Device credential-store material is device-local and excluded; passphrase and recovery slots are portable, and G2 re-enrollment can repair unavailable quick unlock.
