# ADR-0009: Single trusted vault session owner

Status: accepted for G2 implementation; concurrency evidence pending.

The application session owns one backend port and at most one active vault.
The active storage owner owns the VMK and native DB/blob lifetime. One mutex
orders attach, unlock, operations and lock. No live handle escapes the session's
borrowed operation scope. Failed authentication happens before opening SQLCipher
or running reconciliation. Failed unlock returns LOCKED with no active owner.

Typed states: CLOSED, LOCKED, UNLOCKING, OPEN, LOCKING, DEGRADED_READ_ONLY.
Only OPEN admits secret-dependent operations. Lock linearizes under the same
mutex, drops the active owner, then reports LOCKED. Degraded storage closes
content admission; G2 does not invent a repair mechanism. Poisoned synchronization
fails closed. No accounts or background session framework is added.

Renderer IPC remains the existing foundation-status command. No content query,
credential getter, path operation, shell or network permission is introduced.
Tests prove service admission separately from the fixed IPC registry. Existing
Tauri capability and production CSP restrictions are retained.

Sources: [Tauri capabilities](https://v2.tauri.app/security/capabilities/),
[Tauri CSP](https://v2.tauri.app/security/csp/).
