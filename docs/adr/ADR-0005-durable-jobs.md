# ADR-0005: Durable verification jobs and lease generations

G1 uses one small typed VERIFY_ORIGINAL job kind; it authenticates the canonical
original and atomically writes blobs.verified_at plus jobs.DONE. It performs no
AI/media/search work. Imports enqueue one job per logical item in their own
canonical commit. Idempotency key is verify-original:<random-item-id>:1.

Job payload is exclusively blob_id and processor_version, limited to 256 bytes.
Claim is a transaction, serialized through the exclusive vault owner's mutex.
Attempts increment once per lease; worker UUID plus attempt is a lease generation.
Stale or expired owners cannot ACK. Completed replay is a no-op with no duplicate
artifact. Result failure rolls back DONE together with verified_at.

Retry delay is 2^min(attempt,8) seconds plus OS-random jitter in [0,base], bounded
at 512 seconds. max_attempts is enforced on fail and expired-lease recovery.
Expired final attempts become FAILED_TERMINAL rather than remaining stranded.
Cancellation is limited to PENDING. No unbounded worker pool or async runtime.

Job scheduling fields use zero-padded width-20 decimal Unix seconds in UTC,
allowing exact SQL TEXT ordering. Ordinary item timestamps use UTC ISO 8601.
Both are normalized unambiguous formats (Blueprint section 60). G3 owns evolution.
