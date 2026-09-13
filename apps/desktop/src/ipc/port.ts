/**
 * The renderer-side IPC boundary: *what* the renderer may ask for.
 *
 * Blueprint v2 §6.2 and §40.1 put the renderer at the outermost ring of the
 * dependency rule. React components therefore depend on this interface and
 * never on `@tauri-apps/api`: swapping the transport, or running a component
 * under test with no native process at all, must not require touching a
 * component.
 *
 * Adding a command to the application means adding a method here and an
 * implementation in `tauri-adapter.ts`. It does not mean calling `invoke`
 * from a component.
 */
import type { FoundationStatus } from '@dvm/contracts';

/** Typed access to the trusted backend's foundation commands. */
export interface FoundationPort {
  /**
   * Asks the trusted backend for its foundation status.
   *
   * Rejects with an `AppError` envelope (Blueprint v2 §23.1) when the backend
   * refuses. Callers must treat any other rejection shape as untrusted.
   */
  foundationStatus(): Promise<FoundationStatus>;
}
