/**
 * The runtime guards are the renderer's only defence against a payload that
 * does not match the contract, so they are tested against hostile shapes
 * rather than only against the happy path.
 */
import { ERROR_CODES, FOUNDATION_HEALTHS } from '@dvm/contracts';
import { makeAppError, makeFoundationStatus } from '@dvm/test-fixtures';
import { describe, expect, it } from 'vitest';

import { isAppError, isErrorCode, isFoundationHealth, isFoundationStatus } from './parse.ts';

/** Returns a shallow copy of `value` with `field` removed. */
function without(value: object, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

describe('isErrorCode', () => {
  it('accepts every generated code', () => {
    for (const code of ERROR_CODES) {
      expect(isErrorCode(code)).toBe(true);
    }
  });

  it('rejects lookalikes and non-strings', () => {
    for (const value of ['internal', 'INTERNAL_', '', null, undefined, 7, {}, ['INTERNAL']]) {
      expect(isErrorCode(value)).toBe(false);
    }
  });
});

describe('isFoundationHealth', () => {
  it('accepts every generated discriminant', () => {
    for (const health of FOUNDATION_HEALTHS) {
      expect(isFoundationHealth(health)).toBe(true);
    }
  });

  it('rejects anything else', () => {
    for (const value of ['OK', 'healthy', '', null, true]) {
      expect(isFoundationHealth(value)).toBe(false);
    }
  });
});

describe('isAppError', () => {
  it('accepts a complete envelope', () => {
    expect(isAppError(makeAppError())).toBe(true);
  });

  it('accepts an envelope carrying sanitised details', () => {
    expect(isAppError(makeAppError('DISK_FULL', { safe_details: 'volume full' }))).toBe(true);
  });

  it('rejects an envelope with an unknown code', () => {
    expect(isAppError({ ...makeAppError(), code: 'NOT_A_REAL_CODE' })).toBe(false);
  });

  it('rejects an envelope missing a required field', () => {
    for (const field of ['code', 'message_key', 'retryable', 'correlation_id'] as const) {
      expect(isAppError(without(makeAppError(), field))).toBe(false);
    }
  });

  it('rejects an envelope whose retryable flag is not a boolean', () => {
    expect(isAppError({ ...makeAppError(), retryable: 'true' })).toBe(false);
  });

  it('rejects an envelope whose safe_details is not a string', () => {
    expect(isAppError({ ...makeAppError(), safe_details: { path: 'x' } })).toBe(false);
  });

  it('rejects values that are not envelopes at all', () => {
    for (const value of [null, undefined, 'INTERNAL', 42, [], new Error('boom')]) {
      expect(isAppError(value)).toBe(false);
    }
  });
});

describe('isFoundationStatus', () => {
  it('accepts a complete status', () => {
    expect(isFoundationStatus(makeFoundationStatus())).toBe(true);
  });

  it('rejects a status with an unknown health discriminant', () => {
    expect(isFoundationStatus({ ...makeFoundationStatus(), status: 'fine' })).toBe(false);
  });

  it('rejects a status missing a version field', () => {
    for (const field of ['app_version', 'backend_version', 'api_contract_version'] as const) {
      expect(isFoundationStatus(without(makeFoundationStatus(), field))).toBe(false);
    }
  });

  it('rejects a status whose versions are not strings', () => {
    expect(isFoundationStatus({ ...makeFoundationStatus(), app_version: 1 })).toBe(false);
  });

  it('rejects values that are not objects', () => {
    for (const value of [null, undefined, 'ok', 0, []]) {
      expect(isFoundationStatus(value)).toBe(false);
    }
  });
});
