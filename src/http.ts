/**
 * HTTP fetch wrapper with retry logic for @getparafe/sdk
 *
 * Retries on 502/503/504 responses and network errors with exponential backoff.
 * Does NOT retry 4xx or 500 responses.
 */

import { mapBrokerError, InternalError, NetworkError } from './errors.js';

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  timeout: number;
  retries: number;
  /**
   * Headers to sign again before each retry: a `Parafe-PoP` proof is single use, so a
   * retry of a request that reached the broker would be refused as replayed (P-49).
   */
  refreshHeaders?: () => Promise<Record<string, string>>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform an HTTP request against the broker with retry logic.
 *
 * On 502/503/504 or network error: retry up to `options.retries` times with
 * exponential backoff (200ms, 400ms, 800ms, ...), with fresh `refreshHeaders()`.
 * A proof-carrying request that changes state is retried only on 502/503 or a
 * connection that never opened (see `retryOnlyIfUnsent`).
 * On 500: throw immediately (server bug, unlikely to self-resolve).
 *
 * On 4xx: throw immediately with the appropriate typed error.
 */
export async function request<T>(
  url: string,
  options: RequestOptions
): Promise<T> {
  const method = options.method ?? 'POST';
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  const maxAttempts = options.retries + 1;
  let lastError: Error | undefined;
  // A request that changes state (not GET) and carries a single-use proof is retried only
  // when the broker can't have processed it: a 502/503 from the edge, or a connection that
  // never opened. After a timeout, a dropped connection or a 504 it may have run; retrying
  // would run it twice (a second handshake, a mandate refused as already redeemed).
  const retryOnlyIfUnsent = method !== 'GET' && options.refreshHeaders !== undefined;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) {
      await sleep(200 * Math.pow(2, attempt - 1));
      if (options.refreshHeaders) Object.assign(headers, await options.refreshHeaders());
    }

    let response: Response;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), options.timeout);

      try {
        response = await fetch(url, {
          method,
          headers,
          body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (err: unknown) {
      // Network error or timeout — retry
      const msg = err instanceof Error ? err.message : String(err);
      lastError = new NetworkError(msg);
      const code = (err as { cause?: { code?: string } } | null)?.cause?.code;
      const neverSent = code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EAI_AGAIN';
      if (retryOnlyIfUnsent && !neverSent) throw lastError;
      continue;
    }

    // 4xx: parse error body and throw typed error immediately (no retry)
    if (response.status >= 400 && response.status < 500) {
      let body: Record<string, unknown> = {};
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        // ignore JSON parse error
      }
      throw mapBrokerError(response.status, body);
    }

    // 502/503/504: transient gateway errors — retry
    if (response.status >= 502 && response.status <= 504) {
      let body: Record<string, unknown> = {};
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        // ignore JSON parse error
      }
      lastError = mapBrokerError(response.status, body);
      if (retryOnlyIfUnsent && response.status === 504) throw lastError;
      continue;
    }

    // 500 or other 5xx: server bug, unlikely to self-resolve — throw immediately
    if (response.status >= 500) {
      let body: Record<string, unknown> = {};
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        // ignore JSON parse error
      }
      throw mapBrokerError(response.status, body);
    }

    // 2xx/3xx: success
    const text = await response.text();
    if (!text) throw new InternalError('Empty response body from broker');

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(`Failed to parse response JSON: ${text.slice(0, 200)}`);
    }
  }

  // All attempts exhausted
  throw lastError ?? new NetworkError('Request failed after retries');
}
