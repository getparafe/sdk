/**
 * HTTP fetch wrapper with retry logic for @parafe-trust/sdk
 *
 * Retries on 5xx responses and network errors with exponential backoff.
 * Does NOT retry 4xx responses (client errors).
 */

import { mapBrokerError } from './errors.js';

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  timeout: number;
  retries: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform an HTTP request against the broker with retry logic.
 *
 * On 5xx or network error: retry up to `options.retries` times with
 * exponential backoff (200ms, 400ms, 800ms, ...).
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

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) {
      await sleep(200 * Math.pow(2, attempt - 1));
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
      lastError = err instanceof Error ? err : new Error(String(err));
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

    // 5xx: retry
    if (response.status >= 500) {
      let body: Record<string, unknown> = {};
      try {
        body = (await response.json()) as Record<string, unknown>;
      } catch {
        // ignore JSON parse error
      }
      lastError = mapBrokerError(response.status, body);
      continue;
    }

    // 2xx/3xx: success
    const text = await response.text();
    if (!text) return undefined as unknown as T;

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(`Failed to parse response JSON: ${text.slice(0, 200)}`);
    }
  }

  // All attempts exhausted
  throw lastError ?? new Error('Request failed after retries');
}
