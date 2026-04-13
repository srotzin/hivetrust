import { HiveResponse } from './types';

export interface BaseClientConfig {
  baseUrl: string;
  apiKey?: string;
  did?: string;
  internalKey?: string;
  timeoutMs: number;
}

export class BaseClient {
  protected readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly did?: string;
  private readonly internalKey?: string;
  private readonly timeoutMs: number;

  constructor(config: BaseClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.did = config.did;
    this.internalKey = config.internalKey;
    this.timeoutMs = config.timeoutMs;
  }

  private buildHeaders(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.did) {
      headers['Authorization'] = `Bearer ${this.did}`;
    }
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    if (this.internalKey) {
      headers['X-Hive-Internal-Key'] = this.internalKey;
    }
    if (extra) {
      Object.assign(headers, extra);
    }
    return headers;
  }

  protected async request<T = any>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<HiveResponse<T>> {
    const url = `${this.baseUrl}${path}`;
    const headers = this.buildHeaders(extraHeaders);

    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    };

    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    let lastError: unknown;
    const maxAttempts = 2; // 1 initial + 1 retry on 5xx

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const res = await fetch(url, init);
        const json = await res.json().catch(() => null);

        if (res.ok) {
          if (json && typeof json === 'object' && 'success' in json) {
            return json as HiveResponse<T>;
          }
          return { success: true, data: json as T };
        }

        // Retry only on 5xx
        if (res.status >= 500 && attempt < maxAttempts - 1) {
          lastError = json;
          continue;
        }

        return {
          success: false,
          error:
            (json && typeof json === 'object' && (json as any).error) ||
            `HTTP ${res.status}: ${res.statusText}`,
        };
      } catch (err: any) {
        lastError = err;
        if (attempt < maxAttempts - 1) continue;
      }
    }

    return {
      success: false,
      error: lastError instanceof Error ? lastError.message : String(lastError),
    };
  }

  protected get<T = any>(path: string): Promise<HiveResponse<T>> {
    return this.request<T>('GET', path);
  }

  protected post<T = any>(path: string, body?: unknown): Promise<HiveResponse<T>> {
    return this.request<T>('POST', path, body);
  }

  protected put<T = any>(path: string, body?: unknown): Promise<HiveResponse<T>> {
    return this.request<T>('PUT', path, body);
  }

  protected del<T = any>(path: string, body?: unknown): Promise<HiveResponse<T>> {
    return this.request<T>('DELETE', path, body);
  }
}
