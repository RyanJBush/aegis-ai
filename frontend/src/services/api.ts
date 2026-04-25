const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1';
const ACCESS_TOKEN_KEY = 'aegis_access_token';

type HttpMethod = 'GET' | 'POST' | 'PATCH';

export function setAuthToken(token: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
}

export function getAuthToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function hasAuthToken(): boolean {
  return Boolean(getAuthToken());
}

export async function getJson<T>(path: string): Promise<T> {
  return requestJson<T>('GET', path);
}

export async function postJson<TResponse, TBody = unknown>(path: string, body: TBody): Promise<TResponse> {
  return requestJson<TResponse>('POST', path, body);
}

export async function patchJson<TResponse, TBody = unknown>(path: string, body: TBody): Promise<TResponse> {
  return requestJson<TResponse>('PATCH', path, body);
}

async function requestJson<T>(method: HttpMethod, path: string, body?: unknown): Promise<T> {
  const token = getAuthToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }
  if (response.status === 204) {
    return {} as T;
  }
  return (await response.json()) as T;
}
