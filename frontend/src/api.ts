let token = sessionStorage.getItem('lattice-estimator-token') ?? '';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'Error';
  }
}

export function setToken(value: string) {
  token = value.trim();
  if (token) sessionStorage.setItem('lattice-estimator-token', token);
  else sessionStorage.removeItem('lattice-estimator-token');
}

export function getToken() { return token; }

export type ApiResponse<T> = {
  status: number;
  data?: T;
  etag?: string;
};

export async function apiResponse<T>(path: string, init: RequestInit = {}): Promise<ApiResponse<T>> {
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers });
  const etag = response.headers.get('ETag') ?? undefined;
  if (response.status === 304) return { status: response.status, etag };
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText }));
    throw new ApiError(
      error.path ? `${error.path}: ${error.message}` : error.message,
      response.status,
      error.code,
    );
  }
  if (response.status === 204) return { status: response.status, etag };
  return { status: response.status, data: await response.json(), etag };
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  return (await apiResponse<T>(path, init)).data as T;
}

export function download(name: string, value: unknown) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}
