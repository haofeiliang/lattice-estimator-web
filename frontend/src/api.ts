/** Typed fetch helpers, bearer-token storage, error mapping, and JSON downloads. */
let token = sessionStorage.getItem('lattice-estimator-token') ?? '';

export class ApiError extends Error {
  /** HTTP failure with a stable backend error code and status. */
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Convert transport and backend errors to concise Chinese UI messages. */
export function userMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return error instanceof TypeError ? '网络请求失败，请检查服务是否可用' : '发生了未知错误';
  }
  const summary = ({
    400: '请求内容有误',
    401: '身份验证失败，请检查 API 令牌',
    404: '请求的内容不存在',
    409: '操作冲突，请刷新后重试',
    422: '输入参数未通过验证',
    500: '服务内部错误',
    502: '估算服务暂时不可用',
    503: '服务暂时不可用',
    504: '估算请求超时',
  } as Record<number, string>)[error.status] ?? `请求失败（HTTP ${error.status}）`;
  return error.code ? `${summary}（${error.code}）` : summary;
}

/** Update the bearer token for this browser tab. */
export function setToken(value: string) {
  token = value.trim();
  if (token) sessionStorage.setItem('lattice-estimator-token', token);
  else sessionStorage.removeItem('lattice-estimator-token');
}

/** Return the bearer token currently scoped to this browser tab. */
export function getToken() { return token; }

/** JSON body plus response metadata needed for conditional polling. */
export type ApiResponse<T> = {
  status: number;
  data?: T;
  etag?: string;
};

/** Fetch JSON while retaining status and ETag for conditional polling. */
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

/** Fetch only a decoded successful JSON body. */
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  return (await apiResponse<T>(path, init)).data as T;
}

/** Download a JSON-compatible value without sending it back to the server. */
export function download(name: string, value: unknown) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}
