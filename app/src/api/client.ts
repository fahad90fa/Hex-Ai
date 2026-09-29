import axios, { AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from "axios";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ApiResponse<T = unknown> {
  data: T;
  status: number;
  ok: boolean;
}

export interface ApiError {
  message: string;
  code?: string;
  status: number;
}

// ─── Session ID storage key ───────────────────────────────────────────────────
const SESSION_KEY = "nexus_session_id";

export function getStoredSessionId(): string | null {
  try {
    return localStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

export function setStoredSessionId(id: string): void {
  try {
    localStorage.setItem(SESSION_KEY, id);
  } catch {
    // ignore storage errors in restricted environments
  }
}

export function clearStoredSessionId(): void {
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch {
    // ignore
  }
}

// ─── Axios instance ───────────────────────────────────────────────────────────

const client: AxiosInstance = axios.create({
  baseURL: "http://localhost:8000/api/v1",
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

// Request interceptor — attach session_id header when available
client.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const sessionId = getStoredSessionId();
    if (sessionId) {
      config.headers["X-Session-Id"] = sessionId;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor — normalise errors
client.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => {
    if (error.response) {
      const status: number = error.response.status as number;

      if (status === 401) {
        // Session expired or invalid — clear stored id
        clearStoredSessionId();
        // Dispatch a custom event so the app can react
        window.dispatchEvent(new CustomEvent("nexus:unauthorized"));
      }

      const apiError: ApiError = {
        message:
          (error.response.data as { detail?: string })?.detail ??
          `Request failed with status ${status}`,
        code: String(status),
        status,
      };
      return Promise.reject(apiError);
    }

    if (error.request) {
      const apiError: ApiError = {
        message: "Network error — backend may be offline",
        code: "NETWORK_ERROR",
        status: 0,
      };
      return Promise.reject(apiError);
    }

    return Promise.reject(error);
  }
);

export default client;
