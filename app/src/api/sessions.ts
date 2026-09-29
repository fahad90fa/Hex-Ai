import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type SessionStatus =
  | "PENDING"
  | "RUNNING"
  | "PAUSED"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export interface Session {
  id: string;
  target: string;
  status: SessionStatus;
  started_at: string | null;
  ended_at: string | null;
  created_at: string | null;
  config: Record<string, unknown>;
  findings_count: number;
  jobs_count: number;
  coverage_pct: number | null;
}

export interface CreateSessionRequest {
  target: string;
  config?: Record<string, unknown>;
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function createSession(req: CreateSessionRequest): Promise<Session> {
  const { data } = await client.post<Session>("/sessions", req);
  return data;
}

export async function getSession(id: string): Promise<Session> {
  const { data } = await client.get<Session>(`/sessions/${id}`);
  return data;
}

export async function deleteSession(id: string): Promise<void> {
  await client.delete(`/sessions/${id}`);
}

export async function listSessions(): Promise<Session[]> {
  const { data } = await client.get<Session[]>("/sessions");
  return data;
}
