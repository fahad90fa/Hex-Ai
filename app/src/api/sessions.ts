import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type SessionPhase = "RECON" | "SCAN" | "EXPLOIT" | "REPORT";

export interface Session {
  id: string;
  target: string;
  phase: SessionPhase;
  created_at: string;
  updated_at: string;
  findings_count: number;
  jobs_run: number;
  coverage_pct: number;
}

export interface CreateSessionRequest {
  target: string;
  notes?: string;
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

export async function updateSessionPhase(
  id: string,
  phase: SessionPhase
): Promise<Session> {
  const { data } = await client.patch<Session>(`/sessions/${id}/phase`, { phase });
  return data;
}
