import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type JobStatus = "queued" | "running" | "completed" | "failed" | "killed";

export interface Job {
  id: string;
  session_id: string;
  tool_name: string;
  params: Record<string, unknown>;
  status: JobStatus;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  findings_count: number;
  exit_code: number | null;
  error_message: string | null;
}

export interface CreateJobRequest {
  tool_name: string;
  params: Record<string, unknown>;
  session_id?: string;
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function createJob(req: CreateJobRequest): Promise<Job> {
  const { data } = await client.post<Job>("/jobs", req);
  return data;
}

export async function getJob(id: string): Promise<Job> {
  const { data } = await client.get<Job>(`/jobs/${id}`);
  return data;
}

export async function killJob(id: string): Promise<void> {
  await client.post(`/jobs/${id}/kill`);
}

export async function listJobs(sessionId?: string): Promise<Job[]> {
  const params = sessionId ? { session_id: sessionId } : {};
  const { data } = await client.get<Job[]>("/jobs", { params });
  return data;
}
