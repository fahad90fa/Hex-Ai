import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type JobStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "KILLED";

export interface Job {
  id: string;
  session_id: string;
  tool_name: string;
  params: Record<string, unknown>;
  status: JobStatus;
  output_path: string | null;
  output_tail: string[] | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string | null;
  findings_count: number;
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
  await client.delete(`/jobs/${id}`);
}

export async function listJobs(sessionId?: string): Promise<Job[]> {
  const params = sessionId ? { session_id: sessionId } : {};
  const { data } = await client.get<Job[]>("/jobs", { params });
  return data;
}
