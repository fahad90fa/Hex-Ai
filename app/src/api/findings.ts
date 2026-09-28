import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  id: string;
  session_id: string;
  job_id?: string;
  tool_name: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number;
  cve_ids: string[];
  affected_asset: string;
  evidence: string;
  poc: string;
  remediation: string;
  created_at: string;
  updated_at: string;
}

export interface CreateFindingRequest {
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number;
  cve_ids?: string[];
  affected_asset: string;
  evidence?: string;
  poc?: string;
  remediation?: string;
  tool_name?: string;
  job_id?: string;
}

export interface UpdateFindingRequest extends Partial<CreateFindingRequest> {}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function getFindings(sessionId?: string): Promise<Finding[]> {
  const params = sessionId ? { session_id: sessionId } : {};
  const { data } = await client.get<Finding[]>("/findings", { params });
  return data;
}

export async function createFinding(req: CreateFindingRequest): Promise<Finding> {
  const { data } = await client.post<Finding>("/findings", req);
  return data;
}

export async function updateFinding(
  id: string,
  req: UpdateFindingRequest
): Promise<Finding> {
  const { data } = await client.patch<Finding>(`/findings/${id}`, req);
  return data;
}

export async function deleteFinding(id: string): Promise<void> {
  await client.delete(`/findings/${id}`);
}
