import client from "./client";

// ─── Types ────────────────────────────────────────────────────────────────────

export type ToolCategory =
  | "RECON"
  | "SCAN"
  | "WEB"
  | "AUTH"
  | "EXPLOIT"
  | "REVERSING"
  | "NETWORK";

export interface ParamSchema {
  name: string;
  type: "string" | "number" | "boolean" | "select";
  required: boolean;
  default?: string | number | boolean;
  options?: string[];            // for type=select
  placeholder?: string;
  description?: string;
}

export interface Tool {
  name: string;
  description: string;
  category: ToolCategory;
  params: ParamSchema[];
  tags: string[];
}

export interface ToolsByCategory {
  [category: string]: Tool[];
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function getTools(): Promise<Tool[]> {
  const { data } = await client.get<Tool[]>("/tools");
  return data;
}

export async function getToolsByCategory(): Promise<ToolsByCategory> {
  const tools = await getTools();
  return tools.reduce<ToolsByCategory>((acc, tool) => {
    const cat = tool.category;
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(tool);
    return acc;
  }, {});
}

export async function getTool(name: string): Promise<Tool> {
  const { data } = await client.get<Tool>(`/tools/${name}`);
  return data;
}
