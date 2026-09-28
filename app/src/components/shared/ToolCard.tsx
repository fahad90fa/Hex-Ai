import React, { useState } from "react";
import { Play, ChevronDown, ChevronUp } from "lucide-react";
import type { Tool, ParamSchema } from "../../api/tools";
import type { Job } from "../../api/jobs";

interface ToolCardProps {
  tool: Tool;
  lastJob?: Job | null;
  onRun: (toolName: string, params: Record<string, unknown>) => void;
}

function ParamInput({
  schema,
  value,
  onChange,
}: {
  schema: ParamSchema;
  value: string | number | boolean;
  onChange: (v: string | number | boolean) => void;
}) {
  if (schema.type === "boolean") {
    return (
      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
          className="rounded border-[var(--border-2)] bg-[var(--surface-3)] accent-[var(--accent)]"
        />
        <span className="text-xs text-[var(--text-secondary)]">{schema.name}</span>
      </label>
    );
  }

  if (schema.type === "select" && schema.options) {
    return (
      <select
        value={String(value)}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-2 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
      >
        {schema.options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    );
  }

  if (schema.type === "number") {
    return (
      <input
        type="number"
        value={String(value)}
        placeholder={schema.placeholder}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-2 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
      />
    );
  }

  return (
    <input
      type="text"
      value={String(value)}
      placeholder={schema.placeholder ?? schema.name}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-2 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
    />
  );
}

export const ToolCard: React.FC<ToolCardProps> = ({ tool, lastJob, onRun }) => {
  const [expanded, setExpanded] = useState(false);
  const [params, setParams] = useState<Record<string, unknown>>(() => {
    const init: Record<string, unknown> = {};
    tool.params.forEach((p) => {
      init[p.name] = p.default ?? (p.type === "boolean" ? false : p.type === "number" ? 0 : "");
    });
    return init;
  });

  const handleRun = () => {
    onRun(tool.name, params);
  };

  const statusDot = lastJob
    ? lastJob.status === "running"
      ? "bg-yellow-400 animate-pulse-dot"
      : lastJob.status === "completed"
      ? "bg-emerald-400"
      : "bg-red-400"
    : null;

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2">
        <div className="flex items-center gap-2 min-w-0">
          {statusDot && (
            <span className={`inline-block h-2 w-2 flex-shrink-0 rounded-full ${statusDot}`} />
          )}
          <span className="text-sm font-semibold text-[var(--text-primary)] truncate">
            {tool.name}
          </span>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={handleRun}
            className="flex items-center gap-1 rounded bg-[var(--accent)] px-2 py-1 text-xs font-medium text-white hover:bg-[var(--accent-2)] transition-colors"
          >
            <Play size={10} />
            Run
          </button>
          <button
            onClick={() => setExpanded((e) => !e)}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Description */}
      <p className="px-3 pb-2 text-xs text-[var(--text-muted)] line-clamp-2">
        {tool.description}
      </p>

      {/* Expanded params */}
      {expanded && (
        <div className="border-t border-[var(--border)] px-3 py-2 space-y-2">
          {tool.params.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">No parameters required.</p>
          ) : (
            tool.params.map((p) => (
              <div key={p.name}>
                <label className="mb-0.5 block text-xs font-medium text-[var(--text-secondary)]">
                  {p.name}
                  {p.required && <span className="ml-1 text-red-400">*</span>}
                </label>
                {p.description && (
                  <p className="mb-1 text-xs text-[var(--text-muted)]">{p.description}</p>
                )}
                <ParamInput
                  schema={p}
                  value={params[p.name] as string | number | boolean}
                  onChange={(v) => setParams((prev) => ({ ...prev, [p.name]: v }))}
                />
              </div>
            ))
          )}
          <button
            onClick={handleRun}
            className="mt-1 w-full rounded bg-[var(--accent)] py-1.5 text-xs font-semibold text-white hover:bg-[var(--accent-2)] transition-colors"
          >
            Run {tool.name}
          </button>
        </div>
      )}
    </div>
  );
};
