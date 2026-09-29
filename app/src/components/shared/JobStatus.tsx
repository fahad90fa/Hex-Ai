import React, { useState } from "react";
import { CheckCircle2, XCircle, Clock3, Loader2, StopCircle } from "lucide-react";
import type { Job } from "../../api/jobs";
import { useJobStore } from "../../store/jobStore";

interface JobStatusProps {
  job: Job;
  showOutput?: boolean;
}

function formatDuration(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
}

interface OutputModalProps {
  job: Job;
  lines: string[];
  onClose: () => void;
}

const OutputModal: React.FC<OutputModalProps> = ({ job, lines, onClose }) => (
  <div
    className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
    onClick={onClose}
  >
    <div
      className="w-full max-w-3xl max-h-[80vh] rounded-xl border border-[var(--border-2)] bg-[var(--surface)] shadow-xl flex flex-col"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
        <span className="font-semibold text-[var(--text-primary)]">{job.tool_name} output</span>
        <button
          onClick={onClose}
          className="rounded px-2 py-1 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]"
        >
          Close
        </button>
      </div>
      <div className="flex-1 overflow-auto p-4 font-mono text-xs text-[var(--text-secondary)] whitespace-pre-wrap leading-5">
        {lines.length === 0 ? (
          <span className="text-[var(--text-muted)]">No output yet.</span>
        ) : (
          lines.join("\n")
        )}
      </div>
    </div>
  </div>
);

export const JobStatus: React.FC<JobStatusProps> = ({ job }) => {
  const [modalOpen, setModalOpen] = useState(false);
  const lines = useJobStore((s) => s.jobOutputs[job.id] ?? []);

  const iconMap: Record<string, React.ReactNode> = {
    QUEUED:    <Clock3 size={14} className="text-[var(--text-muted)]" />,
    RUNNING:   <Loader2 size={14} className="text-yellow-400 animate-spin" />,
    COMPLETED: <CheckCircle2 size={14} className="text-emerald-400" />,
    FAILED:    <XCircle size={14} className="text-red-400" />,
    KILLED:    <StopCircle size={14} className="text-orange-400" />,
  };

  return (
    <>
      <button
        onClick={() => setModalOpen(true)}
        className="flex w-full items-center gap-2 rounded border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-left text-xs hover:border-[var(--border-2)] transition-colors"
      >
        {iconMap[job.status] ?? null}
        <span className="flex-1 truncate font-medium text-[var(--text-primary)]">
          {job.tool_name}
        </span>
        <span className="text-[var(--text-muted)]">
          {job.ended_at && job.started_at
            ? formatDuration(new Date(job.ended_at).getTime() - new Date(job.started_at).getTime())
            : "—"}
        </span>
        {job.findings_count > 0 && (
          <span className="rounded-full bg-red-900/50 px-1.5 py-0.5 text-xs text-red-400">
            {job.findings_count} findings
          </span>
        )}
      </button>

      {modalOpen && (
        <OutputModal job={job} lines={lines} onClose={() => setModalOpen(false)} />
      )}
    </>
  );
};
