import React from "react";
import { useJobStore } from "../../store/jobStore";

interface StatusBarProps {
  wsConnected: boolean;
  backendReady: boolean;
  currentAiDecision?: string;
  elapsedSeconds?: number;
}

function fmtElapsed(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

const Dot: React.FC<{ on: boolean; label?: string }> = ({ on, label }) => (
  <span className="flex items-center gap-1">
    <span
      className={`inline-block h-2 w-2 rounded-full ${
        on ? "bg-emerald-400 animate-pulse-dot" : "bg-red-500"
      }`}
    />
    {label && <span className="text-[var(--text-muted)]">{label}</span>}
  </span>
);

export const StatusBar: React.FC<StatusBarProps> = ({
  wsConnected,
  backendReady,
  currentAiDecision,
  elapsedSeconds = 0,
}) => {
  const activeCount = useJobStore((s) => s.activeJobs().length);

  return (
    <footer
      className="flex h-[var(--statusbar-height)] items-center gap-4 border-t border-[var(--border)] bg-[var(--surface-2)] px-4 text-xs"
      style={{ flexShrink: 0 }}
    >
      <Dot on={wsConnected} label="WebSocket" />
      <Dot on={backendReady} label="Backend" />

      <span className="h-3 w-px bg-[var(--border)] mx-1" />

      <span className="text-[var(--text-muted)]">
        {activeCount > 0 ? (
          <span className="text-yellow-400">{activeCount} job{activeCount > 1 ? "s" : ""} active</span>
        ) : (
          "Idle"
        )}
      </span>

      {currentAiDecision && (
        <>
          <span className="h-3 w-px bg-[var(--border)] mx-1" />
          <span className="truncate max-w-xs text-[var(--text-muted)] italic">
            AI: {currentAiDecision}
          </span>
        </>
      )}

      <span className="ml-auto text-[var(--text-muted)]">
        {fmtElapsed(elapsedSeconds)}
      </span>
    </footer>
  );
};
