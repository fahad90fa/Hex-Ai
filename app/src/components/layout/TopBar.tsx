import React from "react";
import { Target, XCircle, Loader2 } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { useJobStore } from "../../store/jobStore";
import { useFindingsStore } from "../../store/findingsStore";
import type { SessionStatus } from "../../api/sessions";

type UiPhase = "RECON" | "SCAN" | "EXPLOIT" | "REPORT";

const PHASES: UiPhase[] = ["RECON", "SCAN", "EXPLOIT", "REPORT"];

const PHASE_COLORS: Record<UiPhase, string> = {
  RECON:   "text-blue-400 border-blue-400/50 bg-blue-900/20",
  SCAN:    "text-yellow-400 border-yellow-400/50 bg-yellow-900/20",
  EXPLOIT: "text-red-400 border-red-400/50 bg-red-900/20",
  REPORT:  "text-emerald-400 border-emerald-400/50 bg-emerald-900/20",
};

function statusToPhase(s: SessionStatus | undefined): UiPhase {
  if (!s || s === "PENDING") return "RECON";
  if (s === "RUNNING") return "SCAN";
  if (s === "COMPLETED") return "REPORT";
  return "SCAN";
}

export const TopBar: React.FC = () => {
  const session = useSessionStore((s) => s.currentSession);
  const clearSession = useSessionStore((s) => s.clearSession);
  const activeCount = useJobStore((s) => s.activeJobs().length);
  const findingsCount = useFindingsStore((s) => s.findings.length);
  const criticalCount = useFindingsStore((s) => s.countsBySeverity().CRITICAL);

  const currentPhase: UiPhase = statusToPhase(session?.status);
  const phaseIndex = PHASES.indexOf(currentPhase);

  return (
    <header
      className="flex h-[var(--topbar-height)] items-center gap-4 border-b border-[var(--border)] bg-[var(--surface)] px-4"
      style={{ flexShrink: 0 }}
    >
      {/* Logo + target */}
      <div className="flex items-center gap-2 min-w-0">
        <Target size={18} className="text-[var(--accent)] flex-shrink-0" />
        <span className="text-base font-bold tracking-widest text-[var(--accent-fg)]">NEXUS</span>
        {session && (
          <>
            <span className="text-[var(--text-muted)] mx-1">/</span>
            <span className="truncate text-sm text-[var(--text-secondary)] max-w-[200px]">
              {session.target}
            </span>
          </>
        )}
      </div>

      {/* Phase indicator */}
      {session && (
        <div className="flex items-center gap-1 flex-1 justify-center">
          {PHASES.map((phase, i) => {
            const isActive = i === phaseIndex;
            const isDone = i < phaseIndex;
            return (
              <React.Fragment key={phase}>
                <div
                  className={`
                    flex items-center gap-1 rounded-full border px-3 py-0.5 text-xs font-semibold transition-all
                    ${isActive
                      ? PHASE_COLORS[phase]
                      : isDone
                      ? "border-[var(--border-2)] text-[var(--text-muted)] bg-[var(--surface-3)]"
                      : "border-transparent text-[var(--text-muted)]"
                    }
                  `}
                >
                  {isActive && <Loader2 size={10} className="animate-spin" />}
                  {isDone && <span className="text-[9px]">✓</span>}
                  {phase}
                </div>
                {i < PHASES.length - 1 && (
                  <span
                    className={`h-px w-6 flex-shrink-0 ${
                      isDone ? "bg-[var(--border-2)]" : "bg-[var(--border)]"
                    }`}
                  />
                )}
              </React.Fragment>
            );
          })}
        </div>
      )}

      {/* Right badges */}
      <div className="flex items-center gap-3 flex-shrink-0 ml-auto">
        {activeCount > 0 && (
          <span className="inline-flex items-center gap-1 rounded-full bg-yellow-900/30 border border-yellow-700/30 px-2 py-0.5 text-xs text-yellow-400">
            <Loader2 size={10} className="animate-spin" />
            {activeCount} running
          </span>
        )}

        {findingsCount > 0 && (
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold ${
              criticalCount > 0
                ? "bg-red-900/30 border-red-700/30 text-red-400"
                : "bg-[var(--surface-3)] border-[var(--border-2)] text-[var(--text-secondary)]"
            }`}
          >
            {findingsCount} findings
          </span>
        )}

        {session && (
          <button
            onClick={() => clearSession()}
            className="flex items-center gap-1 rounded border border-red-700/30 bg-red-900/20 px-2 py-1 text-xs text-red-400 hover:bg-red-900/40 transition-colors"
          >
            <XCircle size={12} />
            Stop
          </button>
        )}
      </div>
    </header>
  );
};
