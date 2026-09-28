import React, { useState } from "react";
import { Crosshair, Play, Clock, Activity, Shield, Tag } from "lucide-react";
import { useSessionStore } from "../../store/sessionStore";
import { useFindingsStore } from "../../store/findingsStore";
import { useJobStore } from "../../store/jobStore";
import type { Severity } from "../../api/findings";

const SEV_TILE_STYLES: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-red-900/20",    text: "text-red-400",    border: "border-red-700/30"    },
  HIGH:     { bg: "bg-orange-900/20", text: "text-orange-400", border: "border-orange-700/30" },
  MEDIUM:   { bg: "bg-yellow-900/20", text: "text-yellow-400", border: "border-yellow-700/30" },
  LOW:      { bg: "bg-blue-900/20",   text: "text-blue-400",   border: "border-blue-700/30"   },
  INFO:     { bg: "bg-gray-800/20",   text: "text-gray-400",   border: "border-gray-700/30"   },
};

function useElapsed(createdAt: string | undefined): string {
  const [now, setNow] = React.useState(Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!createdAt) return "—";
  const diff = Math.floor((now - new Date(createdAt).getTime()) / 1000);
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ─── Mock asset data (replaced by real data from backend in production) ───────
interface Asset {
  hostname: string;
  ip: string;
  ports: number[];
  services: string[];
  tech: string[];
}

export const TargetDashboard: React.FC = () => {
  const { currentSession, createSession, isConnecting } = useSessionStore();
  const counts = useFindingsStore((s) => s.countsBySeverity());
  const allFindings = useFindingsStore((s) => s.findings);
  const jobsRun = useJobStore((s) => s.jobs.length);
  const elapsed = useElapsed(currentSession?.created_at);

  const [targetInput, setTargetInput] = useState("");

  const handleStart = () => {
    const t = targetInput.trim();
    if (!t) return;
    createSession(t).catch(() => {});
  };

  // Derive a simple asset list from findings
  const assets = React.useMemo<Asset[]>(() => {
    const map = new Map<string, Asset>();
    allFindings.forEach((f) => {
      const host = f.affected_asset;
      if (!map.has(host)) {
        map.set(host, { hostname: host, ip: "", ports: [], services: [], tech: [] });
      }
      const a = map.get(host)!;
      if (f.tool_name && !a.services.includes(f.tool_name)) {
        a.services.push(f.tool_name);
      }
    });
    return Array.from(map.values()).slice(0, 50);
  }, [allFindings]);

  const SHOWN_SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      {/* Target input */}
      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
          <Crosshair size={16} className="text-[var(--accent)]" />
          New Session
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleStart()}
            placeholder="Target: domain, IP, or CIDR (e.g. example.com or 10.0.0.0/24)"
            className="flex-1 rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none"
          />
          <button
            onClick={handleStart}
            disabled={isConnecting || !targetInput.trim()}
            className="flex items-center gap-2 rounded bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-white hover:bg-[var(--accent-2)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <Play size={14} />
            {isConnecting ? "Connecting…" : "Start"}
          </button>
        </div>
      </div>

      {/* Active session info */}
      {currentSession && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-700/30 bg-emerald-900/10 px-4 py-3">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse-dot flex-shrink-0" />
          <span className="text-sm font-medium text-emerald-300">
            Active: <span className="font-bold">{currentSession.target}</span>
          </span>
          <span className="ml-auto flex items-center gap-1 text-xs text-emerald-600">
            <Clock size={11} />
            {elapsed}
          </span>
        </div>
      )}

      {/* Severity tiles */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {SHOWN_SEVERITIES.map((sev) => {
          const { bg, text, border } = SEV_TILE_STYLES[sev];
          return (
            <div
              key={sev}
              className={`rounded-xl border ${border} ${bg} p-4`}
            >
              <div className={`text-3xl font-black ${text}`}>{counts[sev]}</div>
              <div className={`text-xs font-semibold mt-1 ${text}`}>{sev}</div>
            </div>
          );
        })}
      </div>

      {/* Session stats */}
      {currentSession && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { icon: Activity, label: "Tools Run",       val: jobsRun },
            { icon: Shield,   label: "Findings",         val: allFindings.length },
            { icon: Tag,      label: "Coverage %",       val: `${currentSession.coverage_pct ?? 0}%` },
          ].map(({ icon: Icon, label, val }) => (
            <div
              key={label}
              className="flex items-center gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4"
            >
              <Icon size={20} className="text-[var(--accent)] flex-shrink-0" />
              <div>
                <div className="text-xl font-bold text-[var(--text-primary)]">{val}</div>
                <div className="text-xs text-[var(--text-muted)]">{label}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Asset inventory */}
      {assets.length > 0 && (
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] overflow-hidden">
          <div className="border-b border-[var(--border)] px-4 py-3">
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">Asset Inventory</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--border)] text-left">
                  {["Hostname / Asset", "Services", "Tech"].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-2 text-[var(--text-muted)] font-semibold uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {assets.map((asset, i) => (
                  <tr
                    key={i}
                    className="border-b border-[var(--border)]/50 hover:bg-[var(--surface-2)] transition-colors"
                  >
                    <td className="px-4 py-2 font-mono text-[var(--text-primary)]">
                      {asset.hostname}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex flex-wrap gap-1">
                        {asset.services.slice(0, 5).map((s) => (
                          <span
                            key={s}
                            className="rounded bg-[var(--surface-3)] px-1.5 py-0.5 text-[var(--text-secondary)]"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex flex-wrap gap-1">
                        {asset.tech.slice(0, 4).map((t) => (
                          <span
                            key={t}
                            className="rounded bg-[var(--accent)]/10 border border-[var(--accent)]/20 px-1.5 py-0.5 text-[var(--accent-fg)]"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
