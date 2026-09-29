import React, { useState, useMemo } from "react";
import { FileText, Download, Loader2, BarChart3, Clock } from "lucide-react";
import { useFindingsStore } from "../../store/findingsStore";
import { useSessionStore } from "../../store/sessionStore";
import client from "../../api/client";
import type { Severity } from "../../api/findings";

type Template = "executive" | "technical" | "bugbounty";

interface ReportRecord {
  id: string;
  template: Template;
  generated_at: string;
  download_url: string;
  html_url?: string;
}

const TEMPLATE_META: Record<Template, { label: string; desc: string }> = {
  executive:  { label: "Executive Summary", desc: "High-level risk overview for stakeholders" },
  technical:  { label: "Technical Report",  desc: "Full vulnerability details with evidence & PoC" },
  bugbounty:  { label: "Bug Bounty Report", desc: "Platform-ready report format (HackerOne/Bugcrowd)" },
};

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-blue-400",
  INFO:     "text-gray-400",
};

export const ReportEngine: React.FC = () => {
  const session = useSessionStore((s) => s.currentSession);
  const findings = useFindingsStore((s) => s.findings);
  const total = findings.length;

  const counts = useMemo<Record<Severity, number>>(() => {
    const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f) => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
    return c;
  }, [findings]);

  const topCvss = useMemo(
    () => [...findings].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 10),
    [findings]
  );

  const [template, setTemplate] = useState<Template>("technical");
  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [history, setHistory] = useState<ReportRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    if (!session) return;
    setGenerating(true);
    setProgress(0);
    setError(null);

    // Simulate progress while waiting
    const tick = setInterval(() => {
      setProgress((p) => Math.min(p + 8, 90));
    }, 400);

    try {
      const { data } = await client.post<ReportRecord>("/reports/generate", {
        session_id: session.id,
        template,
      });
      setProgress(100);
      setHistory((h) => [data, ...h]);
    } catch (e) {
      setError(String(e));
    } finally {
      clearInterval(tick);
      setGenerating(false);
    }
  };

  return (
    <div className="flex h-full flex-col gap-0 overflow-hidden">
      <div className="flex h-full gap-0">
        {/* Left: config + stats */}
        <div className="flex w-72 flex-shrink-0 flex-col border-r border-[var(--border)] overflow-y-auto">
          {/* Template selector */}
          <div className="border-b border-[var(--border)] p-4 space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Template
            </h3>
            {(Object.entries(TEMPLATE_META) as [Template, typeof TEMPLATE_META[Template]][]).map(
              ([key, meta]) => (
                <label
                  key={key}
                  className={`flex cursor-pointer items-start gap-3 rounded border p-3 transition-colors ${
                    template === key
                      ? "border-[var(--accent)]/50 bg-[var(--accent)]/10"
                      : "border-[var(--border)] hover:border-[var(--border-2)]"
                  }`}
                >
                  <input
                    type="radio"
                    name="template"
                    value={key}
                    checked={template === key}
                    onChange={() => setTemplate(key)}
                    className="mt-0.5 accent-[var(--accent)]"
                  />
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-primary)]">
                      {meta.label}
                    </div>
                    <div className="text-xs text-[var(--text-muted)] mt-0.5">{meta.desc}</div>
                  </div>
                </label>
              )
            )}
          </div>

          {/* Stats */}
          <div className="border-b border-[var(--border)] p-4 space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Summary
            </h3>
            <div className="space-y-1">
              {(Object.entries(counts) as [Severity, number][]).map(([sev, n]) => (
                <div key={sev} className="flex items-center justify-between text-xs">
                  <span className={`font-medium ${SEV_COLORS[sev]}`}>{sev}</span>
                  <span className="text-[var(--text-primary)] font-bold">{n}</span>
                </div>
              ))}
              <div className="flex items-center justify-between text-xs border-t border-[var(--border)] pt-1 mt-1">
                <span className="text-[var(--text-secondary)]">Total</span>
                <span className="text-[var(--text-primary)] font-bold">{total}</span>
              </div>
            </div>
          </div>

          {/* Top CVEs */}
          {topCvss.length > 0 && (
            <div className="border-b border-[var(--border)] p-4 space-y-2">
              <h3 className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                <BarChart3 size={11} />
                Top Findings
              </h3>
              {topCvss.slice(0, 5).map((f) => (
                <div key={f.id} className="text-xs">
                  <div className="flex items-center justify-between">
                    <span className="truncate text-[var(--text-primary)] max-w-[160px]" title={f.title}>
                      {f.title}
                    </span>
                    <span
                      className={`flex-shrink-0 font-bold ml-2 ${
                        f.cvss_score >= 9
                          ? "text-red-400"
                          : f.cvss_score >= 7
                          ? "text-orange-400"
                          : "text-yellow-400"
                      }`}
                    >
                      {f.cvss_score.toFixed(1)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Generate button */}
          <div className="p-4 mt-auto">
            {error && (
              <p className="mb-2 rounded bg-red-900/20 border border-red-700/30 px-2 py-1 text-xs text-red-400">
                {error}
              </p>
            )}
            {generating && (
              <div className="mb-2">
                <div className="h-1.5 w-full rounded-full bg-[var(--surface-3)] overflow-hidden">
                  <div
                    className="h-full rounded-full bg-[var(--accent)] transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="mt-1 text-xs text-center text-[var(--text-muted)]">
                  Generating… {progress}%
                </p>
              </div>
            )}
            <button
              onClick={handleGenerate}
              disabled={generating || !session}
              className="flex w-full items-center justify-center gap-2 rounded bg-[var(--accent)] py-2 text-sm font-semibold text-white hover:bg-[var(--accent-2)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {generating ? <Loader2 size={14} className="animate-spin" /> : <FileText size={14} />}
              Generate Report
            </button>
          </div>
        </div>

        {/* Right: preview + history */}
        <div className="flex flex-1 flex-col overflow-hidden">
          {/* Preview pane */}
          <div className="flex-1 overflow-y-auto p-6 bg-[var(--bg)]">
            {history.length === 0 ? (
              <div className="flex h-full flex-col items-center justify-center text-center">
                <FileText size={40} className="text-[var(--text-muted)] mb-3 opacity-40" />
                <p className="text-sm text-[var(--text-muted)]">No reports generated yet.</p>
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Select a template and click Generate Report.
                </p>
              </div>
            ) : (
              <div className="max-w-2xl mx-auto">
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] overflow-hidden">
                  <div className="border-b border-[var(--border)] px-6 py-4">
                    <h2 className="text-lg font-bold text-[var(--text-primary)]">
                      NEXUS Security Assessment Report
                    </h2>
                    <p className="text-sm text-[var(--text-secondary)] mt-1">
                      Target: {session?.target ?? "N/A"} · {TEMPLATE_META[template].label}
                    </p>
                  </div>
                  <div className="p-6 space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      {(Object.entries(counts) as [Severity, number][])
                        .filter(([, n]) => n > 0)
                        .map(([sev, n]) => (
                          <div
                            key={sev}
                            className="rounded border border-[var(--border)] bg-[var(--surface-2)] p-3"
                          >
                            <div className={`text-2xl font-bold ${SEV_COLORS[sev]}`}>{n}</div>
                            <div className="text-xs text-[var(--text-muted)]">{sev}</div>
                          </div>
                        ))}
                    </div>
                    <p className="text-xs text-[var(--text-muted)] italic">
                      Full report content will appear here after generation.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* History */}
          {history.length > 0 && (
            <div className="border-t border-[var(--border)] bg-[var(--surface)] p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                Generated Reports
              </h4>
              <div className="space-y-1">
                {history.map((r) => (
                  <div
                    key={r.id}
                    className="flex items-center gap-3 rounded border border-[var(--border)] bg-[var(--surface-2)] px-3 py-2"
                  >
                    <Clock size={12} className="text-[var(--text-muted)]" />
                    <span className="text-xs text-[var(--text-secondary)] flex-1">
                      {TEMPLATE_META[r.template].label} · {new Date(r.generated_at).toLocaleString()}
                    </span>
                    <a
                      href={r.download_url}
                      download
                      className="flex items-center gap-1 rounded bg-[var(--surface-3)] border border-[var(--border-2)] px-2 py-0.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                    >
                      <Download size={10} />
                      PDF
                    </a>
                    {r.html_url && (
                      <a
                        href={r.html_url}
                        download
                        className="flex items-center gap-1 rounded bg-[var(--surface-3)] border border-[var(--border-2)] px-2 py-0.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                      >
                        <Download size={10} />
                        HTML
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
