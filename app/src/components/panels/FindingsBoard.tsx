import React, { useState, useMemo } from "react";
import { Search, Filter, ExternalLink, ChevronDown, ChevronUp, Bug } from "lucide-react";
import { useFindingsStore } from "../../store/findingsStore";
import { SeverityBadge } from "../shared/SeverityBadge";
import { CvssScore } from "../shared/CvssScore";
import type { Finding, Severity } from "../../api/findings";

const COLUMNS: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const COL_STYLES: Record<Severity, { header: string; count: string }> = {
  CRITICAL: { header: "border-red-700/40 bg-red-900/10",    count: "bg-red-900/40 text-red-300" },
  HIGH:     { header: "border-orange-700/40 bg-orange-900/10", count: "bg-orange-900/40 text-orange-300" },
  MEDIUM:   { header: "border-yellow-700/40 bg-yellow-900/10", count: "bg-yellow-900/40 text-yellow-300" },
  LOW:      { header: "border-blue-700/40 bg-blue-900/10",   count: "bg-blue-900/40 text-blue-300" },
  INFO:     { header: "border-gray-700/40 bg-gray-800/10",   count: "bg-gray-800/40 text-gray-400" },
};

// ─── Finding card ─────────────────────────────────────────────────────────────

interface FindingCardProps {
  finding: Finding;
  onClick: () => void;
}

const FindingCard: React.FC<FindingCardProps> = ({ finding, onClick }) => (
  <button
    onClick={onClick}
    className="w-full rounded border border-[var(--border)] bg-[var(--surface)] p-3 text-left hover:border-[var(--border-2)] hover:bg-[var(--surface-2)] transition-colors space-y-2"
  >
    <div className="flex items-start justify-between gap-2">
      <span className="text-xs font-semibold text-[var(--text-primary)] line-clamp-2 flex-1">
        {finding.title}
      </span>
      <CvssScore score={finding.cvss_score} size="sm" />
    </div>
    <div className="flex items-center gap-1 flex-wrap">
      <SeverityBadge severity={finding.severity} compact />
      <span className="rounded bg-[var(--surface-3)] px-1.5 py-0.5 text-xs text-[var(--text-muted)]">
        {finding.tool_name}
      </span>
    </div>
    <p
      className="text-xs text-[var(--text-muted)] truncate"
      title={finding.affected_asset}
    >
      {finding.affected_asset}
    </p>
    <p className="text-[10px] text-[var(--text-muted)]">
      {new Date(finding.created_at).toLocaleString()}
    </p>
  </button>
);

// ─── Finding drawer ───────────────────────────────────────────────────────────

interface FindingDrawerProps {
  finding: Finding;
  onClose: () => void;
}

const FindingDrawer: React.FC<FindingDrawerProps> = ({ finding, onClose }) => {
  const [remOpen, setRemOpen] = useState(false);

  return (
    <div className="flex h-full flex-col border-l border-[var(--border)] bg-[var(--surface)] w-80 flex-shrink-0">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
        <SeverityBadge severity={finding.severity} />
        <button
          onClick={onClose}
          className="text-[var(--text-muted)] hover:text-[var(--text-primary)] text-sm"
        >
          ✕
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Title */}
        <h3 className="font-semibold text-[var(--text-primary)] text-sm leading-snug">
          {finding.title}
        </h3>

        {/* CVSS */}
        <div className="flex items-center gap-3">
          <CvssScore score={finding.cvss_score} size="md" />
          <div className="text-xs text-[var(--text-secondary)]">
            <div>CVSS {finding.cvss_score.toFixed(1)}</div>
            <div className="text-[var(--text-muted)]">{finding.affected_asset}</div>
          </div>
        </div>

        {/* Description */}
        <div>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Description
          </h4>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* CVE IDs */}
        {finding.cve_ids.length > 0 && (
          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              CVEs
            </h4>
            <div className="flex flex-wrap gap-1">
              {finding.cve_ids.map((cve) => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded bg-blue-900/20 border border-blue-700/30 px-2 py-0.5 text-xs text-blue-400 hover:text-blue-300"
                >
                  {cve} <ExternalLink size={9} />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Evidence */}
        {finding.evidence && (
          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Evidence
            </h4>
            <pre className="overflow-x-auto rounded border border-[var(--border)] bg-[var(--bg)] p-2 text-xs text-[var(--text-secondary)] whitespace-pre-wrap">
              {finding.evidence}
            </pre>
          </div>
        )}

        {/* PoC */}
        {finding.poc && (
          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Proof of Concept
            </h4>
            <pre className="overflow-x-auto rounded border border-[var(--border)] bg-[var(--bg)] p-2 text-xs text-emerald-400 whitespace-pre-wrap font-mono">
              {finding.poc}
            </pre>
          </div>
        )}

        {/* Remediation (collapsible) */}
        {finding.remediation && (
          <div>
            <button
              onClick={() => setRemOpen((o) => !o)}
              className="flex w-full items-center justify-between text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            >
              Remediation
              {remOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
            {remOpen && (
              <p className="mt-2 text-xs text-[var(--text-secondary)] leading-relaxed">
                {finding.remediation}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-[var(--border)] p-3">
        <button className="w-full rounded bg-[var(--accent)] py-1.5 text-xs font-semibold text-white hover:bg-[var(--accent-2)] transition-colors">
          Export this Finding
        </button>
      </div>
    </div>
  );
};

// ─── Column ───────────────────────────────────────────────────────────────────

interface ColumnProps {
  severity: Severity;
  findings: Finding[];
  onSelect: (f: Finding) => void;
}

const Column: React.FC<ColumnProps> = ({ severity, findings, onSelect }) => {
  const { header, count } = COL_STYLES[severity];

  return (
    <div className="flex w-52 flex-shrink-0 flex-col rounded-lg border border-[var(--border)] overflow-hidden">
      <div className={`flex items-center justify-between border-b border-[var(--border)] px-3 py-2 ${header}`}>
        <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          {severity}
        </span>
        <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${count}`}>
          {findings.length}
        </span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-2 p-2">
        {findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Bug size={20} className="text-[var(--text-muted)] mb-2 opacity-50" />
            <p className="text-xs text-[var(--text-muted)]">No {severity.toLowerCase()} findings</p>
          </div>
        ) : (
          findings.map((f) => (
            <FindingCard key={f.id} finding={f} onClick={() => onSelect(f)} />
          ))
        )}
      </div>
    </div>
  );
};

// ─── Main panel ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};

export const FindingsBoard: React.FC = () => {
  const findings = useFindingsStore((s) => s.findings);
  const filter = useFindingsStore((s) => s.filter);
  const setFilter = useFindingsStore((s) => s.setFilter);

  // Stable derived array — never created inside a Zustand selector
  const filteredFindings = useMemo(() =>
    findings
      .filter((f) => {
        if (filter.severity && f.severity !== filter.severity) return false;
        if (filter.tool && f.tool_name !== filter.tool) return false;
        if (filter.asset && !f.affected_asset.includes(filter.asset)) return false;
        if (filter.search) {
          const q = filter.search.toLowerCase();
          if (!f.title.toLowerCase().includes(q) && !f.description.toLowerCase().includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.cvss_score - a.cvss_score
      ),
    [findings, filter]
  );

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const byColumn = COLUMNS.reduce<Record<Severity, Finding[]>>(
    (acc, sev) => {
      acc[sev] = filteredFindings.filter((f) => f.severity === sev);
      return acc;
    },
    { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] }
  );

  // Unique tools for filter dropdown
  const tools = Array.from(new Set(findings.map((f) => f.tool_name))).sort();

  return (
    <div className="flex h-full flex-col">
      {/* Top bar */}
      <div className="flex items-center gap-3 border-b border-[var(--border)] bg-[var(--surface)] px-4 py-2 flex-shrink-0">
        {/* Search */}
        <div className="relative flex-1 max-w-xs">
          <Search
            size={13}
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)] pointer-events-none"
          />
          <input
            type="text"
            value={filter.search}
            onChange={(e) => setFilter({ search: e.target.value })}
            placeholder="Search findings..."
            className="w-full rounded border border-[var(--border-2)] bg-[var(--surface-3)] pl-7 pr-3 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
          />
        </div>

        {/* Tool filter */}
        <div className="flex items-center gap-1.5">
          <Filter size={12} className="text-[var(--text-muted)]" />
          <select
            value={filter.tool ?? ""}
            onChange={(e) => setFilter({ tool: e.target.value || null })}
            className="rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-2 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
          >
            <option value="">All tools</option>
            {tools.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {/* Stats */}
        <div className="ml-auto text-xs text-[var(--text-muted)]">
          {filteredFindings.length} / {findings.length} findings
        </div>
      </div>

      {/* Kanban board */}
      <div className="flex flex-1 gap-3 overflow-x-auto p-4">
        {COLUMNS.map((sev) => (
          <Column
            key={sev}
            severity={sev}
            findings={byColumn[sev]}
            onSelect={setSelectedFinding}
          />
        ))}
      </div>

      {/* Detail drawer */}
      {selectedFinding && (
        <div className="absolute inset-y-0 right-0 z-30">
          <FindingDrawer
            finding={selectedFinding}
            onClose={() => setSelectedFinding(null)}
          />
        </div>
      )}
    </div>
  );
};
