import { create } from "zustand";
import type { Finding, Severity } from "../api/findings";

// ─── Filter shape ─────────────────────────────────────────────────────────────

export interface FindingsFilter {
  severity: Severity | null;
  tool: string | null;
  asset: string | null;
  search: string;
}

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

function matchesFilter(f: Finding, filter: FindingsFilter): boolean {
  if (filter.severity && f.severity !== filter.severity) return false;
  if (filter.tool && f.tool_name !== filter.tool) return false;
  if (filter.asset && !f.affected_asset.includes(filter.asset)) return false;
  if (
    filter.search &&
    !f.title.toLowerCase().includes(filter.search.toLowerCase()) &&
    !f.description.toLowerCase().includes(filter.search.toLowerCase())
  )
    return false;
  return true;
}

// ─── State shape ──────────────────────────────────────────────────────────────

interface FindingsState {
  findings: Finding[];
  filter: FindingsFilter;
}

interface FindingsActions {
  addFinding: (f: Finding) => void;
  updateFinding: (id: string, partial: Partial<Finding>) => void;
  deleteFinding: (id: string) => void;
  setFindings: (findings: Finding[]) => void;
  setFilter: (partial: Partial<FindingsFilter>) => void;
  resetFilter: () => void;
}

interface FindingsSelectors {
  filteredFindings: () => Finding[];
  countsBySeverity: () => Record<Severity, number>;
  topCvss: () => Finding[];
}

type FindingsStore = FindingsState & FindingsActions & FindingsSelectors;

const DEFAULT_FILTER: FindingsFilter = {
  severity: null,
  tool: null,
  asset: null,
  search: "",
};

// ─── Store ────────────────────────────────────────────────────────────────────

export const useFindingsStore = create<FindingsStore>((set, get) => ({
  // ── State ──
  findings: [],
  filter: { ...DEFAULT_FILTER },

  // ── Actions ──

  addFinding(f) {
    set((s) => ({ findings: [...s.findings, f] }));
  },

  updateFinding(id, partial) {
    set((s) => ({
      findings: s.findings.map((f) => (f.id === id ? { ...f, ...partial } : f)),
    }));
  },

  deleteFinding(id) {
    set((s) => ({ findings: s.findings.filter((f) => f.id !== id) }));
  },

  setFindings(findings) {
    set({ findings });
  },

  setFilter(partial) {
    set((s) => ({ filter: { ...s.filter, ...partial } }));
  },

  resetFilter() {
    set({ filter: { ...DEFAULT_FILTER } });
  },

  // ── Selectors ──

  filteredFindings() {
    const { findings, filter } = get();
    return findings
      .filter((f) => matchesFilter(f, filter))
      .sort(
        (a, b) =>
          SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
          b.cvss_score - a.cvss_score
      );
  },

  countsBySeverity() {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    get().findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    });
    return counts;
  },

  topCvss() {
    return [...get().findings].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 10);
  },
}));
