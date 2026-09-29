import { useMemo } from "react";
import { useFindingsStore } from "../store/findingsStore";
import type { Finding, Severity } from "../api/findings";

interface FindingsStats {
  total: number;
  bySeverity: Record<Severity, number>;
  avgCvss: number;
  maxCvss: number;
  topFindings: Finding[];
  tools: string[];
  assets: string[];
}

interface UseFindings {
  filtered: Finding[];
  stats: FindingsStats;
}

const SEVERITY_ORDER_HOOK: Record<Severity, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};

export function useFindings(): UseFindings {
  const findings = useFindingsStore((s) => s.findings);
  const filter = useFindingsStore((s) => s.filter);

  const filtered = useMemo<Finding[]>(() =>
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
        SEVERITY_ORDER_HOOK[b.severity] - SEVERITY_ORDER_HOOK[a.severity] || b.cvss_score - a.cvss_score
      ),
    [findings, filter]
  );

  const stats = useMemo<FindingsStats>(() => {
    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
    };
    let cvssSum = 0;
    let maxCvss = 0;
    const toolSet = new Set<string>();
    const assetSet = new Set<string>();

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      cvssSum += f.cvss_score;
      if (f.cvss_score > maxCvss) maxCvss = f.cvss_score;
      toolSet.add(f.tool_name);
      assetSet.add(f.affected_asset);
    }

    const avgCvss = findings.length > 0 ? Math.round((cvssSum / findings.length) * 10) / 10 : 0;

    const topFindings = [...findings]
      .sort((a, b) => b.cvss_score - a.cvss_score)
      .slice(0, 5);

    return {
      total: findings.length,
      bySeverity,
      avgCvss,
      maxCvss,
      topFindings,
      tools: Array.from(toolSet).sort(),
      assets: Array.from(assetSet).sort(),
    };
  }, [findings]);

  return { filtered, stats };
}
