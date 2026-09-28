import React, { useState, useEffect, useMemo } from "react";
import { Search, ChevronRight, ChevronLeft } from "lucide-react";
import { getToolsByCategory } from "../../api/tools";
import type { Tool, ToolCategory } from "../../api/tools";
import { createJob } from "../../api/jobs";
import { useJobStore } from "../../store/jobStore";
import { useSessionStore } from "../../store/sessionStore";
import { ToolCard } from "../shared/ToolCard";
import { JobStatus } from "../shared/JobStatus";

const CATEGORIES: ToolCategory[] = ["RECON", "SCAN", "WEB", "AUTH", "EXPLOIT", "REVERSING", "NETWORK"];

const CAT_COLORS: Record<ToolCategory, string> = {
  RECON:     "text-blue-400 border-blue-700/30",
  SCAN:      "text-yellow-400 border-yellow-700/30",
  WEB:       "text-emerald-400 border-emerald-700/30",
  AUTH:      "text-orange-400 border-orange-700/30",
  EXPLOIT:   "text-red-400 border-red-700/30",
  REVERSING: "text-purple-400 border-purple-700/30",
  NETWORK:   "text-cyan-400 border-cyan-700/30",
};

export const ModuleRunner: React.FC = () => {
  const [activeCategory, setActiveCategory] = useState<ToolCategory>("RECON");
  const [allTools, setAllTools] = useState<Record<string, Tool[]>>({});
  const [loading, setLoading] = useState(true);
  const [quickSearch, setQuickSearch] = useState("");
  const [queueVisible, setQueueVisible] = useState(true);

  const session = useSessionStore((s) => s.currentSession);
  const addJob = useJobStore((s) => s.addJob);
  const jobs = useJobStore((s) => s.jobs);

  useEffect(() => {
    getToolsByCategory()
      .then((data) => setAllTools(data))
      .catch(() => setAllTools({}))
      .finally(() => setLoading(false));
  }, []);

  const handleRun = async (toolName: string, params: Record<string, unknown>) => {
    try {
      const job = await createJob({
        tool_name: toolName,
        params,
        session_id: session?.id,
      });
      addJob(job);
    } catch (e) {
      console.error("Failed to run tool:", e);
    }
  };

  const currentTools = allTools[activeCategory] ?? [];

  // Quick search across all tools
  const quickResults = useMemo(() => {
    if (!quickSearch) return [];
    const q = quickSearch.toLowerCase();
    return Object.values(allTools)
      .flat()
      .filter((t) => t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q))
      .slice(0, 12);
  }, [quickSearch, allTools]);

  const recentJobs = jobs.slice(0, 20);

  return (
    <div className="flex h-full">
      {/* Main area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Category tabs */}
        <div className="flex items-center gap-1 border-b border-[var(--border)] bg-[var(--surface)] px-3 py-2 overflow-x-auto flex-shrink-0">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => {
                setActiveCategory(cat);
                setQuickSearch("");
              }}
              className={`rounded-md border px-3 py-1 text-xs font-semibold flex-shrink-0 transition-colors ${
                activeCategory === cat && !quickSearch
                  ? `bg-[var(--surface-3)] ${CAT_COLORS[cat]}`
                  : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {cat}
            </button>
          ))}

          {/* Quick search */}
          <div className="relative ml-auto flex-shrink-0">
            <Search
              size={12}
              className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--text-muted)] pointer-events-none"
            />
            <input
              type="text"
              value={quickSearch}
              onChange={(e) => setQuickSearch(e.target.value)}
              placeholder="Quick find..."
              className="rounded border border-[var(--border-2)] bg-[var(--surface-3)] pl-6 pr-3 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none w-40"
            />
          </div>
        </div>

        {/* Tool grid */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading ? (
            <div className="flex h-full items-center justify-center">
              <p className="text-xs text-[var(--text-muted)]">Loading modules…</p>
            </div>
          ) : quickSearch ? (
            <>
              <p className="mb-3 text-xs text-[var(--text-muted)]">
                {quickResults.length} results for "{quickSearch}"
              </p>
              {quickResults.length === 0 ? (
                <p className="text-xs text-[var(--text-muted)]">No modules found.</p>
              ) : (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  {quickResults.map((t) => (
                    <ToolCard
                      key={t.name}
                      tool={t}
                      lastJob={jobs.find((j) => j.tool_name === t.name) ?? null}
                      onRun={handleRun}
                    />
                  ))}
                </div>
              )}
            </>
          ) : currentTools.length === 0 ? (
            <div className="flex h-full items-center justify-center">
              <p className="text-xs text-[var(--text-muted)]">
                No {activeCategory} modules available.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {currentTools.map((t) => (
                <ToolCard
                  key={t.name}
                  tool={t}
                  lastJob={jobs.find((j) => j.tool_name === t.name) ?? null}
                  onRun={handleRun}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Job queue sidebar */}
      <div
        className={`flex flex-col border-l border-[var(--border)] bg-[var(--surface)] transition-all duration-200 flex-shrink-0 ${
          queueVisible ? "w-64" : "w-8"
        }`}
      >
        {/* Toggle */}
        <button
          onClick={() => setQueueVisible((v) => !v)}
          className="flex h-8 items-center justify-center border-b border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          title={queueVisible ? "Hide queue" : "Show queue"}
        >
          {queueVisible ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>

        {queueVisible && (
          <>
            <div className="border-b border-[var(--border)] px-3 py-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                Job Queue ({recentJobs.length})
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-1">
              {recentJobs.length === 0 ? (
                <p className="text-center py-8 text-xs text-[var(--text-muted)]">
                  No jobs yet.
                </p>
              ) : (
                recentJobs.map((job) => <JobStatus key={job.id} job={job} />)
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
};
