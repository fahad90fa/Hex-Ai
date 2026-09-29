import React, { useEffect, useRef, useState, useCallback } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import { X, Search, AlignJustify, Trash2 } from "lucide-react";
import { useJobStore } from "../../store/jobStore";
import type { Job } from "../../api/jobs";

// ─── Terminal instance pool (per job) ─────────────────────────────────────────

interface TermInstance {
  xterm: XTerm;
  fit: FitAddon;
  search: SearchAddon;
  autoScroll: boolean;
  lineCount: number;
}

const XTERM_THEME = {
  background:   "#0a0a0f",
  foreground:   "#e2e8f0",
  cursor:       "#7c3aed",
  cursorAccent: "#0a0a0f",
  black:        "#1a1a26",
  brightBlack:  "#2a2a3e",
  red:          "#ef4444",
  brightRed:    "#f87171",
  green:        "#10b981",
  brightGreen:  "#34d399",
  yellow:       "#f59e0b",
  brightYellow: "#fbbf24",
  blue:         "#3b82f6",
  brightBlue:   "#60a5fa",
  magenta:      "#7c3aed",
  brightMagenta:"#a78bfa",
  cyan:         "#06b6d4",
  brightCyan:   "#22d3ee",
  white:        "#cbd5e1",
  brightWhite:  "#f1f5f9",
};

function createTerminal(): TermInstance {
  const xterm = new XTerm({
    theme: XTERM_THEME,
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
    fontSize: 13,
    lineHeight: 1.4,
    scrollback: 10_000,
    cursorBlink: false,
    disableStdin: true,
    allowProposedApi: true,
  });
  const fit = new FitAddon();
  const search = new SearchAddon();
  xterm.loadAddon(fit);
  xterm.loadAddon(search);
  xterm.loadAddon(new WebLinksAddon());
  return { xterm, fit, search, autoScroll: true, lineCount: 0 };
}

function formatTimestamp(): string {
  const d = new Date();
  return `[${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}]`;
}

// ─── Component ────────────────────────────────────────────────────────────────

export const LiveTerminal: React.FC = () => {
  const jobs = useJobStore((s) => s.jobs);
  const jobOutputs = useJobStore((s) => s.jobOutputs);
  const clearOutput = useJobStore((s) => s.clearOutput);

  const activeJobs = jobs.filter(
    (j) => j.status === "RUNNING" || j.status === "QUEUED" || j.status === "COMPLETED" || j.status === "FAILED" || j.status === "KILLED"
  );

  const [activeJobId, setActiveJobId] = useState<string | null>(
    activeJobs[0]?.id ?? null
  );
  const [searchVisible, setSearchVisible] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const termRefs = useRef<Map<string, TermInstance>>(new Map());
  const containerRef = useRef<HTMLDivElement>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);

  // Set default active job when jobs change
  useEffect(() => {
    if (!activeJobId && activeJobs.length > 0) {
      setActiveJobId(activeJobs[0].id);
    }
  }, [activeJobs, activeJobId]);

  // Get or create a terminal instance for a job
  const getOrCreate = useCallback((jobId: string): TermInstance => {
    if (!termRefs.current.has(jobId)) {
      termRefs.current.set(jobId, createTerminal());
    }
    return termRefs.current.get(jobId)!;
  }, []);

  // Mount terminal into DOM when active job changes
  useEffect(() => {
    if (!activeJobId || !containerRef.current) return;

    const inst = getOrCreate(activeJobId);

    if (!inst.xterm.element) {
      inst.xterm.open(containerRef.current);
    } else {
      containerRef.current.appendChild(inst.xterm.element);
    }

    // Replay buffered lines
    const buffered = jobOutputs[activeJobId] ?? [];
    if (inst.lineCount < buffered.length) {
      for (let i = inst.lineCount; i < buffered.length; i++) {
        inst.xterm.writeln(`${formatTimestamp()} ${buffered[i]}`);
      }
      inst.lineCount = buffered.length;
    }

    setTimeout(() => inst.fit.fit(), 50);

    // Hide other terminals
    termRefs.current.forEach((other, id) => {
      if (id !== activeJobId && other.xterm.element) {
        other.xterm.element.style.display = "none";
      }
    });
    if (inst.xterm.element) {
      inst.xterm.element.style.display = "";
    }
  }, [activeJobId, getOrCreate, jobOutputs]);

  // Stream new output lines
  useEffect(() => {
    if (!activeJobId) return;
    const inst = getOrCreate(activeJobId);
    const lines = jobOutputs[activeJobId] ?? [];
    for (let i = inst.lineCount; i < lines.length; i++) {
      inst.xterm.writeln(`${formatTimestamp()} ${lines[i]}`);
    }
    inst.lineCount = lines.length;
    if (inst.autoScroll) {
      inst.xterm.scrollToBottom();
    }
  }, [activeJobId, jobOutputs, getOrCreate]);

  // ResizeObserver for fit
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(() => {
      if (activeJobId) {
        termRefs.current.get(activeJobId)?.fit.fit();
      }
    });
    ro.observe(containerRef.current);
    resizeObserverRef.current = ro;
    return () => ro.disconnect();
  }, [activeJobId]);

  // Cleanup on unmount
  useEffect(() => {
    const refs = termRefs.current;
    return () => {
      refs.forEach((inst) => inst.xterm.dispose());
      refs.clear();
    };
  }, []);

  const handleSearch = () => {
    if (!activeJobId || !searchQuery) return;
    termRefs.current.get(activeJobId)?.search.findNext(searchQuery);
  };

  const handleClear = () => {
    if (!activeJobId) return;
    const inst = termRefs.current.get(activeJobId);
    if (inst) {
      inst.xterm.clear();
      inst.lineCount = 0;
      clearOutput(activeJobId);
    }
  };

  const statusColor = (job: Job) =>
    job.status === "RUNNING"   ? "bg-yellow-400"
    : job.status === "COMPLETED" ? "bg-emerald-400"
    : job.status === "FAILED"    ? "bg-red-400"
    : job.status === "KILLED"    ? "bg-orange-400"
    : "bg-gray-500";

  return (
    <div className="flex h-full flex-col bg-[var(--bg)]">
      {/* Tab bar */}
      <div className="flex items-center gap-1 border-b border-[var(--border)] bg-[var(--surface)] px-2 py-1 overflow-x-auto flex-shrink-0">
        {activeJobs.length === 0 ? (
          <span className="px-3 py-1 text-xs text-[var(--text-muted)]">
            No active jobs — run a module to see output here.
          </span>
        ) : (
          activeJobs.map((job) => (
            <button
              key={job.id}
              onClick={() => setActiveJobId(job.id)}
              className={`
                flex items-center gap-1.5 rounded px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap flex-shrink-0
                ${activeJobId === job.id
                  ? "bg-[var(--surface-3)] text-[var(--text-primary)] border border-[var(--border-2)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }
              `}
            >
              <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${statusColor(job)}`} />
              {job.tool_name}
              <span className="text-[var(--text-muted)]">#{job.id.slice(0, 6)}</span>
            </button>
          ))
        )}

        {/* Controls */}
        <div className="ml-auto flex items-center gap-1 flex-shrink-0">
          <button
            onClick={() => setSearchVisible((v) => !v)}
            title="Search (Ctrl+F)"
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          >
            <Search size={13} />
          </button>
          <button
            onClick={handleClear}
            title="Clear output"
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          >
            <Trash2 size={13} />
          </button>
          <button
            title="Toggle auto-scroll"
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
            onClick={() => {
              if (activeJobId) {
                const inst = termRefs.current.get(activeJobId);
                if (inst) inst.autoScroll = !inst.autoScroll;
              }
            }}
          >
            <AlignJustify size={13} />
          </button>
        </div>
      </div>

      {/* Search bar */}
      {searchVisible && (
        <div className="flex items-center gap-2 border-b border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 flex-shrink-0">
          <input
            autoFocus
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSearch();
              if (e.key === "Escape") setSearchVisible(false);
            }}
            placeholder="Search output..."
            className="flex-1 rounded border border-[var(--border-2)] bg-[var(--surface-3)] px-2 py-0.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent)] focus:outline-none"
          />
          <button
            onClick={handleSearch}
            className="rounded bg-[var(--accent)] px-2 py-0.5 text-xs text-white"
          >
            Find
          </button>
          <button
            onClick={() => setSearchVisible(false)}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            <X size={12} />
          </button>
        </div>
      )}

      {/* Terminal container */}
      <div ref={containerRef} className="flex-1 overflow-hidden p-2" />
    </div>
  );
};
