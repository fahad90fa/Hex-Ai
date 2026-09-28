import { create } from "zustand";
import type { Job } from "../api/jobs";

// ─── State shape ──────────────────────────────────────────────────────────────

interface JobState {
  jobs: Job[];
  jobOutputs: Record<string, string[]>;
}

interface JobActions {
  addJob: (job: Job) => void;
  updateJob: (id: string, partial: Partial<Job>) => void;
  removeJob: (id: string) => void;
  setJobs: (jobs: Job[]) => void;
  appendOutput: (jobId: string, line: string) => void;
  clearOutput: (jobId: string) => void;
}

interface JobSelectors {
  activeJobs: () => Job[];
  getOutput: (jobId: string) => string[];
  completionRate: () => number;
}

type JobStore = JobState & JobActions & JobSelectors;

// ─── Store ────────────────────────────────────────────────────────────────────

export const useJobStore = create<JobStore>((set, get) => ({
  // ── State ──
  jobs: [],
  jobOutputs: {},

  // ── Actions ──

  addJob(job) {
    set((s) => {
      const exists = s.jobs.some((j) => j.id === job.id);
      if (exists) return s;
      return { jobs: [job, ...s.jobs] };
    });
  },

  updateJob(id, partial) {
    set((s) => ({
      jobs: s.jobs.map((j) => (j.id === id ? { ...j, ...partial } : j)),
    }));
  },

  removeJob(id) {
    set((s) => ({
      jobs: s.jobs.filter((j) => j.id !== id),
    }));
  },

  setJobs(jobs) {
    set({ jobs });
  },

  appendOutput(jobId, line) {
    set((s) => {
      const prev = s.jobOutputs[jobId] ?? [];
      // Cap at 10,000 lines
      const capped = prev.length >= 10_000 ? prev.slice(-9_999) : prev;
      return { jobOutputs: { ...s.jobOutputs, [jobId]: [...capped, line] } };
    });
  },

  clearOutput(jobId) {
    set((s) => ({
      jobOutputs: { ...s.jobOutputs, [jobId]: [] },
    }));
  },

  // ── Selectors ──

  activeJobs() {
    return get().jobs.filter((j) => j.status === "running" || j.status === "queued");
  },

  getOutput(jobId) {
    return get().jobOutputs[jobId] ?? [];
  },

  completionRate() {
    const { jobs } = get();
    if (!jobs.length) return 0;
    const done = jobs.filter(
      (j) => j.status === "completed" || j.status === "failed" || j.status === "killed"
    ).length;
    return Math.round((done / jobs.length) * 100);
  },
}));
