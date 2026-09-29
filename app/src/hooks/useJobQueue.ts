import { useMemo } from "react";
import { useJobStore } from "../store/jobStore";
import type { Job } from "../api/jobs";

interface JobQueueStats {
  activeJobs: Job[];
  queuedJobs: Job[];
  completedJobs: Job[];
  failedJobs: Job[];
  queueLength: number;
  activeCount: number;
  completionRate: number;
  averageDurationMs: number;
}

function jobDurationMs(job: Job): number | null {
  if (!job.started_at || !job.ended_at) return null;
  return new Date(job.ended_at).getTime() - new Date(job.started_at).getTime();
}

export function useJobQueue(): JobQueueStats {
  const jobs = useJobStore((s) => s.jobs);

  return useMemo(() => {
    const active    = jobs.filter((j) => j.status === "RUNNING");
    const queued    = jobs.filter((j) => j.status === "QUEUED");
    const completed = jobs.filter((j) => j.status === "COMPLETED");
    const failed    = jobs.filter((j) => j.status === "FAILED" || j.status === "KILLED");
    const finished  = jobs.filter((j) => j.status === "COMPLETED" || j.status === "FAILED" || j.status === "KILLED");

    const completionRate = jobs.length > 0 ? Math.round((finished.length / jobs.length) * 100) : 0;

    const durationsWithData = completed.map(jobDurationMs).filter((d): d is number => d !== null);
    const averageDurationMs =
      durationsWithData.length > 0
        ? Math.round(durationsWithData.reduce((s, d) => s + d, 0) / durationsWithData.length)
        : 0;

    return {
      activeJobs: active,
      queuedJobs: queued,
      completedJobs: completed,
      failedJobs: failed,
      queueLength: queued.length,
      activeCount: active.length,
      completionRate,
      averageDurationMs,
    };
  }, [jobs]);
}
