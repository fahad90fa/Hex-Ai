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

export function useJobQueue(): JobQueueStats {
  const jobs = useJobStore((s) => s.jobs);

  return useMemo(() => {
    const active = jobs.filter((j) => j.status === "running");
    const queued = jobs.filter((j) => j.status === "queued");
    const completed = jobs.filter((j) => j.status === "completed");
    const failed = jobs.filter((j) => j.status === "failed" || j.status === "killed");

    const finished = jobs.filter(
      (j) =>
        j.status === "completed" || j.status === "failed" || j.status === "killed"
    );

    const completionRate =
      jobs.length > 0 ? Math.round((finished.length / jobs.length) * 100) : 0;

    const durationsWithData = completed.filter((j) => j.duration_ms !== null);
    const averageDurationMs =
      durationsWithData.length > 0
        ? Math.round(
            durationsWithData.reduce((sum, j) => sum + (j.duration_ms ?? 0), 0) /
              durationsWithData.length
          )
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
