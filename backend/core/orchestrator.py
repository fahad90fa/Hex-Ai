# language: Python, file: backend/core/orchestrator.py
import asyncio
import json
import logging
import uuid
from pathlib import Path
from datetime import datetime, timezone
import redis.asyncio as aioredis
from ..config import get_settings
from ..tools import TOOL_REGISTRY

logger = logging.getLogger(__name__)
_orchestrator: "WorkerPool | None" = None


class WorkerPool:
    def __init__(self, n_workers: int = 10):
        self.n_workers = n_workers
        self._redis: aioredis.Redis | None = None
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self.category_filter = None  # optional ToolCategory filter

    async def start(self):
        self._redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
        self._running = True
        for i in range(self.n_workers):
            task = asyncio.create_task(self._worker(i))
            self._tasks.append(task)
        logger.info(f"orchestrator started {self.n_workers} workers")

    async def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        if self._redis:
            await self._redis.aclose()

    async def dispatch(self, job: dict) -> str:
        job_id = str(uuid.uuid4())
        job["job_id"] = job_id
        job["queued_at"] = datetime.now(timezone.utc).isoformat()
        if self._redis:
            await self._redis.rpush("nexus:jobs:queue", json.dumps(job))
            await self._redis.set(f"nexus:job:{job_id}:status", "QUEUED")
        await self._publish_event(job.get("session_id", ""), "job.started", {
            "job_id": job_id,
            "tool_name": job.get("tool_name"),
            "params": job.get("params", {}),
        })
        return job_id

    async def _worker(self, worker_id: int):
        while self._running:
            try:
                result = await self._redis.blpop("nexus:jobs:queue", timeout=5)
                if not result:
                    continue
                _, raw = result
                job = json.loads(raw)

                # apply category filter if set
                if self.category_filter:
                    tool_name = job.get("tool_name", "")
                    tool = TOOL_REGISTRY.get(tool_name)
                    if tool and tool.category != self.category_filter:
                        # re-queue for another worker pool
                        await self._redis.rpush("nexus:jobs:queue", raw)
                        continue

                await self._execute_job(job)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"worker {worker_id} error: {e}")

    async def _execute_job(self, job: dict):
        job_id = job["job_id"]
        session_id = job.get("session_id", "")
        tool_name = job.get("tool_name", "")
        params = job.get("params", {})

        tool = TOOL_REGISTRY.get(tool_name)
        if not tool:
            await self._redis.set(f"nexus:job:{job_id}:status", "FAILED")
            await self._publish_event(session_id, "job.failed", {
                "job_id": job_id,
                "error": f"unknown tool: {tool_name}",
            })
            return

        log_dir = Path(f"data/sessions/{session_id}/jobs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{job_id}.log"

        await self._redis.set(f"nexus:job:{job_id}:status", "RUNNING")
        start_time = datetime.now(timezone.utc)

        try:
            tool.configure(job_id=job_id, session_id=session_id, redis=self._redis)

            with open(log_path, "w", buffering=1) as logf:
                async for line in tool.stream(params):
                    logf.write(line + "\n")
                    await self._publish_event(session_id, "job.output", {
                        "job_id": job_id,
                        "line": line,
                    })

            result = await tool.run(params)
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

            await self._redis.set(f"nexus:job:{job_id}:status", "COMPLETED")
            await self._publish_event(session_id, "job.completed", {
                "job_id": job_id,
                "findings_count": len(result.findings),
                "duration_ms": duration_ms,
            })

            # ingest findings
            if result.findings:
                try:
                    from .findings_engine import get_findings_engine
                    fe = get_findings_engine()
                    await fe.ingest(session_id, job_id, result.findings)
                except Exception as e:
                    logger.error(f"findings ingest error: {e}")

        except Exception as e:
            logger.error(f"job {job_id} failed: {e}")
            await self._redis.set(f"nexus:job:{job_id}:status", "FAILED")
            await self._publish_event(session_id, "job.failed", {
                "job_id": job_id,
                "error": str(e),
            })

    async def _publish_event(self, session_id: str, event_type: str, data: dict):
        if not self._redis or not session_id:
            return
        event = {
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        await self._redis.publish(f"session:{session_id}:events", json.dumps(event))


def get_orchestrator() -> WorkerPool:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = WorkerPool()
    return _orchestrator
