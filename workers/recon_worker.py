"""Recon worker process — 5 concurrent recon jobs."""
import asyncio
import logging
from backend.core.worker_pool import WorkerPool
from shared.types import ToolCategory

logger = logging.getLogger("nexus.workers.recon")


async def main():
    pool = WorkerPool(n_workers=5, category_filter=ToolCategory.RECON)
    await pool.start()
    logger.info("recon_worker: 5 workers running")
    try:
        await asyncio.sleep(float("inf"))
    finally:
        await pool.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
