#!/usr/bin/env python3
# Dedicated worker that only processes RECON category jobs
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.orchestrator import WorkerPool
from backend.tools.base import ToolCategory


async def main():
    pool = WorkerPool(n_workers=5)
    # filter to only RECON tools
    pool.category_filter = ToolCategory.RECON
    await pool.start()
    try:
        await asyncio.sleep(float("inf"))
    except KeyboardInterrupt:
        await pool.stop()


if __name__ == "__main__":
    asyncio.run(main())
