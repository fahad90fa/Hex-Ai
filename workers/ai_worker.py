#!/usr/bin/env python3
# AI brain worker — runs LangGraph sessions from the job queue
import asyncio
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redis.asyncio as aioredis
from backend.config import get_settings
from backend.ai.brain import run_session


async def main():
    redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
    print("[ai_worker] started, listening on nexus:ai:queue")
    while True:
        try:
            result = await redis.blpop("nexus:ai:queue", timeout=5)
            if not result:
                continue
            _, raw = result
            job = json.loads(raw)
            session_id = job.get("session_id")
            target = job.get("target")
            if not session_id or not target:
                print(f"[ai_worker] invalid job: {job}")
                continue
            print(f"[ai_worker] starting session {session_id} for target {target}")
            asyncio.create_task(run_session(session_id, target))
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ai_worker] error: {e}")
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
