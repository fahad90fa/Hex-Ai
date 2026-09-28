"""AI worker — pops sessions from nexus:ai:queue and runs the LangGraph brain."""
import asyncio
import json
import logging
import redis.asyncio as aioredis
from backend.config import get_settings
from backend.ai.brain import run_session

logger = logging.getLogger("nexus.workers.ai")


async def main():
    settings = get_settings()
    redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    logger.info("ai_worker: listening on nexus:ai:queue")

    while True:
        try:
            result = await redis.blpop("nexus:ai:queue", timeout=5)
            if not result:
                continue

            _, payload = result
            data = json.loads(payload)
            session_id = data.get("session_id")
            target = data.get("target")

            if not session_id or not target:
                logger.warning(f"ai_worker: invalid payload: {payload[:100]}")
                continue

            logger.info(f"ai_worker: starting session {session_id} for {target}")
            asyncio.create_task(run_session(session_id=session_id, target=target))

        except Exception as e:
            logger.error(f"ai_worker error: {e}")
            await asyncio.sleep(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
