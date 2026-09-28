# language: Python, file: backend/core/ws_hub.py
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Set
from fastapi import WebSocket
import redis.asyncio as aioredis
from ..config import get_settings

logger = logging.getLogger(__name__)


class WebSocketHub:
    def __init__(self):
        self._connections: Dict[str, Set[WebSocket]] = {}  # session_id -> set of websockets
        self._redis: aioredis.Redis | None = None
        self._subscriber_task: asyncio.Task | None = None

    async def startup(self):
        self._redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
        self._subscriber_task = asyncio.create_task(self._redis_subscriber())

    async def shutdown(self):
        if self._subscriber_task:
            self._subscriber_task.cancel()
        if self._redis:
            await self._redis.aclose()

    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        if session_id not in self._connections:
            self._connections[session_id] = set()
        self._connections[session_id].add(websocket)
        logger.info(f"WS connected session={session_id} total={len(self._connections[session_id])}")

    async def disconnect(self, websocket: WebSocket, session_id: str):
        if session_id in self._connections:
            self._connections[session_id].discard(websocket)
            if not self._connections[session_id]:
                del self._connections[session_id]

    async def broadcast(self, session_id: str, event_type: str, data: dict):
        event = {
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        payload = json.dumps(event)
        # publish to Redis so all workers can reach all WS clients
        if self._redis:
            await self._redis.publish(f"session:{session_id}:events", payload)

    async def _redis_subscriber(self):
        sub_redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
        pubsub = sub_redis.pubsub()
        await pubsub.psubscribe("session:*:events")
        async for message in pubsub.listen():
            if message["type"] != "pmessage":
                continue
            try:
                channel: str = message["channel"]
                session_id = channel.split(":")[1]
                payload = json.loads(message["data"])
                await self._deliver(session_id, payload)
            except Exception as e:
                logger.error(f"ws_hub subscriber error: {e}")

    async def _deliver(self, session_id: str, payload: dict):
        dead: list[WebSocket] = []
        for ws in list(self._connections.get(session_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws, session_id)


_hub = WebSocketHub()


def get_hub() -> WebSocketHub:
    return _hub
