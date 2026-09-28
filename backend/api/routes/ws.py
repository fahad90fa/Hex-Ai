"""WebSocket hub — real-time event streaming per session."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

logger = logging.getLogger("nexus.ws")

router = APIRouter()


class WebSocketHub:
    """
    Central hub for broadcasting session events to connected WebSocket clients.

    Clients subscribe to a session by connecting to /ws?session_id=<uuid>.
    Events are published to Redis channels (session:{session_id}:events) and
    forwarded to all connected WebSocket clients for that session.
    """

    # Valid event types
    EVENT_TYPES = {
        "job.started",
        "job.output",
        "job.completed",
        "job.failed",
        "finding.new",
        "graph.node_added",
        "graph.edge_added",
        "ai.decision",
        "cve.match",
        "payload.evasion",
        "report.ready",
    }

    def __init__(self) -> None:
        # session_id -> set of connected WebSocket objects
        self._connections: dict[str, set[WebSocket]] = {}
        self._subscriber_task: Optional[asyncio.Task] = None
        self._redis: Optional[aioredis.Redis] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None

    def connect(self, websocket: WebSocket, session_id: str) -> None:
        if session_id not in self._connections:
            self._connections[session_id] = set()
        self._connections[session_id].add(websocket)
        logger.info("WS client connected to session %s (total: %d)", session_id, len(self._connections[session_id]))

    def disconnect(self, websocket: WebSocket, session_id: str) -> None:
        if session_id in self._connections:
            self._connections[session_id].discard(websocket)
            if not self._connections[session_id]:
                del self._connections[session_id]
        logger.info("WS client disconnected from session %s", session_id)

    async def broadcast(self, session_id: str, event_type: str, data: dict) -> None:
        """Send an event to all WebSocket clients subscribed to the given session."""
        if session_id not in self._connections:
            return

        envelope = {
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        payload = json.dumps(envelope)

        dead: list[WebSocket] = []
        for ws in list(self._connections.get(session_id, [])):
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws, session_id)

    async def start_subscriber(self, redis: aioredis.Redis) -> None:
        """Subscribe to all session event channels and forward to WS clients."""
        self._redis = redis
        self._pubsub = redis.pubsub()
        # Subscribe to a wildcard pattern — psubscribe handles session:*:events
        await self._pubsub.psubscribe("session:*:events")
        self._subscriber_task = asyncio.create_task(self._subscriber_loop())

    async def stop_subscriber(self) -> None:
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
        if self._pubsub:
            await self._pubsub.punsubscribe("session:*:events")
            await self._pubsub.aclose()

    async def _subscriber_loop(self) -> None:
        """Continuously read Redis pmessages and forward to WS clients."""
        try:
            async for message in self._pubsub.listen():
                if message["type"] != "pmessage":
                    continue
                channel: str = message["channel"]
                # channel format: session:{session_id}:events
                parts = channel.split(":")
                if len(parts) < 3:
                    continue
                session_id = parts[1]

                raw_data = message["data"]
                try:
                    event_data = json.loads(raw_data)
                except Exception:
                    event_data = {"raw": raw_data}

                event_type = event_data.get("type", "unknown")
                payload = event_data.get("data", event_data)

                await self.broadcast(session_id, event_type, payload)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("WS subscriber loop error: %s", exc)


# Module-level singleton
ws_hub = WebSocketHub()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, session_id: str = "") -> None:
    """WebSocket endpoint — subscribe to session events."""
    if not session_id:
        await websocket.close(code=4000)
        return

    await websocket.accept()
    ws_hub.connect(websocket, session_id)

    try:
        # Keep the connection alive; handle ping/pong from client
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Respond to heartbeat ping
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_text(json.dumps({"type": "keepalive"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS session %s closed with error: %s", session_id, exc)
    finally:
        ws_hub.disconnect(websocket, session_id)
