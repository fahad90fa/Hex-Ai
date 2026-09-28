# language: Python, file: backend/core/graph_engine.py
# Neo4j async driver: add_node, add_edge, get_nodes, get_edges, shortest_paths, clear_session
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver

from ..config import get_settings

logger = logging.getLogger(__name__)
_graph_engine: "GraphEngine | None" = None


class GraphEngine:
    def __init__(self):
        self._driver: AsyncDriver | None = None

    async def connect(self):
        settings = get_settings()
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        await self._driver.verify_connectivity()
        logger.info("GraphEngine connected to Neo4j")

    async def close(self):
        if self._driver:
            await self._driver.close()

    async def add_node(
        self,
        session_id: str,
        node_type: str,
        label: str,
        properties: Optional[dict] = None,
    ) -> str:
        """Add or merge a node into the graph. Returns the node ID."""
        node_id = str(uuid.uuid4())
        props = properties or {}
        props.update({
            "id": node_id,
            "session_id": session_id,
            "label": label,
            "type": node_type,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        })

        query = (
            f"MERGE (n:{node_type} {{session_id: $session_id, label: $label}}) "
            "ON CREATE SET n += $props "
            "ON MATCH SET n += $props "
            "RETURN n.id AS node_id"
        )

        try:
            async with self._driver.session() as sess:
                result = await sess.run(query, session_id=session_id, label=label, props=props)
                record = await result.single()
                if record:
                    return record["node_id"]
        except Exception as e:
            logger.error(f"graph add_node error: {e}")

        return node_id

    async def add_edge(
        self,
        session_id: str,
        source_label: str,
        source_type: str,
        target_label: str,
        target_type: str,
        relationship: str,
        confidence: float = 1.0,
        properties: Optional[dict] = None,
    ) -> str:
        """Add a directed edge between two nodes. Returns edge ID."""
        edge_id = str(uuid.uuid4())
        edge_props = properties or {}
        edge_props.update({
            "id": edge_id,
            "session_id": session_id,
            "relationship": relationship,
            "confidence": confidence,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        query = (
            f"MATCH (a:{source_type} {{session_id: $session_id, label: $source_label}}) "
            f"MATCH (b:{target_type} {{session_id: $session_id, label: $target_label}}) "
            f"MERGE (a)-[r:{relationship}]->(b) "
            "ON CREATE SET r += $props "
            "ON MATCH SET r += $props "
            "RETURN r.id AS edge_id"
        )

        try:
            async with self._driver.session() as sess:
                result = await sess.run(
                    query,
                    session_id=session_id,
                    source_label=source_label,
                    target_label=target_label,
                    props=edge_props,
                )
                record = await result.single()
                if record:
                    return record["edge_id"]
        except Exception as e:
            logger.error(f"graph add_edge error: {e}")

        return edge_id

    async def get_nodes(self, session_id: str, node_type: Optional[str] = None) -> list[dict]:
        """Return all nodes for a session, optionally filtered by type."""
        if node_type:
            query = f"MATCH (n:{node_type} {{session_id: $session_id}}) RETURN properties(n) AS props"
        else:
            query = "MATCH (n {session_id: $session_id}) RETURN properties(n) AS props"

        try:
            async with self._driver.session() as sess:
                result = await sess.run(query, session_id=session_id)
                records = await result.data()
                return [r["props"] for r in records]
        except Exception as e:
            logger.error(f"graph get_nodes error: {e}")
            return []

    async def get_edges(self, session_id: str, relationship: Optional[str] = None) -> list[dict]:
        """Return all edges for a session."""
        if relationship:
            query = (
                f"MATCH (a {{session_id: $session_id}})-[r:{relationship}]->(b {{session_id: $session_id}}) "
                "RETURN properties(a) AS source, properties(b) AS target, properties(r) AS edge"
            )
        else:
            query = (
                "MATCH (a {session_id: $session_id})-[r]->(b {session_id: $session_id}) "
                "RETURN properties(a) AS source, properties(b) AS target, properties(r) AS edge"
            )

        try:
            async with self._driver.session() as sess:
                result = await sess.run(query, session_id=session_id)
                records = await result.data()
                return [
                    {
                        "source": r["source"],
                        "target": r["target"],
                        "edge": r["edge"],
                    }
                    for r in records
                ]
        except Exception as e:
            logger.error(f"graph get_edges error: {e}")
            return []

    async def shortest_paths(
        self,
        session_id: str,
        source_label: str,
        target_label: str,
        max_depth: int = 10,
    ) -> list[list[dict]]:
        """Find shortest paths between two nodes."""
        query = (
            "MATCH path = shortestPath("
            "(a {session_id: $session_id, label: $source_label})-[*1.." + str(max_depth) + "]->"
            "(b {session_id: $session_id, label: $target_label})) "
            "RETURN [n IN nodes(path) | properties(n)] AS path_nodes"
        )

        try:
            async with self._driver.session() as sess:
                result = await sess.run(
                    query,
                    session_id=session_id,
                    source_label=source_label,
                    target_label=target_label,
                )
                records = await result.data()
                return [r["path_nodes"] for r in records]
        except Exception as e:
            logger.error(f"graph shortest_paths error: {e}")
            return []

    async def clear_session(self, session_id: str):
        """Remove all nodes and edges for a session."""
        query = "MATCH (n {session_id: $session_id}) DETACH DELETE n"
        try:
            async with self._driver.session() as sess:
                await sess.run(query, session_id=session_id)
        except Exception as e:
            logger.error(f"graph clear_session error: {e}")


def get_graph_engine() -> GraphEngine:
    global _graph_engine
    if _graph_engine is None:
        _graph_engine = GraphEngine()
    return _graph_engine
