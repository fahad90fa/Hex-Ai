"""Attack graph routes (nodes, edges, shortest paths)."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db, get_neo4j
from backend.db.models import GraphEdge, GraphNode
from backend.shared_types import GraphEdgeResponse, GraphNodeResponse

router = APIRouter()


@router.get("/graph/nodes", response_model=list[GraphNodeResponse])
async def get_graph_nodes(
    session_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
) -> list[GraphNodeResponse]:
    """Return all graph nodes for a session."""
    result = await db.execute(
        select(GraphNode).where(GraphNode.session_id == session_id)
    )
    return [_node_to_response(n) for n in result.scalars().all()]


@router.get("/graph/edges", response_model=list[GraphEdgeResponse])
async def get_graph_edges(
    session_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
) -> list[GraphEdgeResponse]:
    """Return all graph edges for a session."""
    result = await db.execute(
        select(GraphEdge)
        .join(GraphNode, GraphEdge.source_node_id == GraphNode.id)
        .where(GraphNode.session_id == session_id)
    )
    return [_edge_to_response(e) for e in result.scalars().all()]


@router.get("/graph/paths")
async def get_graph_paths(
    session_id: uuid.UUID = Query(...),
    source: str = Query(..., description="Source node label"),
    target: str = Query(..., description="Target node label"),
    neo4j=Depends(get_neo4j),
) -> dict:
    """Find shortest paths between two nodes using Neo4j Cypher."""
    cypher = """
    MATCH (src {label: $source, session_id: $session_id}),
          (tgt {label: $target, session_id: $session_id}),
          path = shortestPath((src)-[*..20]-(tgt))
    RETURN path
    LIMIT 5
    """
    try:
        async with neo4j.session() as neo_session:
            result = await neo_session.run(
                cypher,
                source=source,
                target=target,
                session_id=str(session_id),
            )
            records = await result.values()

        paths = []
        for record in records:
            path = record[0]
            if path:
                paths.append({
                    "nodes": [dict(n) for n in path.nodes],
                    "relationships": [
                        {"type": r.type, "start": r.start_node.element_id, "end": r.end_node.element_id}
                        for r in path.relationships
                    ],
                    "length": len(path.relationships),
                })
        return {"paths": paths, "count": len(paths)}

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Graph query failed: {exc}")


def _node_to_response(n: GraphNode) -> GraphNodeResponse:
    return GraphNodeResponse(
        id=n.id,
        session_id=n.session_id,
        type=n.type,
        label=n.label,
        properties=n.properties_json or {},
        discovered_at=n.discovered_at,
    )


def _edge_to_response(e: GraphEdge) -> GraphEdgeResponse:
    return GraphEdgeResponse(
        id=e.id,
        source_node_id=e.source_node_id,
        target_node_id=e.target_node_id,
        relationship=e.relationship,
        confidence=e.confidence,
        created_at=e.created_at,
    )
