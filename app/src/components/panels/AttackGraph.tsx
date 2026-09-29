import React, { useCallback, useMemo } from "react";
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Tag } from "lucide-react";
import { useGraphStore, NodeType, GraphNode } from "../../store/graphStore";
import { useAttackGraph } from "../../hooks/useAttackGraph";

// ─── Node detail panel ────────────────────────────────────────────────────────

const NODE_COLORS: Record<NodeType, string> = {
  SUBDOMAIN:  "#3b82f6",
  ENDPOINT:   "#10b981",
  SERVICE:    "#f59e0b",
  CREDENTIAL: "#ef4444",
  USER:       "#7c3aed",
};

interface NodeDetailProps {
  node: GraphNode;
}

const NodeDetail: React.FC<NodeDetailProps> = ({ node }) => {
  const allNodes = useGraphStore((s) => s.nodes);
  const allEdges = useGraphStore((s) => s.edges);

  const connectedNodes = useMemo(() => {
    const ids = new Set<string>();
    allEdges.forEach((e) => {
      if (e.source === node.id) ids.add(e.target);
      if (e.target === node.id) ids.add(e.source);
    });
    return allNodes.filter((n) => ids.has(n.id));
  }, [allNodes, allEdges, node.id]);

  const edges = useMemo(
    () => allEdges.filter((e) => e.source === node.id),
    [allEdges, node.id]
  );

  const color = NODE_COLORS[node.type] ?? "#6b7280";

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2">
        <span
          className="inline-block h-3 w-3 rounded-full flex-shrink-0"
          style={{ backgroundColor: color }}
        />
        <span className="font-semibold text-[var(--text-primary)] break-all">{node.label}</span>
      </div>

      <div className="flex items-center gap-2">
        <span
          className="rounded-full px-2 py-0.5 text-xs font-semibold"
          style={{ backgroundColor: `${color}22`, color }}
        >
          {node.type}
        </span>
      </div>

      {/* Properties */}
      {Object.keys(node.properties).length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Properties
          </h4>
          <div className="space-y-1">
            {Object.entries(node.properties).map(([k, v]) => (
              <div key={k} className="flex gap-2 text-xs">
                <span className="font-medium text-[var(--text-secondary)] min-w-[80px] flex-shrink-0">{k}</span>
                <span className="text-[var(--text-primary)] break-all">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Connections */}
      {connectedNodes.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Connected ({connectedNodes.length})
          </h4>
          <div className="space-y-1">
            {connectedNodes.slice(0, 20).map((n) => (
              <div key={n.id} className="flex items-center gap-1.5 text-xs">
                <span
                  className="inline-block h-2 w-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: NODE_COLORS[n.type] ?? "#6b7280" }}
                />
                <span className="text-[var(--text-primary)] truncate">{n.label}</span>
                <span className="text-[var(--text-muted)] ml-auto flex-shrink-0">{n.type}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Outgoing edges */}
      {edges.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Relationships
          </h4>
          <div className="space-y-1">
            {edges.map((e) => (
              <div key={e.id} className="text-xs">
                <span className="text-[var(--accent-fg)]">{e.relationship}</span>
                {e.technique && (
                  <span className="ml-1 text-[var(--text-muted)]">via {e.technique}</span>
                )}
                <span className="ml-1 text-[var(--text-muted)]">
                  ({Math.round(e.confidence * 100)}% conf)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Legend ───────────────────────────────────────────────────────────────────

const Legend: React.FC = () => (
  <div className="flex flex-col gap-1 rounded border border-[var(--border)] bg-[var(--surface)]/90 p-2 text-xs backdrop-blur">
    {(Object.entries(NODE_COLORS) as [NodeType, string][]).map(([type, color]) => (
      <div key={type} className="flex items-center gap-2">
        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
        <span className="text-[var(--text-secondary)]">{type}</span>
      </div>
    ))}
  </div>
);

// ─── Main panel ───────────────────────────────────────────────────────────────

export const AttackGraph: React.FC = () => {
  const selectNode = useGraphStore((s) => s.selectNode);
  const selectedNodeId = useGraphStore((s) => s.selectedNodeId);
  const allNodes = useGraphStore((s) => s.nodes);
  const selectedNode = useMemo(
    () => allNodes.find((n) => n.id === selectedNodeId) ?? null,
    [allNodes, selectedNodeId]
  );

  const handleNodeSelect = useCallback(
    (id: string | null) => selectNode(id),
    [selectNode]
  );

  const {
    containerRef,
    zoomIn,
    zoomOut,
    fit,
    resetLayout,
    toggleLabels,
    labelsVisible,
    nodeCount,
    edgeCount,
  } = useAttackGraph(handleNodeSelect);

  return (
    <div className="flex h-full">
      {/* Graph area */}
      <div className="relative flex-1 overflow-hidden">
        {/* Cytoscape mount point */}
        <div ref={containerRef} className="cy-container h-full w-full" />

        {/* Controls overlay */}
        <div className="absolute left-3 top-3 flex flex-col gap-1">
          <button
            onClick={zoomIn}
            className="rounded border border-[var(--border)] bg-[var(--surface)]/90 p-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] backdrop-blur transition-colors"
            title="Zoom in"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={zoomOut}
            className="rounded border border-[var(--border)] bg-[var(--surface)]/90 p-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] backdrop-blur transition-colors"
            title="Zoom out"
          >
            <ZoomOut size={14} />
          </button>
          <button
            onClick={fit}
            className="rounded border border-[var(--border)] bg-[var(--surface)]/90 p-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] backdrop-blur transition-colors"
            title="Fit graph"
          >
            <Maximize2 size={14} />
          </button>
          <button
            onClick={resetLayout}
            className="rounded border border-[var(--border)] bg-[var(--surface)]/90 p-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] backdrop-blur transition-colors"
            title="Reset layout"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={toggleLabels}
            className={`rounded border border-[var(--border)] bg-[var(--surface)]/90 p-1.5 backdrop-blur transition-colors ${
              labelsVisible ? "text-[var(--accent-fg)]" : "text-[var(--text-muted)]"
            }`}
            title="Toggle labels"
          >
            <Tag size={14} />
          </button>
        </div>

        {/* Stats overlay */}
        <div className="absolute bottom-3 left-3">
          <div className="rounded border border-[var(--border)] bg-[var(--surface)]/90 px-2 py-1 text-xs text-[var(--text-muted)] backdrop-blur">
            {nodeCount} nodes · {edgeCount} edges
          </div>
        </div>

        {/* Legend */}
        <div className="absolute bottom-3 right-3">
          <Legend />
        </div>

        {/* Empty state */}
        {nodeCount === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <p className="text-[var(--text-muted)] text-sm">No graph data yet.</p>
            <p className="text-[var(--text-muted)] text-xs mt-1">
              Run recon/scan modules to populate the attack graph.
            </p>
          </div>
        )}
      </div>

      {/* Node detail panel */}
      {selectedNode && (
        <div className="w-64 flex-shrink-0 border-l border-[var(--border)] bg-[var(--surface)]">
          <div className="flex items-center justify-between border-b border-[var(--border)] px-3 py-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Node Detail
            </span>
            <button
              onClick={() => selectNode(null)}
              className="text-[var(--text-muted)] hover:text-[var(--text-primary)] text-xs"
            >
              ✕
            </button>
          </div>
          <NodeDetail node={selectedNode} />
        </div>
      )}
    </div>
  );
};
