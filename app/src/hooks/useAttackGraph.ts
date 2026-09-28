import { useEffect, useRef, useCallback, useState } from "react";
import cytoscape, { Core, ElementDefinition, LayoutOptions } from "cytoscape";
import { useGraphStore, NodeType } from "../store/graphStore";

// ─── Node colour map ──────────────────────────────────────────────────────────

const NODE_COLORS: Record<NodeType, string> = {
  SUBDOMAIN:  "#3b82f6",
  ENDPOINT:   "#10b981",
  SERVICE:    "#f59e0b",
  CREDENTIAL: "#ef4444",
  USER:       "#7c3aed",
};

// ─── Layout options ───────────────────────────────────────────────────────────

const LAYOUT: LayoutOptions = {
  name: "cose",
  animate: true,
  animationDuration: 500,
  nodeRepulsion: () => 8000,
  nodeOverlap: 20,
  idealEdgeLength: () => 100,
  edgeElasticity: () => 100,
  nestingFactor: 5,
  gravity: 80,
  numIter: 1000,
  initialTemp: 200,
  coolingFactor: 0.95,
  minTemp: 1.0,
};

// ─── Hook ─────────────────────────────────────────────────────────────────────

export interface UseAttackGraphReturn {
  containerRef: React.RefObject<HTMLDivElement | null>;
  zoomIn: () => void;
  zoomOut: () => void;
  fit: () => void;
  resetLayout: () => void;
  toggleLabels: () => void;
  labelsVisible: boolean;
  nodeCount: number;
  edgeCount: number;
}

export function useAttackGraph(
  onNodeSelect: (id: string | null) => void
): UseAttackGraphReturn {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [labelsVisible, setLabelsVisible] = useState(true);

  const nodes = useGraphStore((s) => s.nodes);
  const edges = useGraphStore((s) => s.edges);

  // ── Initialise Cytoscape once ──────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (ele) =>
              NODE_COLORS[(ele.data("type") as NodeType) ?? "SERVICE"] ?? "#6b7280",
            label: "data(label)",
            color: "#e2e8f0",
            "font-size": "11px",
            "text-valign": "bottom",
            "text-margin-y": 4,
            "min-zoomed-font-size": 8,
            width: 36,
            height: 36,
            "border-width": 2,
            "border-color": "#1e1e2e",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#7c3aed",
            "border-width": 3,
          },
        },
        {
          selector: "edge",
          style: {
            "line-color": "#2a2a3e",
            "target-arrow-color": "#2a2a3e",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(relationship)",
            color: "#94a3b8",
            "font-size": "9px",
            "text-rotation": "autorotate",
            width: (ele) => Math.max(1, (ele.data("confidence") as number) * 3),
          },
        },
        {
          selector: "edge:selected",
          style: {
            "line-color": "#7c3aed",
            "target-arrow-color": "#7c3aed",
          },
        },
      ],
      layout: { name: "preset" },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: true,
      autounselectify: false,
    });

    cy.on("tap", "node", (evt) => {
      onNodeSelect(evt.target.id() as string);
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) onNodeSelect(null);
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Sync nodes ────────────────────────────────────────────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const existing = new Set(cy.nodes().map((n) => n.id()));
    const toAdd: ElementDefinition[] = nodes
      .filter((n) => !existing.has(n.id))
      .map((n) => ({
        group: "nodes" as const,
        data: { id: n.id, label: n.label, type: n.type, ...n.properties },
        position: n.x != null && n.y != null ? { x: n.x, y: n.y } : undefined,
      }));

    if (toAdd.length) {
      cy.add(toAdd);
      cy.layout(LAYOUT).run();
    }
  }, [nodes]);

  // ── Sync edges ────────────────────────────────────────────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const existing = new Set(cy.edges().map((e) => e.id()));
    const toAdd: ElementDefinition[] = edges
      .filter((e) => !existing.has(e.id))
      .map((e) => ({
        group: "edges" as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          relationship: e.relationship,
          confidence: e.confidence,
          technique: e.technique,
        },
      }));

    if (toAdd.length) cy.add(toAdd);
  }, [edges]);

  // ── Label visibility ──────────────────────────────────────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().style("label", labelsVisible ? "data(label)" : "");
    cy.edges().style("label", labelsVisible ? "data(relationship)" : "");
  }, [labelsVisible]);

  // ── Controls ──────────────────────────────────────────────────────────────
  const zoomIn = useCallback(() => {
    cyRef.current?.zoom({ level: (cyRef.current?.zoom() ?? 1) * 1.2 });
  }, []);

  const zoomOut = useCallback(() => {
    cyRef.current?.zoom({ level: (cyRef.current?.zoom() ?? 1) * 0.8 });
  }, []);

  const fit = useCallback(() => {
    cyRef.current?.fit(undefined, 40);
  }, []);

  const resetLayout = useCallback(() => {
    cyRef.current?.layout(LAYOUT).run();
  }, []);

  const toggleLabels = useCallback(() => {
    setLabelsVisible((v) => !v);
  }, []);

  return {
    containerRef,
    zoomIn,
    zoomOut,
    fit,
    resetLayout,
    toggleLabels,
    labelsVisible,
    nodeCount: nodes.length,
    edgeCount: edges.length,
  };
}
