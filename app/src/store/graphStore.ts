import { create } from "zustand";

// ─── Types ────────────────────────────────────────────────────────────────────

export type NodeType = "SUBDOMAIN" | "ENDPOINT" | "SERVICE" | "CREDENTIAL" | "USER";

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  properties: Record<string, unknown>;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  confidence: number;        // 0–1
  technique?: string;
}

// ─── State shape ──────────────────────────────────────────────────────────────

interface GraphState {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedNodeId: string | null;
}

interface GraphActions {
  addNode: (node: GraphNode) => void;
  updateNode: (id: string, partial: Partial<GraphNode>) => void;
  addEdge: (edge: GraphEdge) => void;
  selectNode: (id: string | null) => void;
  clearGraph: () => void;
  setGraph: (nodes: GraphNode[], edges: GraphEdge[]) => void;
}

interface GraphSelectors {
  selectedNode: () => GraphNode | null;
  nodesByType: (type: NodeType) => GraphNode[];
  edgesBySource: (sourceId: string) => GraphEdge[];
  connectedNodes: (nodeId: string) => GraphNode[];
}

type GraphStore = GraphState & GraphActions & GraphSelectors;

// ─── Store ────────────────────────────────────────────────────────────────────

export const useGraphStore = create<GraphStore>((set, get) => ({
  // ── State ──
  nodes: [],
  edges: [],
  selectedNodeId: null,

  // ── Actions ──

  addNode(node) {
    set((s) => {
      const exists = s.nodes.some((n) => n.id === node.id);
      if (exists) return s;
      return { nodes: [...s.nodes, node] };
    });
  },

  updateNode(id, partial) {
    set((s) => ({
      nodes: s.nodes.map((n) => (n.id === id ? { ...n, ...partial } : n)),
    }));
  },

  addEdge(edge) {
    set((s) => {
      const exists = s.edges.some((e) => e.id === edge.id);
      if (exists) return s;
      return { edges: [...s.edges, edge] };
    });
  },

  selectNode(id) {
    set({ selectedNodeId: id });
  },

  clearGraph() {
    set({ nodes: [], edges: [], selectedNodeId: null });
  },

  setGraph(nodes, edges) {
    set({ nodes, edges });
  },

  // ── Selectors ──

  selectedNode() {
    const { nodes, selectedNodeId } = get();
    return nodes.find((n) => n.id === selectedNodeId) ?? null;
  },

  nodesByType(type) {
    return get().nodes.filter((n) => n.type === type);
  },

  edgesBySource(sourceId) {
    return get().edges.filter((e) => e.source === sourceId);
  },

  connectedNodes(nodeId) {
    const { nodes, edges } = get();
    const connectedIds = new Set<string>();
    edges.forEach((e) => {
      if (e.source === nodeId) connectedIds.add(e.target);
      if (e.target === nodeId) connectedIds.add(e.source);
    });
    return nodes.filter((n) => connectedIds.has(n.id));
  },
}));
