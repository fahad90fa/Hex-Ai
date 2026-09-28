import { useEffect, useRef, useState, useCallback } from "react";
import { useJobStore } from "../store/jobStore";
import { useFindingsStore } from "../store/findingsStore";
import { useGraphStore } from "../store/graphStore";
import type { Finding } from "../api/findings";
import type { Job } from "../api/jobs";
import type { GraphNode, GraphEdge } from "../store/graphStore";

// ─── Event envelope types ─────────────────────────────────────────────────────

interface WsEvent<T = unknown> {
  event: string;
  data: T;
}

interface JobOutputData { job_id: string; line: string }
interface FindingData extends Finding {}
interface GraphNodeData extends GraphNode {}
interface GraphEdgeData extends GraphEdge {}
interface JobUpdateData extends Partial<Job> { id: string }

// ─── Hook return ──────────────────────────────────────────────────────────────

interface UseWebSocketReturn {
  connected: boolean;
  lastEvent: WsEvent | null;
  sendMessage: (msg: unknown) => void;
}

const MAX_RETRIES = 10;
const BASE_DELAY_MS = 500;

export function useWebSocket(sessionId: string | null): UseWebSocketReturn {
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMountedRef = useRef(true);

  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);

  const appendOutput = useJobStore((s) => s.appendOutput);
  const updateJob = useJobStore((s) => s.updateJob);
  const addFinding = useFindingsStore((s) => s.addFinding);
  const addNode = useGraphStore((s) => s.addNode);
  const addEdge = useGraphStore((s) => s.addEdge);

  const handleMessage = useCallback(
    (raw: string) => {
      let envelope: WsEvent;
      try {
        envelope = JSON.parse(raw) as WsEvent;
      } catch {
        return;
      }

      setLastEvent(envelope);

      switch (envelope.event) {
        case "job.output": {
          const d = envelope.data as JobOutputData;
          appendOutput(d.job_id, d.line);
          break;
        }
        case "finding.new": {
          const d = envelope.data as FindingData;
          addFinding(d);
          break;
        }
        case "graph.node_added": {
          const d = envelope.data as GraphNodeData;
          addNode(d);
          break;
        }
        case "graph.edge_added": {
          const d = envelope.data as GraphEdgeData;
          addEdge(d);
          break;
        }
        case "job.completed":
        case "job.failed": {
          const d = envelope.data as JobUpdateData;
          updateJob(d.id, {
            status: envelope.event === "job.completed" ? "completed" : "failed",
            ...d,
          });
          break;
        }
        default:
          break;
      }
    },
    [appendOutput, updateJob, addFinding, addNode, addEdge]
  );

  const connect = useCallback(() => {
    if (!sessionId || !isMountedRef.current) return;

    const url = `ws://localhost:8000/ws?session_id=${sessionId}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!isMountedRef.current) { ws.close(); return; }
      retryRef.current = 0;
      setConnected(true);
    };

    ws.onmessage = (ev) => {
      handleMessage(typeof ev.data === "string" ? ev.data : String(ev.data));
    };

    ws.onerror = () => {
      // onclose will follow and handle reconnection
    };

    ws.onclose = () => {
      if (!isMountedRef.current) return;
      setConnected(false);
      wsRef.current = null;

      if (retryRef.current < MAX_RETRIES) {
        const delay = Math.min(BASE_DELAY_MS * 2 ** retryRef.current, 30_000);
        retryRef.current += 1;
        reconnectTimerRef.current = setTimeout(connect, delay);
      }
    };
  }, [sessionId, handleMessage]);

  useEffect(() => {
    isMountedRef.current = true;
    if (sessionId) connect();

    return () => {
      isMountedRef.current = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [sessionId, connect]);

  const sendMessage = useCallback((msg: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  return { connected, lastEvent, sendMessage };
}
