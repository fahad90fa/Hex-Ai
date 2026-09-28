import React, { useEffect, useState } from "react";
import { Sidebar, PanelId } from "./components/layout/Sidebar";
import { TopBar } from "./components/layout/TopBar";
import { StatusBar } from "./components/layout/StatusBar";
import { TargetDashboard } from "./components/panels/TargetDashboard";
import { AttackGraph } from "./components/panels/AttackGraph";
import { ModuleRunner } from "./components/panels/ModuleRunner";
import { LiveTerminal } from "./components/panels/LiveTerminal";
import { ExploitWorkspace } from "./components/panels/ExploitWorkspace";
import { FindingsBoard } from "./components/panels/FindingsBoard";
import { ReportEngine } from "./components/panels/ReportEngine";
import { useSessionStore } from "./store/sessionStore";
import { useWebSocket } from "./hooks/useWebSocket";
import client from "./api/client";

// ─── Backend overlay ──────────────────────────────────────────────────────────

const BackendOverlay: React.FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-[var(--bg)]">
    <div className="flex flex-col items-center gap-4 rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-10 shadow-2xl max-w-sm w-full mx-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full border border-red-700/30 bg-red-900/20">
        <span className="text-3xl">⚡</span>
      </div>
      <h1 className="text-xl font-bold tracking-widest text-[var(--accent-fg)]">NEXUS</h1>
      <p className="text-center text-sm text-[var(--text-secondary)]">
        Unable to reach the backend at{" "}
        <code className="rounded bg-[var(--surface-3)] px-1 py-0.5 text-xs text-[var(--accent-fg)]">
          localhost:8000
        </code>
      </p>
      <p className="text-center text-xs text-[var(--text-muted)]">
        Make sure the Python backend is running:{" "}
        <code className="rounded bg-[var(--surface-3)] px-1 py-0.5 text-[10px]">
          python backend/main.py
        </code>
      </p>
      <button
        onClick={onRetry}
        className="w-full rounded bg-[var(--accent)] py-2 text-sm font-semibold text-white hover:bg-[var(--accent-2)] transition-colors"
      >
        Retry Connection
      </button>
    </div>
  </div>
);

// ─── Panel router ─────────────────────────────────────────────────────────────

function renderPanel(panel: PanelId): React.ReactNode {
  switch (panel) {
    case "dashboard": return <TargetDashboard />;
    case "graph":     return <AttackGraph />;
    case "modules":   return <ModuleRunner />;
    case "terminal":  return <LiveTerminal />;
    case "exploit":   return <ExploitWorkspace />;
    case "findings":  return <FindingsBoard />;
    case "report":    return <ReportEngine />;
  }
}

// ─── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const [activePanel, setActivePanel] = useState<PanelId>("dashboard");
  const [backendReady, setBackendReady] = useState(false);
  const [checkingBackend, setCheckingBackend] = useState(true);
  const [elapsed, setElapsed] = useState(0);

  const session = useSessionStore((s) => s.currentSession);
  const hydrateSession = useSessionStore((s) => s.hydrate);

  // WebSocket — only connect when we have a session
  const { connected: wsConnected } = useWebSocket(session?.id ?? null);

  // ── Backend health check ───────────────────────────────────────────────────
  const checkBackend = () => {
    setCheckingBackend(true);
    client
      .get("/health")
      .then(() => setBackendReady(true))
      .catch(() => setBackendReady(false))
      .finally(() => setCheckingBackend(false));
  };

  useEffect(() => {
    checkBackend();
    // Poll every 10s
    const interval = setInterval(checkBackend, 10_000);
    return () => clearInterval(interval);
  }, []);

  // ── Hydrate stored session ─────────────────────────────────────────────────
  useEffect(() => {
    hydrateSession();
  }, [hydrateSession]);

  // ── Elapsed timer ──────────────────────────────────────────────────────────
  useEffect(() => {
    if (!session) { setElapsed(0); return; }
    const start = new Date(session.created_at).getTime();
    const tick = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(tick);
  }, [session]);

  // ── Hash-based navigation ─────────────────────────────────────────────────
  useEffect(() => {
    const handleHash = () => {
      const hash = window.location.hash.replace("#", "") as PanelId;
      const valid: PanelId[] = ["dashboard", "graph", "modules", "terminal", "exploit", "findings", "report"];
      if (valid.includes(hash)) setActivePanel(hash);
    };
    window.addEventListener("hashchange", handleHash);
    handleHash();
    return () => window.removeEventListener("hashchange", handleHash);
  }, []);

  const navigate = (panel: PanelId) => {
    window.location.hash = panel;
    setActivePanel(panel);
  };

  // Show overlay only when backend definitely not reachable (not while checking)
  if (!checkingBackend && !backendReady) {
    return <BackendOverlay onRetry={checkBackend} />;
  }

  return (
    <div
      className="flex h-full flex-col overflow-hidden"
      style={{ background: "var(--bg)", color: "var(--text-primary)" }}
    >
      {/* Top bar */}
      <TopBar />

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar activePanel={activePanel} onNavigate={navigate} />

        {/* Main content */}
        <main className="relative flex-1 overflow-hidden bg-[var(--bg)]">
          {renderPanel(activePanel)}
        </main>
      </div>

      {/* Status bar */}
      <StatusBar
        wsConnected={wsConnected}
        backendReady={backendReady}
        elapsedSeconds={elapsed}
      />
    </div>
  );
}
