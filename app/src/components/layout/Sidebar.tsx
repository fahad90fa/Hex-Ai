import React, { useState } from "react";
import {
  Crosshair,
  GitBranch,
  Terminal,
  Monitor,
  Zap,
  Bug,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

export type PanelId =
  | "dashboard"
  | "graph"
  | "modules"
  | "terminal"
  | "exploit"
  | "findings"
  | "report";

interface NavItem {
  id: PanelId;
  label: string;
  Icon: React.FC<{ size?: number }>;
}

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Target Dashboard", Icon: Crosshair },
  { id: "graph",     label: "Attack Graph",      Icon: GitBranch },
  { id: "modules",   label: "Module Runner",     Icon: Terminal },
  { id: "terminal",  label: "Live Terminal",      Icon: Monitor },
  { id: "exploit",   label: "Exploit Workspace", Icon: Zap },
  { id: "findings",  label: "Findings Board",    Icon: Bug },
  { id: "report",    label: "Report Engine",     Icon: FileText },
];

interface SidebarProps {
  activePanel: PanelId;
  onNavigate: (panel: PanelId) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activePanel, onNavigate }) => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className="flex flex-col border-r border-[var(--border)] bg-[var(--surface)] transition-all duration-200"
      style={{ width: collapsed ? "var(--sidebar-width-collapsed)" : "var(--sidebar-width)" }}
    >
      {/* Toggle button */}
      <div className="flex h-[var(--topbar-height)] items-center justify-end px-2 border-b border-[var(--border)]">
        <button
          onClick={() => setCollapsed((c) => !c)}
          className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-3)] transition-colors"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex flex-1 flex-col gap-0.5 py-2 px-1.5 overflow-y-auto">
        {NAV_ITEMS.map(({ id, label, Icon }) => {
          const active = activePanel === id;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
              className={`
                flex items-center gap-3 rounded-md px-2 py-2 text-left text-sm font-medium transition-colors
                ${active
                  ? "bg-[var(--accent)]/20 text-[var(--accent-fg)] border border-[var(--accent)]/30"
                  : "text-[var(--text-secondary)] hover:bg-[var(--surface-3)] hover:text-[var(--text-primary)]"
                }
              `}
            >
              <Icon size={16} />
              {!collapsed && <span className="truncate">{label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Settings */}
      <div className="border-t border-[var(--border)] py-2 px-1.5">
        <button
          title="Settings"
          className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-sm text-[var(--text-muted)] hover:bg-[var(--surface-3)] hover:text-[var(--text-primary)] transition-colors"
        >
          <Settings size={16} />
          {!collapsed && <span>Settings</span>}
        </button>
      </div>
    </aside>
  );
};
