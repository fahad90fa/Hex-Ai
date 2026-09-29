import React from "react";
import { AlertTriangle, AlertCircle, Info, ShieldAlert, Minus } from "lucide-react";
import type { Severity } from "../../api/findings";

interface SeverityBadgeProps {
  severity: Severity;
  compact?: boolean;
}

const CONFIG: Record<
  Severity,
  { bg: string; text: string; border: string; Icon: React.FC<{ size?: number }> }
> = {
  CRITICAL: {
    bg: "bg-red-900/40",
    text: "text-red-400",
    border: "border-red-700/50",
    Icon: ShieldAlert,
  },
  HIGH: {
    bg: "bg-orange-900/40",
    text: "text-orange-400",
    border: "border-orange-700/50",
    Icon: AlertTriangle,
  },
  MEDIUM: {
    bg: "bg-yellow-900/40",
    text: "text-yellow-400",
    border: "border-yellow-700/50",
    Icon: AlertCircle,
  },
  LOW: {
    bg: "bg-blue-900/40",
    text: "text-blue-400",
    border: "border-blue-700/50",
    Icon: Minus,
  },
  INFO: {
    bg: "bg-gray-800/40",
    text: "text-gray-400",
    border: "border-gray-600/50",
    Icon: Info,
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, compact = false }) => {
  const { bg, text, border, Icon } = CONFIG[severity];

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold ${bg} ${text} ${border}`}
    >
      <Icon size={11} />
      {!compact && severity}
    </span>
  );
};
