import React from "react";

interface CvssScoreProps {
  score: number;    // 0-10
  size?: "sm" | "md" | "lg";
}

function getRing(score: number): { ring: string; label: string; text: string } {
  if (score >= 9)   return { ring: "#ef4444", label: "Critical", text: "text-red-400" };
  if (score >= 7)   return { ring: "#f97316", label: "High",     text: "text-orange-400" };
  if (score >= 4)   return { ring: "#eab308", label: "Medium",   text: "text-yellow-400" };
  return                  { ring: "#10b981", label: "Low",      text: "text-emerald-400" };
}

const SIZE_MAP = {
  sm: { outer: 36, stroke: 3, fontSize: "text-xs" },
  md: { outer: 48, stroke: 4, fontSize: "text-sm" },
  lg: { outer: 64, stroke: 5, fontSize: "text-base" },
};

export const CvssScore: React.FC<CvssScoreProps> = ({ score, size = "md" }) => {
  const { ring, text } = getRing(score);
  const { outer, stroke, fontSize } = SIZE_MAP[size];
  const r = (outer - stroke * 2) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(10, score)) / 10;
  const dash = circ * pct;

  return (
    <div className="inline-flex flex-col items-center gap-0.5">
      <svg width={outer} height={outer} style={{ transform: "rotate(-90deg)" }}>
        {/* Track */}
        <circle
          cx={outer / 2}
          cy={outer / 2}
          r={r}
          fill="none"
          stroke="#1e1e2e"
          strokeWidth={stroke}
        />
        {/* Progress */}
        <circle
          cx={outer / 2}
          cy={outer / 2}
          r={r}
          fill="none"
          stroke={ring}
          strokeWidth={stroke}
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
        />
        {/* Score text — rotate back */}
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="central"
          style={{ transform: "rotate(90deg)", transformOrigin: "center", fontSize: size === "sm" ? 10 : size === "md" ? 13 : 17 }}
          fill="#e2e8f0"
          fontWeight="bold"
        >
          {score.toFixed(1)}
        </text>
      </svg>
      <span className={`${fontSize} font-semibold ${text} leading-none`}>
        {score.toFixed(1)}
      </span>
    </div>
  );
};
