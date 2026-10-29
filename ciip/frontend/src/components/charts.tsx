/** Dependency-free SVG charts sized for dashboard cards. */

export function BarList({ data, labels, colors }: {
  data: Record<string, number>; labels?: Record<string, string>; colors?: Record<string, string>;
}) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (!entries.length) return <div className="muted pad">Aucune donnée</div>;
  return (
    <ul className="barlist">
      {entries.map(([k, v]) => (
        <li key={k}>
          <span className="barlist-label">{labels?.[k] ?? k}</span>
          <span className="barlist-track">
            <span className="barlist-fill" style={{ width: `${(v / max) * 100}%`, background: colors?.[k] }} />
          </span>
          <span className="barlist-value">{v}</span>
        </li>
      ))}
    </ul>
  );
}

export function TrendChart({ points }: { points: { date: string; count: number }[] }) {
  const w = 600;
  const h = 140;
  const pad = 24;
  const max = Math.max(1, ...points.map((p) => p.count));
  const step = points.length > 1 ? (w - pad * 2) / (points.length - 1) : 0;
  const xy = points.map((p, i) => [pad + i * step, h - pad - (p.count / max) * (h - pad * 2)] as const);
  const line = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = xy.length ? `${line} L${xy[xy.length - 1]![0]},${h - pad} L${xy[0]![0]},${h - pad} Z` : "";
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="trend" role="img" aria-label="Incidents par jour sur 30 jours">
      <line x1={pad} x2={w - pad} y1={h - pad} y2={h - pad} className="axis" />
      <text x={pad} y={14} className="axis-label">max {max}/jour</text>
      <path d={area} className="trend-area" />
      <path d={line} className="trend-line" />
      {xy.map(([x, y], i) => (
        <circle key={points[i]!.date} cx={x} cy={y} r={points[i]!.count ? 2.5 : 0} className="trend-dot">
          <title>{`${points[i]!.date} : ${points[i]!.count}`}</title>
        </circle>
      ))}
      {points.length > 0 && (
        <>
          <text x={pad} y={h - 6} className="axis-label">{points[0]!.date.slice(5)}</text>
          <text x={w - pad} y={h - 6} className="axis-label" textAnchor="end">{points[points.length - 1]!.date.slice(5)}</text>
        </>
      )}
    </svg>
  );
}

export function Gauge({ value, label }: { value: number | null; label: string }) {
  const pct = value ?? 0;
  const r = 40;
  const c = Math.PI * r;
  const tone = pct >= 90 ? "var(--ok)" : pct >= 70 ? "var(--warn)" : "var(--danger)";
  return (
    <svg viewBox="0 0 100 60" className="gauge" role="img" aria-label={`${label} : ${value ?? "n/d"} %`}>
      <path d="M10,50 A40,40 0 0 1 90,50" className="gauge-track" />
      <path d="M10,50 A40,40 0 0 1 90,50" style={{ stroke: tone, strokeDasharray: `${(pct / 100) * c} ${c}` }} className="gauge-fill" />
      <text x="50" y="46" textAnchor="middle" className="gauge-value">{value === null ? "n/d" : `${value}%`}</text>
    </svg>
  );
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};
