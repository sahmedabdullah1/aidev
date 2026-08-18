import type { Severity } from "./api";

export type ChartSlice = {
  label: string;
  value: number;
  color: string;
};

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b42318",
  high: "#c45c26",
  medium: "#b8860b",
  low: "#2f6b4f",
  info: "#3d5a80",
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function countBySeverity(items: { severity: Severity }[]): ChartSlice[] {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const item of items) {
    counts[item.severity] = (counts[item.severity] || 0) + 1;
  }
  return SEV_ORDER.filter((s) => counts[s] > 0).map((s) => ({
    label: s,
    value: counts[s],
    color: SEV_COLOR[s],
  }));
}

export function topIssueBars(
  items: { error?: string; title?: string; severity: Severity }[],
  limit = 8,
): ChartSlice[] {
  return items.slice(0, limit).map((item, i) => {
    const label = (item.error || item.title || `Issue ${i + 1}`).slice(0, 42);
    return {
      label,
      value: Math.max(1, SEV_ORDER.length - SEV_ORDER.indexOf(item.severity)),
      color: SEV_COLOR[item.severity],
    };
  });
}

/** Prefer occurrence-like weight when confidence is present */
export function issueImpactBars(
  items: { error?: string; title?: string; severity: Severity; confidence_score?: number }[],
  limit = 8,
): ChartSlice[] {
  return items.slice(0, limit).map((item, i) => {
    const sevWeight = Math.max(1, SEV_ORDER.length - SEV_ORDER.indexOf(item.severity));
    const conf = typeof item.confidence_score === "number" ? item.confidence_score / 20 : 3;
    return {
      label: (item.error || item.title || `Issue ${i + 1}`).slice(0, 42),
      value: Math.round(sevWeight * conf * 10) / 10,
      color: SEV_COLOR[item.severity],
    };
  });
}

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx: number, cy: number, r: number, startAngle: number, endAngle: number) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end = polarToCartesian(cx, cy, r, startAngle);
  const large = endAngle - startAngle <= 180 ? 0 : 1;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 0 ${end.x} ${end.y} L ${cx} ${cy} Z`;
}

function PieChart({ slices, title }: { slices: ChartSlice[]; title: string }) {
  const total = slices.reduce((s, x) => s + x.value, 0) || 1;
  let angle = 0;
  const cx = 90;
  const cy = 90;
  const r = 78;

  return (
    <div className="chart-card">
      <h5 className="chart-title">{title}</h5>
      <div className="chart-pie-wrap">
        <svg viewBox="0 0 180 180" className="chart-pie" role="img" aria-label={title}>
          {slices.length === 1 ? (
            <circle cx={cx} cy={cy} r={r} fill={slices[0].color} />
          ) : (
            slices.map((slice) => {
              const sweep = (slice.value / total) * 360;
              const start = angle;
              const end = angle + sweep;
              angle = end;
              return <path key={slice.label} d={arcPath(cx, cy, r, start, end)} fill={slice.color} />;
            })
          )}
          <circle cx={cx} cy={cy} r={42} fill="rgba(255,255,255,0.92)" />
          <text x={cx} y={cy - 4} textAnchor="middle" className="chart-center-num">
            {total}
          </text>
          <text x={cx} y={cy + 14} textAnchor="middle" className="chart-center-label">
            issues
          </text>
        </svg>
        <ul className="chart-legend">
          {slices.map((s) => (
            <li key={s.label}>
              <span className="swatch" style={{ background: s.color }} />
              <span className="leg-label">{s.label}</span>
              <strong>{s.value}</strong>
              <span className="leg-pct">{Math.round((s.value / total) * 100)}%</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function BarChart({ slices, title }: { slices: ChartSlice[]; title: string }) {
  const max = Math.max(...slices.map((s) => s.value), 1);
  return (
    <div className="chart-card">
      <h5 className="chart-title">{title}</h5>
      <div className="chart-bars" role="img" aria-label={title}>
        {slices.map((s) => (
          <div className="bar-row" key={s.label}>
            <div className="bar-label" title={s.label}>
              {s.label}
            </div>
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{
                  width: `${Math.max(6, (s.value / max) * 100)}%`,
                  background: s.color,
                }}
              />
            </div>
            <div className="bar-value">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBarChart({ slices, title }: { slices: ChartSlice[]; title: string }) {
  const max = Math.max(...slices.map((s) => s.value), 1);
  return (
    <div className="chart-card">
      <h5 className="chart-title">{title}</h5>
      <div className="chart-bars" role="img" aria-label={title}>
        {slices.map((s) => (
          <div className="bar-row" key={s.label}>
            <div className="bar-label" style={{ textTransform: "capitalize" }}>
              {s.label}
            </div>
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{
                  width: `${Math.max(8, (s.value / max) * 100)}%`,
                  background: s.color,
                }}
              />
            </div>
            <div className="bar-value">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ReportCharts({
  severityItems,
  issueItems,
}: {
  severityItems: { severity: Severity }[];
  issueItems: { error?: string; title?: string; severity: Severity; confidence_score?: number }[];
}) {
  const pie = countBySeverity(severityItems);
  const issueBars = issueImpactBars(issueItems);
  if (!pie.length && !issueBars.length) return null;

  return (
    <div className="section report-charts">
      <h4>Issue visuals</h4>
      <div className="charts-grid">
        {!!pie.length && <PieChart slices={pie} title="Issues by severity" />}
        {!!pie.length && <SeverityBarChart slices={pie} title="Severity counts" />}
      </div>
      {!!issueBars.length && (
        <div className="charts-grid single" style={{ marginTop: 14 }}>
          <BarChart slices={issueBars} title="Top issues (severity × confidence)" />
        </div>
      )}
    </div>
  );
}
