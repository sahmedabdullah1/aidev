import { LiveState } from "./api";

type Traffic = {
  total_requests?: number;
  success?: number;
  http_errors?: number;
  error_pct?: number;
  status_counts?: Record<string, number>;
  top_uris?: Record<string, number>;
  top_clients?: Record<string, number>;
  avg_latency_sec?: number | null;
  p95_latency_sec?: number | null;
};

type CarbonLog = {
  lines?: number;
  errors?: number;
  warnings?: number;
  gc_pauses?: number;
  top_error_messages?: Record<string, number>;
};

type Metrics = {
  cpu_pct?: number | null;
  mem_pct?: number | null;
  disk_pct?: number | null;
  load_1?: number | null;
  net_rx_bps?: number | null;
  net_tx_bps?: number | null;
  hostname?: string | null;
  note?: string | null;
  ips?: string[];
};

type Emissions = {
  kg_co2_per_hour?: number | null;
  session_kg_co2?: number | null;
  method?: string;
};

type Rates = {
  requests_per_sec?: number;
  window_error_pct?: number;
  session_error_pct?: number;
  avg_latency_sec?: number | null;
};

function fmt(n?: number | null, digits = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
}

function bps(n?: number | null) {
  if (n === null || n === undefined) return "—";
  if (n > 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB/s`;
  if (n > 1000) return `${(n / 1000).toFixed(1)} KB/s`;
  return `${Math.round(n)} B/s`;
}

function topPairs(obj?: Record<string, number>, limit = 6) {
  return Object.entries(obj || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
}

export function LiveSnapshotPanel({
  state,
  onAnalyzeNow,
  analyzingNow,
}: {
  state: LiveState;
  onAnalyzeNow: () => void;
  analyzingNow: boolean;
}) {
  const snap = state.snapshot || {};
  const traffic = (snap.traffic || {}) as Traffic;
  const carbon = (snap.carbon_log || {}) as CarbonLog;
  const metrics = (snap.metrics || {}) as Metrics;
  const emissions = (snap.emissions || {}) as Emissions;
  const rates = (snap.rates || {}) as Rates;
  const suspicious = (snap.suspicious_ips || []) as {
    ip: string;
    error_hits: number;
    requests: number;
    error_share: number;
  }[];
  const recent = (snap.recent_errors || []) as {
    file?: string;
    level?: string;
    logger?: string;
    message?: string;
  }[];

  return (
    <div className="live-board">
      <div className="live-board-head">
        <div>
          <h3 className="section-title">Live server</h3>
          <p className="empty">
            <span className={`live-dot ${state.error ? "bad" : "ok"}`} />
            {state.mode === "ssh" ? `${state.username || "user"}@${state.host}` : "this machine"}
            {" · "}
            {(state.log_dirs || []).join(", ") || "no dirs"}
            {state.last_poll_at ? ` · polled ${new Date(state.last_poll_at).toLocaleTimeString()}` : ""}
          </p>
        </div>
        <button className="ghost" type="button" onClick={onAnalyzeNow} disabled={analyzingNow || state.analyzing}>
          {state.analyzing || analyzingNow ? "AI report running…" : "Generate AI report now"}
        </button>
      </div>
      {state.error && <p className="error">{state.error}</p>}
      {!!state.warnings?.length && (
        <p className="empty">Warnings: {state.warnings.slice(-3).join(" · ")}</p>
      )}

      <ul className="file-stat-metrics live-kpis">
        <li>
          <span>Requests / sec</span>
          <strong>{fmt(rates.requests_per_sec, 2)}</strong>
        </li>
        <li>
          <span>Total requests</span>
          <strong>{fmt(traffic.total_requests)}</strong>
        </li>
        <li>
          <span>HTTP error %</span>
          <strong className={Number(traffic.error_pct) > 5 ? "err-val" : "ok-val"}>
            {fmt(traffic.error_pct, 2)}%
          </strong>
        </li>
        <li>
          <span>CPU</span>
          <strong>{metrics.cpu_pct == null ? "—" : `${fmt(metrics.cpu_pct, 1)}%`}</strong>
        </li>
        <li>
          <span>Memory</span>
          <strong>{metrics.mem_pct == null ? "—" : `${fmt(metrics.mem_pct, 1)}%`}</strong>
        </li>
        <li>
          <span>Disk</span>
          <strong>{metrics.disk_pct == null ? "—" : `${fmt(metrics.disk_pct, 1)}%`}</strong>
        </li>
        <li>
          <span>Net in / out</span>
          <strong>
            {bps(metrics.net_rx_bps)} / {bps(metrics.net_tx_bps)}
          </strong>
        </li>
        <li>
          <span>Est. CO₂</span>
          <strong>
            {emissions.kg_co2_per_hour == null ? "—" : `${fmt(emissions.kg_co2_per_hour, 3)} kg/h`}
          </strong>
        </li>
      </ul>
      <p className="empty">
        Carbon log errors {fmt(carbon.errors)} · warnings {fmt(carbon.warnings)} · GC pauses {fmt(carbon.gc_pauses)}
        {traffic.p95_latency_sec != null ? ` · p95 latency ${traffic.p95_latency_sec}s` : ""}
        {emissions.session_kg_co2 != null ? ` · session ${fmt(emissions.session_kg_co2, 4)} kg CO₂` : ""}
        {state.reports_generated ? ` · AI reports ${state.reports_generated}` : ""}
      </p>
      {metrics.note && <p className="empty">{metrics.note}</p>}

      <div className="file-stat-grid">
        <article className="file-stat-card">
          <div className="file-stat-head">
            <strong>Top URIs</strong>
          </div>
          <ul className="stat-breakdown">
            {topPairs(traffic.top_uris).map(([uri, n]) => (
              <li key={uri}>
                <code>{uri}</code> × {fmt(n)}
              </li>
            ))}
            {!topPairs(traffic.top_uris).length && <li>Waiting for http_access.log lines…</li>}
          </ul>
        </article>
        <article className="file-stat-card">
          <div className="file-stat-head">
            <strong>Client IPs</strong>
          </div>
          <ul className="stat-breakdown">
            {topPairs(traffic.top_clients).map(([ip, n]) => (
              <li key={ip}>
                <code>{ip}</code> × {fmt(n)}
              </li>
            ))}
            {!topPairs(traffic.top_clients).length && <li>No client IPs yet.</li>}
          </ul>
        </article>
        <article className="file-stat-card">
          <div className="file-stat-head">
            <strong>HTTP statuses</strong>
          </div>
          <ul className="stat-breakdown">
            {topPairs(traffic.status_counts).map(([code, n]) => (
              <li key={code}>
                <code>{code}</code> × {fmt(n)}
              </li>
            ))}
            {!topPairs(traffic.status_counts).length && <li>No access-log statuses yet.</li>}
          </ul>
        </article>
        <article className="file-stat-card">
          <div className="file-stat-head">
            <strong>Suspicious IPs</strong>
          </div>
          <ul className="stat-breakdown">
            {suspicious.slice(0, 8).map((row) => (
              <li key={row.ip}>
                <code>{row.ip}</code> {row.error_share}% errors ({fmt(row.error_hits)}/{fmt(row.requests)})
              </li>
            ))}
            {!suspicious.length && <li>No unusual IP error share yet.</li>}
          </ul>
        </article>
      </div>

      <div className="section">
        <h4>Tailed files</h4>
        <p className="empty">
          {state.files.map((f) => `${f.name} (${f.log_type}, ${(f.bytes_read / 1024).toFixed(0)} KB read)`).join(" · ") ||
            "Discovering…"}
        </p>
      </div>

      {!!recent.length && (
        <div className="section">
          <h4>Recent errors</h4>
          {recent
            .slice()
            .reverse()
            .slice(0, 12)
            .map((e, i) => (
              <article className={`finding ${e.level === "ERROR" || e.level === "FATAL" ? "high" : "medium"}`} key={`${e.message}-${i}`}>
                <div className="meta">
                  {e.level} · {e.logger} · {e.file}
                </div>
                <p>{e.message}</p>
              </article>
            ))}
        </div>
      )}

      {!!carbon.top_error_messages && Object.keys(carbon.top_error_messages).length > 0 && (
        <div className="stat-breakdown">
          <span className="stat-breakdown-title">Top carbon / traffic failure messages</span>
          <ul>
            {topPairs(carbon.top_error_messages, 8).map(([msg, n]) => (
              <li key={msg} title={msg}>
                {msg.length > 90 ? `${msg.slice(0, 90)}…` : msg} × {fmt(n)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
