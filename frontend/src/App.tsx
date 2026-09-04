import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  DevOpsReport,
  Finding,
  isWso2Report,
  Job,
  LiveState,
  Wso2ErrorItem,
  Wso2Report,
} from "./api";
import { LiveSnapshotPanel } from "./LivePanel";
import { ReportCharts } from "./ReportCharts";

function ReportShareBar({ report }: { report: DevOpsReport | Wso2Report }) {
  const [shareMsg, setShareMsg] = useState<string | null>(null);
  const pageUrl =
    typeof window !== "undefined"
      ? `${window.location.origin}${window.location.pathname}?report=${report.id}`
      : api.downloadUrl(report.id, "html");
  const title = isWso2Report(report)
    ? `WSO2 APIM/MI report #${report.id}`
    : `AI DevOps report #${report.id}`;
  const blurb = `${title} — health ${report.health_score}/100, risk ${report.risk_level}. ${report.executive_summary.slice(0, 220)}`;

  const flash = (msg: string) => {
    setShareMsg(msg);
    window.setTimeout(() => setShareMsg(null), 2500);
  };

  const copyText = async (text: string, okMsg: string) => {
    try {
      await navigator.clipboard.writeText(text);
      flash(okMsg);
    } catch {
      flash("Copy failed — use the download links instead");
    }
  };

  const onShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title,
          text: blurb,
          url: pageUrl,
        });
        flash("Share sheet opened");
        return;
      } catch {
        /* user cancelled or unsupported — fall through to copy */
      }
    }
    await copyText(`${blurb}\n\n${pageUrl}`, "Report link copied");
  };

  return (
    <div className="report-share">
      <div className="report-share-label">Download & share</div>
      <div className="actions report-share-actions">
        <a className="share-btn" href={api.downloadUrl(report.id, "md")} download={`${report.id}.md`}>
          Download Markdown
        </a>
        <a className="share-btn" href={api.downloadUrl(report.id, "html")} download={`${report.id}.html`}>
          Download HTML
        </a>
        <a className="share-btn" href={api.downloadUrl(report.id, "json")} download={`${report.id}.json`}>
          Download JSON
        </a>
        <button type="button" className="share-btn primary-share" onClick={onShare}>
          Share report
        </button>
        <button type="button" className="share-btn" onClick={() => copyText(pageUrl, "Link copied")}>
          Copy link
        </button>
        <button type="button" className="share-btn" onClick={() => copyText(blurb, "Summary copied")}>
          Copy summary
        </button>
      </div>
      {shareMsg && <p className="share-toast">{shareMsg}</p>}
    </div>
  );
}
function usePollingJob(jobId: string | null) {
  const [job, setJob] = useState<Job | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const tick = async () => {
      try {
        const j = await api.job(jobId);
        if (!alive) return;
        setJob(j);
        if (j.status === "completed" || j.status === "failed" || j.status === "cancelled") return;
        window.setTimeout(tick, 1500);
      } catch {
        if (alive) window.setTimeout(tick, 2500);
      }
    };
    tick();
    return () => {
      alive = false;
    };
  }, [jobId]);

  return job;
}

function FindingCard({ f }: { f: Finding }) {
  const fixes = f.recommended_fixes?.length ? f.recommended_fixes : f.recommendation ? [f.recommendation] : [];
  return (
    <article className={`finding ${f.severity}`}>
      <div className="meta">
        {f.severity} · {f.category}
        {typeof f.confidence_score === "number" ? ` · ${f.confidence_score}% confidence` : ""}
      </div>
      <h5>{f.title}</h5>
      <p>{f.executive_summary || f.what_happened || f.description}</p>
      {f.root_cause && (
        <p>
          <strong>Root cause:</strong> {f.root_cause}
        </p>
      )}
      {fixes.length > 0 && (
        <ul>
          {fixes.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      )}
    </article>
  );
}

function CustomerImpactBlock({ coverage }: { coverage: Record<string, unknown> }) {
  const summary = (coverage?.impacted_customers_summary || null) as null | {
    headline?: string;
    customers?: { customer: string; failure_hits: number }[];
    top_apps?: { name: string; count: number }[];
    top_apis?: { name: string; count: number }[];
  };
  if (!summary) return null;
  return (
    <div className="section customer-impact">
      <h4>Who is impacted</h4>
      <p className="summary">
        <strong>{summary.headline || "Customer / partner impact from logs"}</strong>
      </p>
      {!!summary.customers?.length && (
        <ul>
          {summary.customers.slice(0, 12).map((c) => (
            <li key={c.customer}>
              {c.customer} — {c.failure_hits} failure hit{c.failure_hits === 1 ? "" : "s"}
            </li>
          ))}
        </ul>
      )}
      {!!summary.top_apps?.length && (
        <p>
          <strong>Top apps:</strong>{" "}
          {summary.top_apps
            .slice(0, 8)
            .map((a) => `${a.name} (${a.count})`)
            .join(", ")}
        </p>
      )}
      {!!summary.top_apis?.length && (
        <p>
          <strong>Top APIs:</strong>{" "}
          {summary.top_apis
            .slice(0, 8)
            .map((a) => `${a.name} (${a.count})`)
            .join(", ")}
        </p>
      )}
    </div>
  );
}

function FileStatsBlock({ coverage }: { coverage: Record<string, unknown> }) {
  const rows = (coverage?.file_stats || []) as {
    file?: string;
    display_name?: string;
    ip?: string | null;
    product?: string;
    log_type?: string;
    is_simosa?: boolean;
    app?: string;
    total_transactions?: number;
    total_success?: number;
    total_errors?: number;
    error_pct?: number;
    time_range?: string;
    top_status_codes?: { code: string; count: number }[];
    top_failure_messages?: { message: string; count: number }[];
    top_apis?: { api: string; count: number }[];
  }[];
  if (!rows.length) return null;
  const fmt = (n?: number) => (n ?? 0).toLocaleString();
  return (
    <div className="section file-stats">
      <h4>Per log file</h4>
      <p className="empty">Each file mapped to one node IP — total transactions, success, errors, and error %.</p>
      <div className="file-stat-grid">
        {rows.map((row) => (
          <article className="file-stat-card" key={row.file || row.display_name}>
            <div className="file-stat-head">
              <strong>{row.display_name || row.file}</strong>
              <code>{row.ip || "IP not mapped"}</code>
            </div>
            <p className="empty">
              {row.is_simosa ? <span className="badge-simosa">SIMOSA</span> : null}
              {row.app && row.app !== "SIMOSA" ? `${row.app} · ` : ""}
              {row.product}{row.log_type ? ` · ${row.log_type}` : ""}
              {row.time_range ? <span className="stat-timerange"> · {row.time_range}</span> : null}
            </p>
            <ul className="file-stat-metrics">
              <li>
                <span>Total transac</span>
                <strong>{fmt(row.total_transactions)}</strong>
              </li>
              <li>
                <span>Success</span>
                <strong className="ok-val">{fmt(row.total_success)}</strong>
              </li>
              <li>
                <span>Error (KO)</span>
                <strong className="err-val">{fmt(row.total_errors)}</strong>
              </li>
            </ul>
            <div className="file-stat-pct">
              Error rate <strong
                style={{ color: Number(row.error_pct || 0) > 10 ? "var(--crit)" : Number(row.error_pct || 0) > 3 ? "var(--high)" : "inherit" }}
              >{Number(row.error_pct || 0).toFixed(2)}%</strong>
            </div>
            {row.top_status_codes && row.top_status_codes.length > 0 && (
              <div className="stat-breakdown">
                <span className="stat-breakdown-title">Top KO codes</span>
                <ul>
                  {row.top_status_codes.slice(0, 4).map((c) => (
                    <li key={c.code}><code>{c.code}</code> × {fmt(c.count)}</li>
                  ))}
                </ul>
              </div>
            )}
            {row.top_failure_messages && row.top_failure_messages.length > 0 && (
              <div className="stat-breakdown">
                <span className="stat-breakdown-title">Top failure reasons</span>
                <ul>
                  {row.top_failure_messages.slice(0, 3).map((m) => (
                    <li key={m.message} title={m.message}>
                      {m.message.length > 48 ? m.message.slice(0, 48) + "…" : m.message}
                      {" "}× {fmt(m.count)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {row.top_apis && row.top_apis.length > 0 && (
              <div className="stat-breakdown">
                <span className="stat-breakdown-title">APIs</span>
                <ul>
                  {row.top_apis.slice(0, 4).map((a) => (
                    <li key={a.api}><code>{a.api}</code> × {fmt(a.count)}</li>
                  ))}
                </ul>
              </div>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}

function Wso2ErrorCard({ e }: { e: Wso2ErrorItem }) {
  return (
    <article className={`finding ${e.severity}`}>
      <div className="meta">
        {e.severity} · {e.log_type}
        {e.subsystem ? ` · ${e.subsystem}` : ""} · {e.confidence_score}%
      </div>
      <h5>{e.error}</h5>
      {e.technical_name && e.technical_name !== e.error && (
        <p className="empty" style={{ marginTop: 0 }}>
          Technical signal: {e.technical_name}
          {e.exception_type ? ` · ${e.exception_type}` : ""}
        </p>
      )}
      {typeof e.failure_count === "number" && typeof e.failure_total === "number" && (
        <p>
          <strong>Impact:</strong> {e.failure_count} of {e.failure_total} failures
          {typeof e.impact_pct === "number" ? ` (${e.impact_pct}%)` : ""}
          {e.impact_summary ? ` — ${e.impact_summary}` : ""}
        </p>
      )}
      {e.plain_meaning && (
        <p>
          <strong>In plain words:</strong> {e.plain_meaning}
        </p>
      )}
      {!!e.call_flow?.length && (
        <div>
          <strong>Small call flow:</strong>
          <ol className="call-flow">
            {e.call_flow.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </div>
      )}
      {!!e.impacted_customers?.length && (
        <p>
          <strong>Impacted customers / partners:</strong> {e.impacted_customers.join(", ")}
        </p>
      )}
      {!!e.config_checks?.length && (
        <div>
          <strong>Configs to check (and what to set):</strong>
          <ul>
            {e.config_checks.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
      <p>
        <strong>Description:</strong> {e.description}
      </p>
      <p>
        <strong>Possible occurrence:</strong> {e.possible_occurrence}
      </p>
      {e.evidence && (
        <p>
          <strong>Evidence:</strong> {e.evidence}
        </p>
      )}
      {!!e.affected_components?.length && (
        <p>
          <strong>Affected:</strong> {e.affected_components.join(", ")}
        </p>
      )}
      <div>
        <strong>Remedial actions:</strong>
        <ul>
          {e.remedial_actions.map((a) => (
            <li key={a}>{a}</li>
          ))}
        </ul>
      </div>
      {!!e.wso2_doc_refs?.length && (
        <p>
          <strong>Docs:</strong>{" "}
          {e.wso2_doc_refs.map((d) => (
            <a key={d} href={d} target="_blank" rel="noreferrer">
              WSO2 logging guide
            </a>
          ))}
        </p>
      )}
      {e.source_file && <code>{e.source_file}</code>}
    </article>
  );
}

const LOG_HINTS = [
  "wso2carbon.log",
  "audit.log",
  "http_access.log",
  "wire.log",
  "wire_tls.log",
  "gc.log",
  "heapdump.hprof",
  "catalina.out",
];

export default function App() {
  const [mode, setMode] = useState<"wso2" | "repo" | "live">("wso2");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [notes, setNotes] = useState("");
  const [osName, setOsName] = useState("Linux");
  const [apimVersion, setApimVersion] = useState("4.6.0");
  const [eiVersion, setEiVersion] = useState("4.5.0");
  const [ipAddresses, setIpAddresses] = useState(
    JSON.stringify(
      {
        apim: ["10.50.13.126", "10.50.13.127"],
        mi: ["10.50.13.126", "10.50.13.127", "10.50.13.128"],
      },
      null,
      0,
    ),
  );
  const [computeAlloc, setComputeAlloc] = useState(
    JSON.stringify({ vcpu: 16, ram_gb: 32, disk_gb: 235 }, null, 0),
  );
  const [computeUse, setComputeUse] = useState("");
  const [dbVersion, setDbVersion] = useState("MySQL 8.4.3-commercial");
  const [environment, setEnvironment] = useState("prod");
  const [logFiles, setLogFiles] = useState<FileList | null>(null);
  const [vaFile, setVaFile] = useState<File | null>(null);
  const [liveKind, setLiveKind] = useState<"ssh" | "local">("ssh");
  const [liveHost, setLiveHost] = useState("");
  const [livePort, setLivePort] = useState("22");
  const [liveUser, setLiveUser] = useState("");
  const [livePassword, setLivePassword] = useState("");
  const [liveKey, setLiveKey] = useState("");
  const [liveLogDir, setLiveLogDir] = useState("/opt/wso2am/repository/logs");
  const [liveExtraDirs, setLiveExtraDirs] = useState("/opt/wso2mi/repository/logs");
  const [livePoll, setLivePoll] = useState("5");
  const [liveReportMins, setLiveReportMins] = useState("3");
  const [liveState, setLiveState] = useState<LiveState | null>(null);
  const [liveBusy, setLiveBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [report, setReport] = useState<DevOpsReport | Wso2Report | null>(null);
  const [health, setHealth] = useState<{
    llm_configured: boolean;
    gitlab_configured: boolean;
    llm_provider?: string;
    llm_model?: string;
  } | null>(null);

  const activeJob = usePollingJob(activeJobId);

  const refresh = async () => {
    const [j, h] = await Promise.all([api.jobs(), api.health()]);
    setJobs(j.jobs);
    setHealth({
      llm_configured: h.llm_configured,
      gitlab_configured: h.gitlab_configured,
      llm_provider: h.llm_provider,
      llm_model: h.llm_model,
    });
  };

  useEffect(() => {
    refresh().catch((e) => setError(String(e.message || e)));
    const params = new URLSearchParams(window.location.search);
    const rid = params.get("report");
    if (rid) {
      api
        .report(rid)
        .then((r) => {
          setReport(r);
          setActiveJobId(r.job_id);
        })
        .catch((e) => setError(String(e.message || e)));
    }
  }, []);

  useEffect(() => {
    if (!activeJob) return;
    refresh().catch(() => undefined);
    if (activeJob.status === "completed" && activeJob.report_id) {
      api.report(activeJob.report_id).then(setReport).catch((e) => setError(String(e.message || e)));
    }
  }, [activeJob?.status, activeJob?.report_id, activeJob?.progress]);

  useEffect(() => {
    api
      .liveStatus()
      .then((s) => {
        if (s.connected) setLiveState(s);
      })
      .catch(() => undefined);
  }, []);

  const lastLiveReportRef = useRef<string | null>(null);

  useEffect(() => {
    if (!liveState?.connected) return;
    const es = new EventSource(api.liveStreamUrl());
    es.onmessage = (ev) => {
      try {
        const next = JSON.parse(ev.data) as LiveState;
        setLiveState(next);
        if (next.last_job_id) setActiveJobId(next.last_job_id);
        if (next.last_report_id && next.last_report_id !== lastLiveReportRef.current) {
          lastLiveReportRef.current = next.last_report_id;
          api.report(next.last_report_id).then(setReport).catch(() => undefined);
        }
      } catch {
        /* ignore malformed frames */
      }
    };
    return () => es.close();
  }, [liveState?.connected]);

  const parseMaybeJson = (raw: string) => {
    const t = raw.trim();
    if (!t) return undefined;
    try {
      return JSON.parse(t);
    } catch {
      return t;
    }
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    if (mode !== "live") setReport(null);
    try {
      if (mode === "live") {
        const extra = liveExtraDirs
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
          .filter((d) => d !== liveLogDir.trim());
        const mins = Number(liveReportMins) || 3;
        const res = await api.liveConnect({
          mode: liveKind,
          host: liveKind === "ssh" ? liveHost.trim() : undefined,
          port: Number(livePort) || 22,
          username: liveKind === "ssh" ? liveUser.trim() : undefined,
          password: livePassword || undefined,
          private_key: liveKey.trim() || undefined,
          log_dir: liveLogDir.trim(),
          extra_log_dirs: extra,
          poll_seconds: Number(livePoll) || 5,
          report_interval_seconds: Math.max(30, mins * 60),
          os_name: osName.trim() || undefined,
          apim_version: apimVersion.trim() || undefined,
          ei_version: eiVersion.trim() || undefined,
          ip_addresses: parseMaybeJson(ipAddresses),
          compute_allocation: parseMaybeJson(computeAlloc),
          db_version: dbVersion.trim() || undefined,
          notes: notes.trim() || undefined,
          environment: environment.trim() || undefined,
        });
        const status = await api.liveStatus();
        setLiveState(status);
        setError(null);
        if (res.message) {
          /* connection message shown via live board */
        }
      } else if (mode === "wso2") {
        if (!logFiles || logFiles.length === 0) {
          throw new Error("Upload WSO2 log files (all 8 types when available)");
        }
        const form = new FormData();
        if (osName.trim()) form.append("os", osName.trim());
        if (apimVersion.trim()) form.append("apim_version", apimVersion.trim());
        if (eiVersion.trim()) form.append("ei_version", eiVersion.trim());
        if (ipAddresses.trim()) form.append("ip_addresses", ipAddresses.trim());
        if (computeUse.trim()) form.append("infra_compute_consumption", computeUse.trim());
        if (computeAlloc.trim()) form.append("compute_allocation", computeAlloc.trim());
        if (dbVersion.trim()) form.append("db_version", dbVersion.trim());
        if (notes.trim()) form.append("notes", notes.trim());
        if (environment.trim()) form.append("environment", environment.trim());
        Array.from(logFiles).forEach((f) => form.append("log_files", f));
        if (vaFile) form.append("va_report", vaFile);
        const res = await api.wso2Analyze(form);
        setActiveJobId(res.job_id);
      } else {
        const job = await api.investigate({
          repo_url: repoUrl.trim(),
          branch: branch.trim() || undefined,
          notes: notes.trim() || undefined,
        });
        setActiveJobId(job.id);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const openJob = async (job: Job) => {
    setActiveJobId(job.id);
    setError(null);
    if (job.report_id) {
      try {
        setReport(await api.report(job.report_id));
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } else setReport(null);
  };

  const progressLabel = useMemo(() => {
    if (!activeJob) return null;
    return `${activeJob.status}${activeJob.progress ? ` — ${activeJob.progress}` : ""}`;
  }, [activeJob]);

  const handleLiveDisconnect = async () => {
    try {
      setLiveBusy(true);
      await api.liveDisconnect();
      setLiveState({ ...(liveState as LiveState), connected: false });
      setLiveState(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLiveBusy(false);
    }
  };

  const handleLiveAnalyzeNow = async () => {
    try {
      setLiveBusy(true);
      const res = await api.liveAnalyzeNow();
      if (res.job_id) setActiveJobId(res.job_id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLiveBusy(false);
    }
  };

  const isAnalyzing = useMemo(() => {
    if (mode === "live") return busy;
    if (busy) return true;
    if (!activeJob) return false;
    return !["completed", "failed", "cancelled"].includes(activeJob.status);
  }, [busy, activeJob, mode]);

  const [isStopping, setIsStopping] = useState(false);

  const handleStopJob = async () => {
    const targetId = activeJobId || activeJob?.id;
    if (!targetId) {
      setBusy(false);
      return;
    }
    try {
      setIsStopping(true);
      await api.stopJob(targetId);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsStopping(false);
      setBusy(false);
    }
  };

  const analyzingMessage = useMemo(() => {
    if (busy && !activeJobId) {
      return mode === "wso2" ? "Uploading logs and starting analysis…" : "Starting investigation…";
    }
    if (activeJob?.progress) return activeJob.progress;
    if (activeJob?.status === "queued") return "Queued — waiting to start…";
    if (activeJob?.status === "collecting") return "Scanning WSO2 logs…";
    if (activeJob?.status === "analyzing") return "Deep analysis in progress — correlating failures & customers…";
    if (activeJob?.status === "cloning") return "Cloning repository…";
    return mode === "wso2" ? "Analyzing WSO2 logs…" : "Investigating…";
  }, [busy, activeJobId, activeJob, mode]);

  // Progress bar — target % per status, auto-advance within each stage
  const [barPct, setBarPct] = useState(0);
  const barPctRef = useRef(0);

  useEffect(() => {
    const status = activeJob?.status ?? (busy ? "queued" : null);
    const done = activeJob?.status === "completed";
    const failed = activeJob?.status === "failed";
    const cancelled = activeJob?.status === "cancelled";

    if (!isAnalyzing && !done && !failed && !cancelled) {
      setBarPct(0);
      barPctRef.current = 0;
      return;
    }
    if (done) { setBarPct(100); barPctRef.current = 100; return; }
    if (failed || cancelled) { setBarPct(barPctRef.current || 50); return; }

    // Target ceilings per stage
    const ceiling =
      status === "queued" ? 12 :
      status === "collecting" ? 45 :
      status === "analyzing" ? 90 :
      status === "cloning" ? 20 : 10;

    const tick = () => {
      setBarPct((prev) => {
        if (prev >= ceiling) return prev;
        // Ease in to ceiling — fast at first, slow near limit
        const gap = ceiling - prev;
        const step = Math.max(0.15, gap * 0.04);
        const next = Math.min(prev + step, ceiling);
        barPctRef.current = next;
        return next;
      });
    };

    const id = setInterval(tick, 300);
    return () => clearInterval(id);
  }, [isAnalyzing, activeJob?.status, busy]);

  return (
    <div className="app">
      <header className="topbar">
        <h1 className="brand">
          AI <span>DevOps</span>
        </h1>
        <div className="status-pills">
          <span className={`pill ${health?.llm_configured ? "ok" : "warn"}`}>
            {health?.llm_configured
              ? `AI ${health.llm_provider || "llm"} · ${health.llm_model || "ready"}`
              : "Add Groq API key"}
          </span>
          {liveState?.connected && (
            <span className="pill ok">Live · {liveState.host || "localhost"}</span>
          )}
        </div>
      </header>

      <section className="hero-stage">
        <div className="hero-visual">
          <img
            src="/wso2-apim-mi-hero.png"
            alt="WSO2 API Manager and Micro Integrator log analysis"
          />
          <div className="hero-veil" />
          <div className="hero-overlay">
            <p className="hero-kicker">APIM gateway · Micro Integrator · live server RCA</p>
            <h2>WSO2 APIM + MI deep log analysis.</h2>
            <p>
              Connect to the server that writes carbon and access logs, or upload a snapshot.
              Live mode tails files, scrapes CPU/RAM, and regenerates AI reports as traffic arrives.
            </p>
            <div className="actions">
              <button type="button" className={mode === "wso2" ? "primary" : "ghost light"} onClick={() => setMode("wso2")}>
                WSO2 APIM / MI
              </button>
              <button type="button" className={mode === "live" ? "primary" : "ghost light"} onClick={() => setMode("live")}>
                Live server
              </button>
              <button type="button" className={mode === "repo" ? "primary" : "ghost light"} onClick={() => setMode("repo")}>
                Git repo
              </button>
            </div>
          </div>
        </div>

        <form className="panel form analyze-panel" onSubmit={onSubmit}>
          <div className="form-head">
            <h3>
              {mode === "live"
                ? "Connect to the log server"
                : mode === "wso2"
                  ? "Analyze APIM / MI logs"
                  : "Investigate git repository"}
            </h3>
            <p>
              {mode === "live"
                ? "SSH into the host (or watch a local path) where wso2carbon.log and http_access.log are written. Stats update every few seconds; a full AI report runs on a timer."
                : mode === "wso2"
                  ? "Defaults are prefilled for your environment — upload logs and run."
                  : "Paste a repo URL to investigate."}
            </p>
          </div>
          {mode === "live" ? (
            <>
              <div className="row">
                <label>
                  Connection
                  <select value={liveKind} onChange={(e) => setLiveKind(e.target.value as "ssh" | "local")}>
                    <option value="ssh">SSH to external server</option>
                    <option value="local">This machine (log directory)</option>
                  </select>
                </label>
                <label>
                  Environment
                  <input placeholder="prod" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
                </label>
              </div>
              {liveKind === "ssh" && (
                <>
                  <div className="row">
                    <label>
                      Server host
                      <input required placeholder="10.50.13.126 or apim.example.com" value={liveHost} onChange={(e) => setLiveHost(e.target.value)} />
                    </label>
                    <label>
                      SSH port
                      <input value={livePort} onChange={(e) => setLivePort(e.target.value)} />
                    </label>
                  </div>
                  <div className="row">
                    <label>
                      SSH username
                      <input required placeholder="wso2" value={liveUser} onChange={(e) => setLiveUser(e.target.value)} />
                    </label>
                    <label>
                      SSH password (optional if using a key)
                      <input type="password" autoComplete="off" value={livePassword} onChange={(e) => setLivePassword(e.target.value)} />
                    </label>
                  </div>
                  <label>
                    Private key (PEM paste, or local path like ~/.ssh/id_rsa)
                    <textarea rows={3} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={liveKey} onChange={(e) => setLiveKey(e.target.value)} />
                  </label>
                </>
              )}
              <div className="row">
                <label>
                  APIM log directory
                  <input required placeholder="/opt/wso2am/repository/logs" value={liveLogDir} onChange={(e) => setLiveLogDir(e.target.value)} />
                </label>
                <label>
                  Extra dirs (MI, comma-separated)
                  <input placeholder="/opt/wso2mi/repository/logs" value={liveExtraDirs} onChange={(e) => setLiveExtraDirs(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <label>
                  Poll every (seconds)
                  <input value={livePoll} onChange={(e) => setLivePoll(e.target.value)} />
                </label>
                <label>
                  AI report every (minutes)
                  <input value={liveReportMins} onChange={(e) => setLiveReportMins(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <label>
                  APIM version
                  <input value={apimVersion} onChange={(e) => setApimVersion(e.target.value)} />
                </label>
                <label>
                  MI / EI version
                  <input value={eiVersion} onChange={(e) => setEiVersion(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <label>
                  IP addresses (APIM + MI)
                  <input value={ipAddresses} onChange={(e) => setIpAddresses(e.target.value)} />
                </label>
                <label>
                  Compute allocation
                  <input value={computeAlloc} onChange={(e) => setComputeAlloc(e.target.value)} />
                </label>
              </div>
              <label>
                Notes
                <textarea rows={2} placeholder="Grid region, known incident window…" value={notes} onChange={(e) => setNotes(e.target.value)} />
              </label>
              <p className="empty">Expected on the server: {LOG_HINTS.join(" · ")}</p>
            </>
          ) : mode === "wso2" ? (
            <>
              <div className="row">
                <label>
                  OS
                  <input placeholder="RHEL 8.8 / Ubuntu 22.04" value={osName} onChange={(e) => setOsName(e.target.value)} />
                </label>
                <label>
                  Environment
                  <input placeholder="prod" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <label>
                  APIM version
                  <input placeholder="4.6.0" value={apimVersion} onChange={(e) => setApimVersion(e.target.value)} />
                </label>
                <label>
                  MI / EI version
                  <input placeholder="4.5.0" value={eiVersion} onChange={(e) => setEiVersion(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <label>
                  DB version
                  <input placeholder="MySQL 8.4.3-commercial" value={dbVersion} onChange={(e) => setDbVersion(e.target.value)} />
                </label>
                <label>
                  IP addresses (APIM + MI)
                  <input
                    placeholder='{"apim":["10.50.13.126"],"mi":["10.50.13.128"]}'
                    value={ipAddresses}
                    onChange={(e) => setIpAddresses(e.target.value)}
                  />
                </label>
              </div>
              <div className="row">
                <label>
                  Compute allocation
                  <textarea
                    rows={2}
                    placeholder='{"vcpu":16,"ram_gb":32,"disk_gb":235}'
                    value={computeAlloc}
                    onChange={(e) => setComputeAlloc(e.target.value)}
                  />
                </label>
                <label>
                  Infra compute consumption
                  <textarea
                    rows={2}
                    placeholder='{"cpu_pct":82,"ram_pct":91,"disk_pct":70}'
                    value={computeUse}
                    onChange={(e) => setComputeUse(e.target.value)}
                  />
                </label>
              </div>
              <label>
                APIM + MI log files (upload carbon logs from both products / nodes)
                <input type="file" multiple required={mode === "wso2"} onChange={(e) => setLogFiles(e.target.files)} />
              </label>
              <p className="empty">Expected: {LOG_HINTS.join(" · ")} — mix APIM and MI files in one run</p>
              <label>
                Vulnerability Assessment report (optional)
                <input type="file" accept=".txt,.md,.json,.pdf,.csv,.log" onChange={(e) => setVaFile(e.target.files?.[0] || null)} />
              </label>
              <label>
                Notes
                <textarea rows={2} placeholder="Incident window, recent deploy, patch level…" value={notes} onChange={(e) => setNotes(e.target.value)} />
              </label>
            </>
          ) : (
            <>
              <label>
                Git / GitLab repository URL
                <input required placeholder="https://gitlab.com/group/project.git" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} />
              </label>
              <label>
                Branch
                <input placeholder="main" value={branch} onChange={(e) => setBranch(e.target.value)} />
              </label>
              <label>
                Notes
                <textarea rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} />
              </label>
            </>
          )}
          <div className="actions">
            <button className="primary" type="submit" disabled={isAnalyzing || liveBusy || (mode === "live" && !!liveState?.connected)}>
              {isAnalyzing ? (
                <>
                  <span className="btn-spinner" aria-hidden="true" />
                  {mode === "live" ? "Connecting…" : "Analyzing…"}
                </>
              ) : mode === "live" ? (
                liveState?.connected ? "Connected" : "Connect live"
              ) : mode === "wso2" ? (
                "Analyze WSO2 logs"
              ) : (
                "Investigate repo"
              )}
            </button>
            {mode === "live" && liveState?.connected && (
              <button className="danger" type="button" onClick={handleLiveDisconnect} disabled={liveBusy}>
                Disconnect
              </button>
            )}
            {isAnalyzing && mode !== "live" && (
              <button
                className="danger"
                type="button"
                onClick={handleStopJob}
                disabled={isStopping}
                title="Stop current analysis"
              >
                {isStopping ? (
                  <>
                    <span className="btn-spinner" aria-hidden="true" />
                    Stopping…
                  </>
                ) : (
                  "Stop analysis"
                )}
              </button>
            )}
            <button className="ghost" type="button" onClick={() => refresh()} disabled={isAnalyzing}>
              Refresh
            </button>
          </div>
          {(mode !== "live" && (isAnalyzing || activeJob?.status === "completed" || activeJob?.status === "failed" || activeJob?.status === "cancelled")) && (
            <div
              className={`progress-bar-wrap${
                activeJob?.status === "completed"
                  ? " done"
                  : activeJob?.status === "failed"
                  ? " failed"
                  : activeJob?.status === "cancelled"
                  ? " cancelled"
                  : ""
              }`}
              role="progressbar"
              aria-valuenow={Math.round(barPct)}
              aria-valuemin={0}
              aria-valuemax={100}
            >
              <div className="progress-bar-track">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${barPct}%` }}
                />
              </div>
              <span className="progress-bar-label">
                {activeJob?.status === "completed"
                  ? "✓ Analysis complete"
                  : activeJob?.status === "failed"
                  ? "Analysis failed"
                  : activeJob?.status === "cancelled"
                  ? "✕ Analysis stopped"
                  : `${Math.round(barPct)}%`}
              </span>
            </div>
          )}
          {isAnalyzing && mode !== "live" && (
            <div className="analyze-loader" role="status" aria-live="polite">
              <span className="analyze-spinner" aria-hidden="true" />
              <div className="analyze-loader-content">
                <strong>Analyzing{mode === "wso2" ? " WSO2 logs" : ""}…</strong>
                <p>{analyzingMessage}</p>
                {progressLabel && <p className="analyze-loader-meta">{progressLabel}</p>}
              </div>
              <button
                className="stop-btn"
                type="button"
                onClick={handleStopJob}
                disabled={isStopping}
                title="Stop analysis"
              >
                {isStopping ? "Stopping…" : "Stop"}
              </button>
            </div>
          )}
          {!isAnalyzing && activeJob?.status === "completed" && (
            <p className="empty">{progressLabel}</p>
          )}
          {!isAnalyzing && activeJob?.status === "cancelled" && (
            <p className="empty" style={{ color: "var(--high, #c45c26)" }}>
              {progressLabel || "Analysis stopped by user."}
            </p>
          )}
          {activeJob?.status === "failed" && activeJob.error && (
            <p className="error">
              {activeJob.error.split("\n").find((line) => line.trim()) || activeJob.error}
            </p>
          )}
          {error && <p className="error">{error}</p>}
        </form>
      </section>

      {liveState?.connected && (
        <section className="panel live-wrap">
          <LiveSnapshotPanel
            state={liveState}
            onAnalyzeNow={handleLiveAnalyzeNow}
            analyzingNow={liveBusy}
          />
        </section>
      )}

      <div className="layout">
        <aside className="panel">
          <h3 className="section-title">Investigations</h3>
          {jobs.length === 0 && <p className="empty">No jobs yet.</p>}
          {jobs.map((job) => (
            <div className="job" key={job.id} onClick={() => openJob(job)}>
              <div className="job-url">{job.repo_url}</div>
              <div className="job-meta">
                <span className={`badge ${job.status}`}>{job.status}</span>
                <span>{job.trigger}</span>
                <span>{new Date(job.created_at).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </aside>

        <main className="panel">
          <h3 className="section-title">Report</h3>
          {isAnalyzing && !report && mode !== "live" && (
            <div className="analyze-loader report-loader" role="status" aria-live="polite">
              <span className="analyze-spinner" aria-hidden="true" />
              <div className="analyze-loader-content">
                <strong>Building investigation report…</strong>
                <p>{analyzingMessage}</p>
              </div>
              <button
                className="stop-btn"
                type="button"
                onClick={handleStopJob}
                disabled={isStopping}
                title="Stop analysis"
              >
                {isStopping ? "Stopping…" : "Stop"}
              </button>
            </div>
          )}
          {!report && !isAnalyzing && (
            <p className="empty">
              {liveState?.connected
                ? liveState.analyzing
                  ? "First live AI report is running — numbers above update immediately."
                  : "Live stats are streaming. An AI report will appear here when the first window is analyzed."
                : "Select a completed investigation."}
            </p>
          )}
          {report && isWso2Report(report) && (
            <>
              <div className="report-head">
                <div>
                  <strong>WSO2 APIM analysis</strong>
                  <div className="job-meta">
                    <span className={`badge ${report.risk_level}`}>{report.risk_level}</span>
                    <span>APIM {(report.context as { apim_version?: string }).apim_version || "n/a"}</span>
                    <span>#{report.id}</span>
                  </div>
                </div>
                <div className="score-ring" style={{ ["--p" as string]: report.health_score }}>
                  {report.health_score}
                </div>
              </div>
              <p className="summary">{report.executive_summary}</p>
              {report.primary_root_cause && (
                <p className="summary">
                  <strong>Primary root cause:</strong> {report.primary_root_cause}
                </p>
              )}
              <CustomerImpactBlock coverage={report.log_coverage} />
              <FileStatsBlock coverage={report.log_coverage} />
              {!!report.doc_references?.length && (
                <p className="empty">
                  Docs:{" "}
                  <a href={report.doc_references[0]} target="_blank" rel="noreferrer">
                    Configuring Logging (APIM)
                  </a>
                </p>
              )}
              <ReportShareBar report={report} />
              <ReportCharts
                severityItems={report.errors}
                issueItems={report.errors.map((e) => ({
                  error: e.error,
                  severity: e.severity,
                  confidence_score: e.confidence_score,
                }))}
              />
              <div className="section">
                <h4>Errors ({report.errors.length})</h4>
                {report.errors.map((e) => (
                  <Wso2ErrorCard key={e.id} e={e} />
                ))}
              </div>
              {!!report.va_correlations?.length && (
                <div className="section">
                  <h4>VA correlations</h4>
                  {report.va_correlations.map((v) => (
                    <article className={`finding ${v.risk}`} key={v.va_finding}>
                      <h5>{v.va_finding}</h5>
                      <p>{v.correlation_notes}</p>
                      <p>
                        <strong>Related errors:</strong> {v.related_log_errors.join(", ") || "n/a"}
                      </p>
                      <ul>
                        {v.recommended_actions.map((a) => (
                          <li key={a}>{a}</li>
                        ))}
                      </ul>
                    </article>
                  ))}
                </div>
              )}
              {!!report.roadmap?.length && (
                <div className="section">
                  <h4>Roadmap</h4>
                  <ol>
                    {report.roadmap.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ol>
                </div>
              )}
            </>
          )}
          {report && !isWso2Report(report) && (
            <>
              <p className="summary">{report.executive_summary}</p>
              <ReportShareBar report={report} />
              <ReportCharts
                severityItems={report.sections.flatMap((s) => s.findings)}
                issueItems={report.sections.flatMap((s) =>
                  s.findings.map((f) => ({
                    title: f.title,
                    severity: f.severity,
                    confidence_score: f.confidence_score,
                  })),
                )}
              />
              {report.sections.map((section) => (
                <div className="section" key={section.title}>
                  <h4>{section.title}</h4>
                  {section.findings.map((f) => (
                    <FindingCard key={f.id} f={f} />
                  ))}
                </div>
              ))}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
