import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  api,
  DevOpsReport,
  Finding,
  isWso2Report,
  Job,
  Wso2ErrorItem,
  Wso2Report,
} from "./api";
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
        if (j.status === "completed" || j.status === "failed") return;
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
  const [mode, setMode] = useState<"wso2" | "repo">("wso2");
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

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    setReport(null);
    try {
      if (mode === "wso2") {
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

  const isAnalyzing = useMemo(() => {
    if (busy) return true;
    if (!activeJob) return false;
    return !["completed", "failed"].includes(activeJob.status);
  }, [busy, activeJob]);

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
            <p className="hero-kicker">APIM gateway · Micro Integrator · carbon log RCA</p>
            <h2>WSO2 APIM + MI deep log analysis.</h2>
            <p>
              Upload APIM and MI carbon logs, add infra context, and get LLM-only RCA with remediations,
              severity charts, and shareable HTML reports.
            </p>
            <div className="actions">
              <button type="button" className={mode === "wso2" ? "primary" : "ghost light"} onClick={() => setMode("wso2")}>
                WSO2 APIM / MI
              </button>
              <button type="button" className={mode === "repo" ? "primary" : "ghost light"} onClick={() => setMode("repo")}>
                Git repo
              </button>
            </div>
          </div>
        </div>

        <form className="panel form analyze-panel" onSubmit={onSubmit}>
          <div className="form-head">
            <h3>{mode === "wso2" ? "Analyze APIM / MI logs" : "Investigate git repository"}</h3>
            <p>{mode === "wso2" ? "Defaults are prefilled for your environment — upload logs and run." : "Paste a repo URL to investigate."}</p>
          </div>
          {mode === "wso2" ? (
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
                <input type="file" multiple required onChange={(e) => setLogFiles(e.target.files)} />
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
            <button className="primary" type="submit" disabled={isAnalyzing}>
              {isAnalyzing ? (
                <>
                  <span className="btn-spinner" aria-hidden="true" />
                  Analyzing…
                </>
              ) : mode === "wso2" ? (
                "Analyze WSO2 logs"
              ) : (
                "Investigate repo"
              )}
            </button>
            <button className="ghost" type="button" onClick={() => refresh()} disabled={isAnalyzing}>
              Refresh
            </button>
          </div>
          {isAnalyzing && (
            <div className="analyze-loader" role="status" aria-live="polite">
              <span className="analyze-spinner" aria-hidden="true" />
              <div>
                <strong>Analyzing{mode === "wso2" ? " WSO2 logs" : ""}…</strong>
                <p>{analyzingMessage}</p>
                {progressLabel && <p className="analyze-loader-meta">{progressLabel}</p>}
              </div>
            </div>
          )}
          {!isAnalyzing && progressLabel && <p className="empty">{progressLabel}</p>}
          {error && <p className="error">{error}</p>}
        </form>
      </section>

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
          {isAnalyzing && !report && (
            <div className="analyze-loader report-loader" role="status" aria-live="polite">
              <span className="analyze-spinner" aria-hidden="true" />
              <div>
                <strong>Building investigation report…</strong>
                <p>{analyzingMessage}</p>
              </div>
            </div>
          )}
          {!report && !isAnalyzing && <p className="empty">Select a completed investigation.</p>}
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
