# AI DevOps

Paste a Git / GitLab repository URL. The platform clones it, collects DevOps evidence (software stack, Docker, CI/CD, secrets heuristics, IPs/ports, logs), runs an AI investigation, and produces a structured report with errors, security findings, improvements, and a roadmap.

On every GitLab push or merge request, a webhook can trigger the same pipeline automatically.

## WSO2 API Manager log analysis

Dedicated mode for the standard APIM log set under `<APIM_HOME>/repository/logs/`  
([Configuring Logging](https://apim.docs.wso2.com/en/4.3.0/administer/logging-and-monitoring/logging/configuring-logging/)):

| Log file | Purpose |
|---|---|
| `wso2carbon.log` | Main server log |
| `audit.log` | Admin audit events |
| `http_access.log` | HTTP access (IP/URI/status/latency) |
| `wire.log` | Raw HTTP >>/<< (debug) |
| `wire_tls.log` | TLS handshake troubleshooting |
| `gc.log` | JVM GC / memory |
| `heapdump.hprof` | OOM heap dump |
| `catalina.out` | Tomcat/JVM console |

### Inputs
OS · APIM version · EI version · IP addresses · all log types · infra compute consumption · compute allocation · DB version · optional VA report

### Outputs (LLM-only)
For each issue: **Error**, **Description**, **Possible occurrence**, **Remedial actions** (with WSO2 doc refs), plus **VA report correlation**.

```bash
curl -X POST http://localhost:8000/api/wso2/analyze \
  -F os='RHEL 8.8' \
  -F apim_version='4.3.0' \
  -F ei_version='8.2.0' \
  -F db_version='PostgreSQL 14' \
  -F ip_addresses='{"gateway":"10.0.1.10"}' \
  -F compute_allocation='{"vcpu":8,"ram_gb":32}' \
  -F infra_compute_consumption='{"cpu_pct":85,"ram_pct":90}' \
  -F log_files=@/path/wso2carbon.log \
  -F log_files=@/path/audit.log \
  -F log_files=@/path/http_access.log \
  -F va_report=@/path/va-report.txt
```

UI: open the dashboard → **WSO2 APIM** tab.

### EI/MI reading model (no error-code catalog)

Carbon logs are interpreted as:

`Timestamp | Level | Logger (Java class) | Message | Exception`

Primary signals: **logger** + **exception type** (not a global error code). Subsystems are classified from namespaces such as `org.apache.synapse*`, `org.apache.axis2`, `org.wso2.micro.integrator`, `org.apache.commons.dbcp`, connectors (JMS/Kafka/DB/File/SMTP/RabbitMQ), etc.

| Capability | Details |
|---|---|
| **Repo investigation** | Clone any Git URL (public or private with `GITLAB_TOKEN`) |
| **Software inventory** | Languages, manifests (`package.json`, `requirements.txt`, `go.mod`, …) |
| **Containers** | Dockerfiles, Compose services, images, exposed ports |
| **CI/CD & IaC** | `.gitlab-ci.yml`, GitHub Actions, Jenkins, Terraform/Helm hints |
| **Security** | Secret patterns, risky files, TLS-skip signals, lockfile hygiene |
| **Network / IP** | IPs, hosts, ports from configs + optional user-provided IP JSON |
| **Logs** | Upload logs or discover `*.log` files; extract error/warning tails |
| **AI report** | Health score, severity-ranked findings, quick wins, 30/60/90 roadmap |
| **GitLab automation** | `POST /api/webhooks/gitlab` on push / MR events |
| **Exports** | Markdown, HTML, JSON |

Without `LLM_API_KEY` / `GROQ_API_KEY`, investigations fail until a free Groq key is configured (no hardcoded reports).
## Quick start (local)

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # edit LLM_API_KEY / GitLab settings
export PYTHONPATH=.
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### 3. Investigate via API

```bash
curl -X POST http://localhost:8000/api/investigate \
  -H 'Content-Type: application/json' \
  -d '{
    "repo_url": "https://github.com/encode/httpx.git",
    "notes": "Public sample investigation",
    "software_info": {"owner": "platform-team"},
    "ip_info": {"env": "staging"}
  }'
```

Poll `GET /api/jobs/{id}` until `status=completed`, then `GET /api/reports/{report_id}`.

## Docker Compose

```bash
cp .env.example .env
# set LLM_API_KEY and GITLAB_WEBHOOK_SECRET
docker compose up --build
```

- UI: http://localhost:3000  
- API docs: http://localhost:8000/docs  

## GitLab webhook automation

1. Set a strong `GITLAB_WEBHOOK_SECRET` in `.env`.
2. In GitLab → **Settings → Webhooks**:
   - URL: `https://<your-host>/api/webhooks/gitlab`
   - Secret token: same as `GITLAB_WEBHOOK_SECRET`
   - Triggers: **Push events**, **Merge request events**
3. For private repos, set `GITLAB_TOKEN` (read_repository scope).

On each push/MR, AI DevOps queues an investigation and stores a new report.

Example local test payload:

```bash
curl -X POST http://localhost:8000/api/webhooks/gitlab \
  -H 'Content-Type: application/json' \
  -H 'X-Gitlab-Token: change-me-to-a-long-random-string' \
  -d '{
    "object_kind": "push",
    "ref": "refs/heads/main",
    "user_name": "demo",
    "project": {
      "git_http_url": "https://github.com/encode/httpx.git",
      "web_url": "https://github.com/encode/httpx"
    },
    "commits": [{"id": "abc12345", "message": "demo push"}]
  }'
```

## Optional inputs

| Field | Purpose |
|---|---|
| `notes` | Free-text infra context, incidents, SLAs |
| `software_info` | Extra runtime / OS / version facts (JSON) |
| `ip_info` | Public IPs, VPC CIDRs, load balancers (JSON) |
| `metrics` | CPU/mem/latency/error-rate / alert snapshots (JSON) |
| `business_metrics` | Login/payment/order failures, active users (JSON) |
| `live_probe` | Probe local Docker, kubectl, host health |
| log uploads | `POST /api/investigate/with-logs` multipart |

## SRE investigation domains

Collectors + AI correlate across:

1. Application logs · 2. Infrastructure metrics · 3. Kubernetes · 4. Docker  
5. CI/CD · 6. Git history · 7. Server health · 8. Web servers · 9. Databases  
10. API reliability · 11. Security · 12. Performance · 13. Monitoring platforms  
14. Alerts · 15. Source/IaC · 16. Build quality · 17. Cloud · 18. Business metrics

Each finding includes: executive summary, severity, affected services, what happened, root cause, evidence, impact, recommended fixes, preventive measures, related components, and confidence score (0–100%).

## Architecture

```
frontend (React) ──► FastAPI
                       ├── collectors (git, software, docker, ci, security, network, logs)
                       ├── AI analyzer (OpenAI-compatible LLM)
                       ├── report renderer (md/html/json)
                       └── GitLab webhook → job queue
```

Data lands in `./data` (workspace clones, uploads, reports, SQLite).

## LLM providers (AI-only reports)

Reports are **LLM-only** — hardcoded / heuristic findings are disabled.

### Recommended (free): Groq + Llama 3.3 70B

Best fit for AI DevOps: open-source model, free API key, fast inference, strong reasoning.

1. Create a free key: https://console.groq.com/keys  
2. Put it in `.env`:

```env
LLM_API_KEY=gsk_your_key_here
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=llama-3.3-70b-versatile
```

3. Verify:

```bash
chmod +x scripts/test_llm.sh
./scripts/test_llm.sh
```

4. Restart the API.

Without a key, investigations **fail** with a clear error (they will not invent a fake report).

### Other free options

| Option | Config |
|---|---|
| Groq Llama 8B (faster, higher free limits) | `LLM_MODEL=llama-3.1-8b-instant` |
| Groq Llama 4 Scout (more context) | `LLM_MODEL=meta-llama/llama-4-scout-17b-16e-instruct` |
| Local Ollama | `LLM_BASE_URL=http://127.0.0.1:11434/v1` · `LLM_API_KEY=ollama` · `LLM_MODEL=llama3.1` |
## Project layout

```
aidev/
├── backend/app/          # FastAPI application
├── frontend/             # Vite + React dashboard
├── data/                 # runtime storage
├── docker-compose.yml
└── .env.example
```

## Security notes

- Treat webhook secrets and GitLab tokens as credentials.
- Secret scanning is **heuristic** — always verify and rotate real leaks.
- Prefer running against staging clones; production secrets should never live in git.
