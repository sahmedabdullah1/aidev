"""Database, web server, cloud/IaC, quality, and monitoring config collectors."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.config import Settings

SKIP = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}


def _iter_files(repo_path: Path, settings: Settings):
    n = 0
    for path in repo_path.rglob("*"):
        if n >= settings.max_files_scanned:
            break
        if not path.is_file() or any(p in SKIP for p in path.parts):
            continue
        n += 1
        yield path


def collect_database_signals(repo_path: Path, settings: Settings) -> dict[str, Any]:
    configs: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    engines: set[str] = set()
    patterns = {
        "postgres": re.compile(r"(?i)(postgres|postgresql|psycopg|sqlalchemy)"),
        "mysql": re.compile(r"(?i)(mysql|mariadb|pymysql)"),
        "mongodb": re.compile(r"(?i)(mongodb|mongoose|pymongo)"),
        "redis": re.compile(r"(?i)\bredis\b"),
    }
    pool_re = re.compile(r"(?i)(pool_size|max_connections|connection.?pool|maxPoolSize)")
    slow_re = re.compile(r"(?i)(slow.?query|deadlock|lock wait|too many connections)")

    for path in _iter_files(repo_path, settings):
        name = path.name.lower()
        if name in {"my.cnf", "postgresql.conf", "redis.conf", "mongod.conf"} or "migration" in str(path).lower():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
            except OSError:
                continue
            configs.append({"path": str(path.relative_to(repo_path)), "preview": text[:1500]})
        if path.suffix.lower() not in {".py", ".js", ".ts", ".go", ".java", ".yml", ".yaml", ".env", ".toml", ".properties", ".sql"}:
            continue
        if path.stat().st_size > settings.max_file_bytes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(repo_path))
        for eng, rx in patterns.items():
            if rx.search(text):
                engines.add(eng)
        if pool_re.search(text):
            configs.append({"path": rel, "signal": "connection_pool_config", "preview": text[:800]})
        if slow_re.search(text):
            issues.append({"type": "db_error_signal", "severity": "high", "path": rel, "detail": "DB lock/slow-query/connection failure signal in code/config"})
        if re.search(r"(?i)sslmode\s*=\s*disable|ssl\s*=\s*false", text):
            issues.append({"type": "db_ssl_disabled", "severity": "high", "path": rel, "detail": "Database SSL appears disabled"})

    return {"engines": sorted(engines), "configs": configs[:40], "issues": issues[:40]}


def collect_webserver(repo_path: Path, settings: Settings) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    names = {"nginx.conf", "default.conf", "httpd.conf", ".htaccess", "Caddyfile"}
    for path in _iter_files(repo_path, settings):
        rel = str(path.relative_to(repo_path))
        if path.name in names or "nginx" in rel.lower() or "apache" in rel.lower():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
            except OSError:
                continue
            files.append({"path": rel, "preview": text[:2500]})
            if re.search(r"(?i)ssl_certificate|listen\s+443", text) is None and "server" in text.lower():
                issues.append({"type": "possible_no_tls", "severity": "medium", "path": rel, "detail": "Web server config may lack TLS listeners"})
            if re.search(r"(?i)proxy_pass\s+http://", text):
                issues.append({"type": "http_upstream", "severity": "low", "path": rel, "detail": "Reverse proxy uses HTTP upstream — ensure internal-only"})
    return {"configs": files[:30], "issues": issues[:30], "has_webserver_config": bool(files)}


def collect_cloud_iac(repo_path: Path, settings: Settings) -> dict[str, Any]:
    files: list[str] = []
    providers: set[str] = set()
    issues: list[dict[str, Any]] = []
    for path in _iter_files(repo_path, settings):
        rel = str(path.relative_to(repo_path))
        if path.suffix == ".tf" or path.name in {"serverless.yml", "template.yaml", "cloudformation.yml", "main.tf", "cdk.json"}:
            files.append(rel)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[: settings.max_file_bytes]
            except OSError:
                continue
            if "aws_" in text or "provider \"aws\"" in text:
                providers.add("AWS")
            if "azurerm_" in text or "provider \"azurerm\"" in text:
                providers.add("Azure")
            if "google_" in text or "provider \"google\"" in text:
                providers.add("GCP")
            if re.search(r'(?i)cidr_block\s*=\s*"0\.0\.0\.0/0"|0\.0\.0\.0/0', text):
                issues.append({"type": "open_cidr", "severity": "high", "path": rel, "detail": "Open 0.0.0.0/0 found in IaC"})
            if re.search(r"(?i)acl\s*=\s*[\"']public-read", text):
                issues.append({"type": "public_bucket", "severity": "critical", "path": rel, "detail": "Possibly public object storage ACL"})
    return {"iac_files": files[:80], "providers": sorted(providers), "issues": issues[:40]}


def collect_quality(repo_path: Path, settings: Settings) -> dict[str, Any]:
    tests: list[str] = []
    quality_files: list[str] = []
    issues: list[dict[str, Any]] = []
    for path in _iter_files(repo_path, settings):
        rel = str(path.relative_to(repo_path))
        low = rel.lower()
        if any(x in low for x in ("/test/", "/tests/", "_test.", ".spec.", ".test.", "/__tests__/")):
            tests.append(rel)
        if path.name in {
            "sonar-project.properties",
            "coverage.xml",
            ".coveragerc",
            "pytest.ini",
            "jest.config.js",
            "jest.config.ts",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.cjs",
            "eslint.config.js",
            "ruff.toml",
            ".golangci.yml",
        }:
            quality_files.append(rel)
    if not tests:
        issues.append({"type": "no_tests", "severity": "high", "path": None, "detail": "No obvious unit/integration tests discovered"})
    if not quality_files:
        issues.append({"type": "no_quality_gates", "severity": "medium", "path": None, "detail": "No lint/coverage/Sonar config found"})
    return {
        "test_files": tests[:80],
        "quality_configs": quality_files[:40],
        "test_file_count": len(tests),
        "issues": issues,
    }


def collect_monitoring_configs(repo_path: Path, settings: Settings) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    platforms: set[str] = set()
    issues: list[dict[str, Any]] = []
    markers = {
        "prometheus": re.compile(r"(?i)prometheus|scrape_configs"),
        "grafana": re.compile(r"(?i)grafana"),
        "loki": re.compile(r"(?i)\bloki\b"),
        "elk": re.compile(r"(?i)elasticsearch|logstash|kibana|opensearch"),
        "datadog": re.compile(r"(?i)datadog"),
        "newrelic": re.compile(r"(?i)newrelic|new_relic"),
        "dynatrace": re.compile(r"(?i)dynatrace"),
        "otel": re.compile(r"(?i)opentelemetry|otel"),
        "alertmanager": re.compile(r"(?i)alertmanager|alerting_rules"),
    }
    for path in _iter_files(repo_path, settings):
        if path.stat().st_size > settings.max_file_bytes:
            continue
        if path.suffix.lower() not in {".yml", ".yaml", ".json", ".toml", ".conf", ".py", ".ts", ".js", ".tf"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = [name for name, rx in markers.items() if rx.search(text)]
        if not hits:
            continue
        rel = str(path.relative_to(repo_path))
        for h in hits:
            platforms.add(h)
        files.append({"path": rel, "platforms": hits, "preview": text[:1200]})
    if not platforms:
        issues.append({"type": "no_monitoring", "severity": "high", "path": None, "detail": "No Prometheus/Grafana/ELK/Datadog/OTel signals found"})
    return {"platforms": sorted(platforms), "configs": files[:40], "issues": issues}


def collect_app_log_patterns(repo_path: Path, settings: Settings, uploaded_summaries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Classify application failure modes from logs and code."""
    buckets = {
        "exceptions": 0,
        "auth_failures": 0,
        "api_failures": 0,
        "database_errors": 0,
        "payment_failures": 0,
        "slow_requests": 0,
        "missing_env": 0,
        "memory_pressure": 0,
    }
    samples: dict[str, list[str]] = {k: [] for k in buckets}
    patterns = {
        "exceptions": re.compile(r"(?i)(exception|traceback|fatal|panic|segfault)"),
        "auth_failures": re.compile(r"(?i)(unauthorized|authentication failed|invalid token|login failed|401)"),
        "api_failures": re.compile(r"(?i)(api (error|failed)|5\d\d|bad gateway|gateway timeout)"),
        "database_errors": re.compile(r"(?i)(sqlalchemy|postgres|mysql|mongodb|deadlock|connection refused.*(db|sql|redis|mongo))"),
        "payment_failures": re.compile(r"(?i)(payment failed|stripe|paypal|card declined|checkout error)"),
        "slow_requests": re.compile(r"(?i)(slow request|took \d{4,}ms|timeout|deadline exceeded)"),
        "missing_env": re.compile(r"(?i)(missing (env|environment)|keyerror.*(env|config)|undefined env|required env)"),
        "memory_pressure": re.compile(r"(?i)(outofmemory|oomkilled|memory leak|heap out of memory|GC overhead)"),
    }

    sources: list[str] = []
    texts: list[tuple[str, str]] = []
    for path in repo_path.glob("**/*.log"):
        if ".git" in path.parts:
            continue
        try:
            texts.append((str(path.relative_to(repo_path)), path.read_text(encoding="utf-8", errors="replace")[: settings.max_log_bytes]))
        except OSError:
            continue
    for item in uploaded_summaries or []:
        sources.append(item.get("source") or "upload")
        blob = "\n".join((item.get("error_lines") or []) + [item.get("tail") or ""])
        texts.append((item.get("source") or "upload", blob))

    for src, text in texts[:30]:
        sources.append(src)
        for key, rx in patterns.items():
            for m in rx.finditer(text):
                buckets[key] += 1
                line_start = text.rfind("\n", 0, m.start()) + 1
                line_end = text.find("\n", m.end())
                line = text[line_start: line_end if line_end != -1 else m.end() + 120]
                if len(samples[key]) < 8:
                    samples[key].append(line.strip()[:300])

    return {"counts": buckets, "samples": samples, "sources": list(dict.fromkeys(sources))[:40]}
