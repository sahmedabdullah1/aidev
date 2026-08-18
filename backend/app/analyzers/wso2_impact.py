"""Plain-language enrichment for WSO2 issues: impact counts, call flow, configs, customers."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from app.models.wso2_schemas import Wso2ErrorItem

# Partner / customer hints seen in Jazz / banking API estates
CUSTOMER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile('(?i)\\bmeezan\\b|meezan.?bank|PMD[-_]?meezan'), 'Meezan Bank'),
    (re.compile('(?i)\\bmcb\\b|muslim.?commercial|PMD[-_]?mcb'), 'MCB'),
    (re.compile('(?i)\\bapc\\b|apc.?partner|PMD[-_]?apc'), 'APC Partner'),
    (re.compile('(?i)\\bhbl\\b|habib.?bank|PMD[-_]?hbl'), 'HBL'),
    (re.compile('(?i)\\bubl\\b|united.?bank|PMD[-_]?ubl'), 'UBL'),
    (re.compile('(?i)\\baskari\\b|PMD[-_]?askari'), 'Askari Bank'),
    (re.compile('(?i)\\bal.?falah\\b|\\balfalah\\b|PMD[-_]?alfalah'), 'Bank Alfalah'),
    (re.compile('(?i)\\bnadra\\b'), 'NADRA / SECP verification consumers'),
    (re.compile('(?i)\\bjazz\\s*cash\\b|jazzcash'), 'JazzCash'),
    (re.compile('(?i)jazzfb|jazz[_-]?fb|Jazz_FB|FaceBook|\\bfacebook\\b'), 'Jazz Facebook channel'),
    (re.compile('(?i)\\becare\\b'), 'Jazz eCare'),
    (re.compile('(?i)whatsapp|infobip|zarr[_-]?whatsapp|ZARR_WHATSAPP|ZarrWhatsapp'), 'WhatsApp / Infobip / ZARR consumers'),
    (re.compile('(?i)/otp\\b|otp/|AUTHOTP|AUTH_OTP|one.?time.?password|\\botpapi\\b'), 'OTP consumers'),
    (re.compile('(?i)\\bGMLC\\b|GMLC_WSO2'), 'GMLC location / partner apps'),
    (re.compile('(?i)VAS_Ideation|IdeationTech|Jazz_Vas'), 'VAS / Ideation Tech partner'),
    (re.compile('(?i)\\bCMPA\\b'), 'CMPA / CNIC-MSISDN match consumers'),
    (re.compile('(?i)B2bLiveApiCYN|\\bB2B\\b'), 'B2B Live API consumers'),
    (re.compile('(?i)\\bHLR5G\\b|\\bHLR\\b'), 'HLR / network provisioning consumers'),
    (re.compile('(?i)IVRBSSWRAPPER|\\bIVR\\b'), 'IVR / BSS consumers'),
    (re.compile('(?i)TokenAPI|TOKEN_API'), 'Token API clients'),
    (re.compile('(?i)subscription'), 'Subscription API consumers'),
    (re.compile('(?i)prepaid|balance|clientele|checkeligibl'), 'Prepaid / balance / eligibility consumers'),
]

# TransactionID prefixes like PMD-hbl-... map to bank partners
TX_PREFIX_CUSTOMERS: dict[str, str] = {
    "hbl": "HBL",
    "ubl": "UBL",
    "mcb": "MCB",
    "meezan": "Meezan Bank",
    "apc": "APC Partner",
    "askari": "Askari Bank",
    "alfalah": "Bank Alfalah",
    "jazz": "JazzCash",
}

# Normalized API / path segment → customer group
API_CUSTOMER_MAP: dict[str, str] = {
    "jazz_fb_advance": "Jazz Facebook channel",
    "jazz_fb": "Jazz Facebook channel",
    "jazzfb": "Jazz Facebook channel",
    "jazz_vas_generic": "VAS / Ideation Tech partner",
    "jazz_vas": "VAS / Ideation Tech partner",
    "authotp": "OTP consumers",
    "auth_otp": "OTP consumers",
    "otp": "OTP consumers",
    "otpapi": "OTP consumers",
    "tokenapi": "Token API clients",
    "token_api": "Token API clients",
    "gmlc": "GMLC location / partner apps",
    "cmpa": "CMPA / CNIC-MSISDN match consumers",
    "zarr_whatsapp": "WhatsApp / Infobip / ZARR consumers",
    "zarrwhatsapp": "WhatsApp / Infobip / ZARR consumers",
    "checkeligibility": "Prepaid / balance / eligibility consumers",
    "checkeligiblity": "Prepaid / balance / eligibility consumers",
    "subscription": "Subscription API consumers",
    "prepaid": "Prepaid / balance / eligibility consumers",
    "clientele": "Prepaid / balance / eligibility consumers",
    "hlr5g": "HLR / network provisioning consumers",
    "ivrbsswrapper": "IVR / BSS consumers",
    "b2bliveapicyn": "B2B Live API consumers",
    "ecare": "Jazz eCare"
}

# Technical signature → easy title + plain meaning + call flow + configs
PLAYBOOKS: list[dict[str, Any]] = [
    {
        "match": re.compile(r"(?i)Invalid Credentials|API authentication failure|APIAuthenticationHandler|API_AUTH"),
        "title": "API login rejected — wrong or expired credentials",
        "plain": (
            "A client app called an API on APIM, but APIM could not accept the token/key. "
            "Usually the access token is missing, expired, revoked, or the app is not subscribed to that API."
        ),
        "call_flow": [
            "Client / partner app",
            "APIM Gateway (APIAuthenticationHandler)",
            "Rejects request (Invalid Credentials)",
            "API backend is never reached",
        ],
        "configs": [
            {
                "file": "Developer Portal → Application → Production Keys",
                "check": "Consumer key/secret and access token are valid and not expired",
                "set": "Generate/regenerate token; confirm grant type matches how the client authenticates",
            },
            {
                "file": "Publisher → API → Subscriptions",
                "check": "Calling application has an ACTIVE subscription to the failing API",
                "set": "Subscribe the app to the API (and correct tier) then republish if needed",
            },
            {
                "file": "deployment.toml (APIM) — [apim.oauth_config] / key manager",
                "check": "Key Manager / token endpoint reachable; JWT validation settings correct",
                "set": "Verify key_manager URL, enable_jwt, and issuer settings for your KM",
            },
            {
                "file": "Client request Authorization header",
                "check": "Header is Bearer <access_token> (or correct API key header)",
                "set": "Stop sending expired/cached tokens; refresh from token endpoint before call",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)Invalid JWT|JWT validation|JWT token"),
        "title": "Broken access token (JWT) — gateway cannot trust the token",
        "plain": (
            "The client sent a JWT access token, but APIM could not validate it "
            "(bad signature, wrong issuer, expired, or malformed)."
        ),
        "call_flow": [
            "Client sends Authorization: Bearer <JWT>",
            "APIM Gateway validates JWT",
            "Validation fails",
            "Request denied before backend",
        ],
        "configs": [
            {
                "file": "deployment.toml — [apim.key_manager] / JWT section",
                "check": "issuer, audience, and certificate/JWKS used to verify tokens",
                "set": "Align issuer with Key Manager; update cert/JWKS if KM cert rotated",
            },
            {
                "file": "Client token request",
                "check": "Token obtained from the correct token endpoint for this environment",
                "set": "Use prod token endpoint for prod APIs; do not reuse staging tokens",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)UserStoreException|resolving Id for the user|authenticating user|User Manager Core"),
        "title": "User directory / identity store problem",
        "plain": (
            "APIM/MI tried to look up or authenticate a user in the user store (often backed by the DB), "
            "but the identity component failed. This blocks logins and some internal admin operations."
        ),
        "call_flow": [
            "Admin / system / API user action",
            "Carbon User Manager",
            "User store / JDBC user DB",
            "Fails with UserStoreException",
        ],
        "configs": [
            {
                "file": "<CARBON_HOME>/repository/conf/deployment.toml — [user_store] / [database.shared_db]",
                "check": "User store type and shared DB URL/user/password",
                "set": "Correct JDBC URL to MySQL, valid credentials, and restart after fix",
            },
            {
                "file": "master-datasources.xml (if used) / database.user",
                "check": "WSO2_USER / SHARED_DB datasource is healthy",
                "set": "Test connection from the node; fix max_connections / auth plugin on MySQL 8.4",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)registry transaction|Could not create connection|SQLNonTransient|Database error"),
        "title": "Database connection failure (registry / shared DB)",
        "plain": (
            "The product could not open a DB connection (often MySQL). "
            "Registry and many core features stop working until connectivity is restored."
        ),
        "call_flow": [
            "APIM or MI node",
            "JDBC datasource",
            "MySQL shared/registry DB",
            "Connection refused / failed",
        ],
        "configs": [
            {
                "file": "deployment.toml — [database.shared_db] / [database.apim_db]",
                "check": "hostname, port, database name, username, password, driver",
                "set": 'type="mysql", url="jdbc:mysql://HOST:3306/DB?..." with working credentials',
            },
            {
                "file": "MySQL server (8.4.3)",
                "check": "Service up, max_connections, grants for WSO2 user, network from 10.50.13.x",
                "set": "Allow host, raise max_connections if exhausted, verify TLS/auth plugin",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)status code 400|Request failed with status code 400|AI Service Unavailable"),
        "title": "Backend returned Bad Request (HTTP 400)",
        "plain": (
            "APIM/MI forwarded (or built) a request to a backend/AI service, and that backend rejected it as invalid. "
            "This is usually a bad payload, missing header, or contract mismatch — not a gateway crash."
        ),
        "call_flow": [
            "End user / channel (e.g. WhatsApp)",
            "MI mediation / LogMediator API",
            "Backend AI / Infobip service",
            "HTTP 400 Bad Request → user sees failure message",
        ],
        "configs": [
            {
                "file": "MI API / sequence (Synapse) endpoint URL",
                "check": "Backend URL and method match the provider contract",
                "set": "Update endpoint address and Content-Type in the API/sequence artifact",
            },
            {
                "file": "Payload factory / JSON transform mediator",
                "check": "JSON body fields required by Infobip/AI are present and typed correctly",
                "set": "Fix mapping for text/template fields; log outbound body briefly for verification",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)Json Payload is empty"),
        "title": "Empty JSON body received",
        "plain": (
            "An API or mediator expected a JSON request body, but the body was empty. "
            "Clients may be posting without Content-Type/body, or a previous step dropped the payload."
        ),
        "call_flow": [
            "Client",
            "APIM/MI API",
            "JSON parser / mediator",
            "Fails — payload empty",
        ],
        "configs": [
            {
                "file": "Client request",
                "check": "POST/PUT includes JSON body and Content-Type: application/json",
                "set": "Send non-empty JSON; avoid GET for body-required APIs",
            },
            {
                "file": "MI message builders / synapse properties",
                "check": "JSON message builder enabled for application/json",
                "set": "Ensure messageBuilders/messageFormatters include JSON in axis2.xml / deployment.toml",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)heartbeat notification|Status:\s*401"),
        "title": "Cluster heartbeat unauthorized (401)",
        "plain": (
            "A node tried to send a heartbeat/notification to another component and got HTTP 401 Unauthorized. "
            "Often follows identity/DB issues or mismatched internal credentials."
        ),
        "call_flow": [
            "APIM/MI node",
            "Internal notification / event endpoint",
            "Auth check",
            "401 Unauthorized",
        ],
        "configs": [
            {
                "file": "deployment.toml — internal APIs / event hub credentials",
                "check": "Internal service credentials match across nodes",
                "set": "Sync admin/system passwords and eventhub configs on all nodes",
            },
        ],
    },
    {
        "match": re.compile(r"(?i)Cannot borrow client|ssl://|9711"),
        "title": "Cannot connect to peer node over SSL",
        "plain": (
            "This node could not borrow/open a secure client connection to another cluster member "
            "(often clustering/port 9711). Peer may be down, firewalled, or TLS-mismatched."
        ),
        "call_flow": [
            "Local APIM/MI node",
            "SSL client pool",
            "Peer node (e.g. 10.50.13.x:9711)",
            "Connection borrow failed",
        ],
        "configs": [
            {
                "file": "deployment.toml — [clustering] / hazelcast members",
                "check": "Member IPs/ports and clustering enabled consistently",
                "set": "List all members (126/127/128); open firewall for clustering ports",
            },
            {
                "file": "Keystores / client truststore",
                "check": "Peer certificates trusted",
                "set": "Import peer cert into client-truststore.jks if TLS handshake fails",
            },
        ],
    },
]



def extract_identity_from_text(text: str) -> dict[str, Any]:
    """Pull appName, requestURI, API names, and TransactionID prefixes from a log line."""
    blob = text or ""
    apps = re.findall(r"(?i)appName=([^\s,&]+)", blob)
    uris = re.findall(r"(?i)requestURI=([^\s,&]+)", blob)
    apis = re.findall(r"(?i)\bapi(?:Name)?[=:][\s]*([A-Za-z0-9_./-]+)", blob)
    # /t/tenant/api/version or /api-context style segments
    path_apis = re.findall(r"(?i)/(?:t/[^/]+/)?([A-Za-z][A-Za-z0-9_-]{2,})/(?:v?\d|1\.0|2\.0)", blob)
    tx_ids = re.findall(r"(?i)(?:TransactionID|txnId|txn_id|correlation)=([^\s,&]+)", blob)
    tx_ids += re.findall(r"\bPMD-[A-Za-z0-9_-]+", blob)
    return {
        "app_names": list(dict.fromkeys(apps))[:20],
        "request_uris": list(dict.fromkeys(uris))[:20],
        "api_names": list(dict.fromkeys(apis + path_apis))[:20],
        "transaction_ids": list(dict.fromkeys(tx_ids))[:20],
    }


def _normalize_api_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")


def _customers_from_api_name(name: str) -> list[str]:
    key = _normalize_api_key(name)
    out: list[str] = []
    if key in API_CUSTOMER_MAP:
        out.append(API_CUSTOMER_MAP[key])
    for ak, label in API_CUSTOMER_MAP.items():
        if ak in key or key in ak:
            if label not in out:
                out.append(label)
    for pat, label in CUSTOMER_PATTERNS:
        if pat.search(name) and label not in out:
            out.append(label)
    return out


def _customers_from_txid(txid: str) -> list[str]:
    out: list[str] = []
    m = re.search(r"(?i)PMD[-_]?([A-Za-z]+)", txid or "")
    if m:
        label = TX_PREFIX_CUSTOMERS.get(m.group(1).lower())
        if label:
            out.append(label)
    for pat, label in CUSTOMER_PATTERNS:
        if pat.search(txid or "") and label not in out:
            out.append(label)
    return out


def extract_customers(*texts: str | None) -> list[str]:
    blob = " ".join(t for t in texts if t)
    found: list[str] = []

    def _add(name: str) -> None:
        if name and name not in found:
            found.append(name)

    for pat, name in CUSTOMER_PATTERNS:
        if pat.search(blob):
            _add(name)

    ident = extract_identity_from_text(blob)
    for app in ident["app_names"]:
        for c in _customers_from_api_name(app):
            _add(c)
        _add(f"App: {app}")
    for uri in ident["request_uris"]:
        for c in _customers_from_api_name(uri):
            _add(c)
        for pat, name in CUSTOMER_PATTERNS:
            if pat.search(uri):
                _add(name)
    for api in ident["api_names"]:
        for c in _customers_from_api_name(api):
            _add(c)
    for tx in ident["transaction_ids"]:
        for c in _customers_from_txid(tx):
            _add(c)

    # Prefer named partners over generic App: labels when ranking for display
    partners = [x for x in found if not x.startswith("App: ")]
    apps = [x for x in found if x.startswith("App: ")]
    return (partners + apps)[:12]


def build_customer_impact_summary(log_evidence: dict[str, Any]) -> dict[str, Any]:
    """Roll up who is impacted across the whole scan (counts + top apps/APIs/URIs)."""
    customer_counts: Counter[str] = Counter()
    app_counts: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    uri_counts: Counter[str] = Counter()
    tx_prefix_counts: Counter[str] = Counter()

    findings = list(log_evidence.get("priority_failure_findings") or [])
    for f in findings:
        n = int(f.get("occurrence_count") or 1)
        blob = " ".join(
            str(f.get(k) or "")
            for k in ("functional_error", "evidence", "request_uri", "app_name", "api_name", "transaction_id")
        )
        # Prefer pre-extracted identity from scanner when present
        for app in f.get("app_names") or ([f["app_name"]] if f.get("app_name") else []):
            app_counts[app] += n
            blob += f" appName={app}"
        for uri in f.get("request_uris") or ([f["request_uri"]] if f.get("request_uri") else []):
            uri_counts[uri] += n
            blob += f" requestURI={uri}"
        for api in f.get("api_names") or ([f["api_name"]] if f.get("api_name") else []):
            api_counts[api] += n
            blob += f" api:{api}"
        for tx in f.get("transaction_ids") or ([f["transaction_id"]] if f.get("transaction_id") else []):
            blob += f" TransactionID={tx}"
            m = re.search(r"(?i)PMD[-_]?([A-Za-z]+)", str(tx))
            if m:
                tx_prefix_counts[m.group(1).upper()] += n

        for c in extract_customers(blob):
            if not c.startswith("App: "):
                customer_counts[c] += n

    # Also fold scan-level identity rollups if present
    for row in log_evidence.get("scan_summaries") or []:
        ident = row.get("identity") or {}
        for name, cnt in (ident.get("customers") or {}).items():
            customer_counts[name] += int(cnt)
        for name, cnt in (ident.get("app_names") or {}).items():
            app_counts[name] += int(cnt)
        for name, cnt in (ident.get("api_names") or {}).items():
            api_counts[name] += int(cnt)
        for name, cnt in (ident.get("request_uris") or {}).items():
            uri_counts[name] += int(cnt)

    top_customers = [{"customer": k, "failure_hits": v} for k, v in customer_counts.most_common(15)]
    headline = (
        ", ".join(f"{r['customer']} ({r['failure_hits']})" for r in top_customers[:8])
        if top_customers
        else "No customer/partner identity found in scanned log lines (need appName / requestURI / TransactionID)"
    )
    return {
        "headline": headline,
        "customers": top_customers,
        "top_apps": [{"name": k, "count": v} for k, v in app_counts.most_common(12)],
        "top_apis": [{"name": k, "count": v} for k, v in api_counts.most_common(12)],
        "top_uris": [{"name": k, "count": v} for k, v in uri_counts.most_common(12)],
        "tx_prefixes": [{"prefix": k, "count": v} for k, v in tx_prefix_counts.most_common(12)],
    }


def _blob(e: Wso2ErrorItem) -> str:
    return " ".join(
        str(x)
        for x in [
            e.error,
            e.description,
            e.functional_error,
            e.exception_type,
            e.logger,
            e.evidence,
        ]
        if x
    )


def _pick_playbook(e: Wso2ErrorItem) -> dict[str, Any] | None:
    blob = _blob(e)
    for pb in PLAYBOOKS:
        if pb["match"].search(blob):
            return pb
    return None


def _match_finding(e: Wso2ErrorItem, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    err = (e.error or "").lower()
    func = (e.functional_error or "").lower()
    logger = (e.logger or "").lower()
    best = None
    best_score = 0
    for f in findings:
        msg = (f.get("functional_error") or "").lower()
        flog = (f.get("logger") or "").lower()
        score = 0
        if logger and flog and logger in flog:
            score += 3
        if err and err[:40] in msg:
            score += 4
        if func and func[:40] in msg:
            score += 4
        for token in re.findall(r"[a-z]{4,}", err)[:6]:
            if token in msg:
                score += 1
        # identity boost
        for field in ("app_names", "request_uris", "api_names"):
            for val in f.get(field) or []:
                if str(val).lower() in (_blob(e).lower()):
                    score += 2
        if score > best_score:
            best_score = score
            best = f
    return best if best_score >= 2 else None


def _total_failures(log_evidence: dict[str, Any]) -> int:
    total = 0
    for row in log_evidence.get("scan_summaries") or []:
        sig = row.get("signals") or {}
        levels = row.get("level_counts") or {}
        err_n = int(sig.get("error_lines") or levels.get("ERROR") or 0)
        warn_n = int(sig.get("warn_lines") or levels.get("WARN") or 0)
        total += max(
            err_n + warn_n,
            int(row.get("failure_count_raw") or 0),
            int(sig.get("auth_failures") or 0) + int(sig.get("http_4xx") or 0) + int(sig.get("http_5xx") or 0),
        )
    if total <= 0:
        findings = log_evidence.get("priority_failure_findings") or []
        total = sum(int(f.get("occurrence_count") or 1) for f in findings) or len(findings)
    return max(total, 1)


def enrich_wso2_errors(
    errors: list[Wso2ErrorItem],
    log_evidence: dict[str, Any],
) -> list[Wso2ErrorItem]:
    findings = list(log_evidence.get("priority_failure_findings") or [])
    total = _total_failures(log_evidence)
    impact_summary = build_customer_impact_summary(log_evidence)
    log_evidence["impacted_customers_summary"] = impact_summary
    global_blob = " ".join(
        str(f.get("functional_error") or "") + " " + str(f.get("evidence") or "") for f in findings[:80]
    )
    # Prefer real partner names from rollup for sparse issues
    top_partner_names = [r["customer"] for r in (impact_summary.get("customers") or [])[:6]]

    for e in errors:
        pb = _pick_playbook(e)
        matched = _match_finding(e, findings)
        count = int((matched or {}).get("occurrence_count") or 0)
        if count <= 0:
            logger = (e.logger or "").split(".")[-1].lower()
            for f in findings:
                msg = (f.get("functional_error") or "") + " " + (f.get("logger") or "")
                if logger and logger.lower() in msg.lower():
                    count += int(f.get("occurrence_count") or 1)
                elif e.exception_type and e.exception_type in (f.get("functional_error") or ""):
                    count += int(f.get("occurrence_count") or 1)
            if count <= 0:
                count = 1
        pct = min(100.0, round(100.0 * count / total, 1))

        if pb:
            if not e.technical_name:
                e.technical_name = e.error
            e.error = pb["title"]
            if not e.plain_meaning:
                e.plain_meaning = pb["plain"]
            if not e.call_flow:
                e.call_flow = list(pb["call_flow"])
            if not e.config_checks:
                e.config_checks = [
                    f"{c['file']}: check → {c['check']}; configure → {c['set']}" for c in pb["configs"]
                ]
        else:
            if not e.technical_name:
                e.technical_name = e.error
            if re.search(r"Exception|Error\b", e.error) and len(e.error) < 80:
                e.error = f"System fault: {e.error} (needs engineering review)"
            if not e.plain_meaning:
                e.plain_meaning = (
                    e.description
                    or e.functional_error
                    or "A component reported a failure in the carbon log. Review evidence and logger details below."
                )
            if not e.call_flow:
                e.call_flow = [
                    "Client / partner",
                    "APIM Gateway or MI mediation",
                    e.subsystem or e.logger or "WSO2 component",
                    "Failure recorded in wso2carbon.log",
                ]

        e.failure_count = count
        e.failure_total = total
        e.impact_pct = pct
        e.impact_summary = (
            f"{count} of {total} scanned failures ({pct}%) match this issue pattern — "
            f"{'high' if pct >= 25 else 'moderate' if pct >= 8 else 'localized'} impact share."
        )

        matched_blob_parts = [
            e.error,
            e.description,
            e.functional_error,
            e.evidence,
            (matched or {}).get("functional_error"),
            (matched or {}).get("evidence"),
        ]
        if matched:
            for field in ("app_names", "request_uris", "api_names", "transaction_ids"):
                vals = matched.get(field) or []
                matched_blob_parts.extend(str(v) for v in vals)
            for field in ("app_name", "request_uri", "api_name", "transaction_id"):
                if matched.get(field):
                    matched_blob_parts.append(str(matched[field]))
        customers = extract_customers(*matched_blob_parts, global_blob if count > 1 else None)
        # If still only generic, attach top partners from estate-wide rollup for platform-wide issues
        if (not customers or all(c.startswith("App: ") for c in customers)) and top_partner_names:
            if pct >= 8 or "Database" in (e.error or "") or "User directory" in (e.error or ""):
                customers = list(dict.fromkeys(customers + top_partner_names))[:12]
        if not e.impacted_customers:
            e.impacted_customers = customers or [
                "Not clearly identifiable from these log lines — check appName/requestURI/TransactionID in carbon or http_access logs"
            ]

        if not e.config_checks:
            e.config_checks = [
                "deployment.toml: verify DB, key manager, and hostname settings for this node",
                "Publisher/DevPortal: verify API subscription and application keys for the calling app",
                "Client side: verify token/payload against the failing requestURI",
            ]

    return errors
