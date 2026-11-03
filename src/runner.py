#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B2B Cyber CVE, Sanctions & KYB Compliance Gate — GitHub Action Runner
Zero external dependencies (Python 3.11+ standard library only) for <3s startup on any runner.
Supports RapidAPI (@b2bquantapis), Zyla API Hub, Apify PPE (@b2b-quant-apis), and Zero-Key Instant Preview.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APIFY_OWNER = "b2b-quant-apis"
MASTER_ROUTER_SLUG = "b2b-quant-mcp-server"
FREE_CATALOG_URL = "https://jesleytassili-glitch.github.io/v1/free-catalog-status.json"

RAPIDAPI_PUBLIC_SLUGS = {
    "cisa-kev-ransomware-vulnerability-auditor",
    "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
    "global-sanctions-pep-interpol-watchlist-screener",
    "b2b-quant-mcp-server",
    "eu-ted-public-tenders-procurement-radar",
}

ZYLA_ENDPOINTS: dict[str, str] = {
    "b2b-gov-procurement-pncp-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37723/run+b2b+gov+procurement+pncp+radar",
    "us-sam-gov-federal-procurement-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37728/run+us+sam+gov+federal+procurement+auditor",
    "eu-ted-public-tenders-procurement-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37729/run+eu+ted+public+tenders+procurement+radar",
    "brazil-camara-legislative-regulatory-risk-radar": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37730/run+brazil+camara+legislative+regulatory+risk",
    "us-osha-workplace-safety-violation-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37731/run+us+osha+workplace+safety+violation+auditor",
    "us-epa-echo-environmental-compliance-auditor": "https://zylalabs.com/api/14642/b2b+gov+procurement+pncp+radar+api/37732/run+us+epa+echo+environmental+compliance",
    "brazil-tax-reform-ncm-classtrib-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37724/run+brazil+tax+reform+ncm+classtrib+auditor",
    "eu-vies-vat-tax-compliance-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37775/run+eu+vies+vat+tax+compliance+auditor",
    "us-sec-edgar-filings-insider-radar": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37776/run+us+sec+edgar+filings+insider+radar",
    "us-fdic-bankfind-institution-financial-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37777/run+us+fdic+bankfind+institution+financial",
    "global-gleif-lei-corporate-ownership-kyb": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37778/run+global+gleif+lei+corporate+ownership+kyb",
    "brazil-bcb-ptax-sgs-financial-contract-indexer": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37779/run+brazil+bcb+ptax+sgs+financial+contract+indexer",
    "brazil-pix-ispb-cvm-financial-kyb-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37780/run+brazil+pix+ispb+cvm+financial+kyb+auditor",
    "uk-fca-companies-house-kyb-compliance-auditor": "https://zylalabs.com/api/14643/brazil+tax+reform+ncm+classtrib+auditor+api/37781/run+uk+fca+companies+house+kyb+compliance",
    "healthcare-tiss-xml-validator": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37725/run+healthcare+tiss+xml+validator",
    "us-healthcare-npi-provider-lead-enricher": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37838/run+us+healthcare+npi+provider+lead+enricher",
    "us-clinical-trials-biotech-radar": "https://zylalabs.com/api/14644/healthcare+tiss+xml+validator+api/37839/run+us+clinical+trials+biotech+radar",
    "brazil-antt-freight-cte-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37726/run+brazil+antt+minimum+freight+calculator+ct+e",
    "brazil-cep-geocoordinates-logistics-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37846/run+brazil+cep+geocoordinates+ibge+code+api",
    "us-nhtsa-vehicle-vin-recall-auditor": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37847/run+us+nhtsa+vehicle+vin+decoder+safety+recall+a",
    "us-census-fcc-real-estate-geo-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37848/run+us+real+estate+census+tract+fips+proptech+ap",
    "brazil-b2b-cnpj-qsa-lead-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37849/run+brazil+b2b+cnpj+partners+qsa+cnae+lead+api",
    "brazil-ibge-cnae-municipal-b2b-expansion-enricher": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37850/run+brazil+ibge+cnae+2+3+municipal+code+b2b+tax",
    "multi-ats-tech-job-board-hiring-radar": "https://zylalabs.com/api/14645/brazil+antt+minimum+freight+calculator+ct+e+api/37851/run+multi+ats+tech+job+board+b2b+hiring+intent+a",
    "us-fda-recalls-safety-monitor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37727/run+us+fda+recalls+safety+monitor+food+drug+api",
    "cisa-kev-ransomware-vulnerability-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37866/run+us+cisa+kev+exploited+vulnerabilities+api",
    "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37867/run+b2b+ssl+tls+ct+log+subdomain+attack+surface",
    "global-b2b-email-domain-security-auditor": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37868/run+global+b2b+email+mx+spf+dmarc+deliverability",
    "icann-rdap-domain-whois-brand-recon": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37869/run+icann+rdap+official+domain+whois+brand+api",
    "global-sanctions-pep-interpol-watchlist-screener": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37870/run+global+ofac+un+eu+sanctions+pep+watchlist+ap",
    "b2b-quant-mcp-server": "https://zylalabs.com/api/14646/us+fda+recalls+safety+monitor+food+drug+api/37871/run+b2b+regulatory+kyb+fintech+secops+mcp+server"
}

MODE_TO_ACTOR: dict[str, dict[str, Any]] = {
    "cisa-kev-scan": {
        "slug": "cisa-kev-ransomware-vulnerability-auditor",
        "title": "CISA KEV Active Ransomware CVE Audit",
        "rapidapi_url": "https://rapidapi.com/b2bquantapis/api/cisa-kev-ransomware-vulnerability-auditor",
        "apify_url": "https://apify.com/b2b-quant-apis/cisa-kev-ransomware-vulnerability-auditor",
    },
    "domain-attack-surface": {
        "slug": "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
        "title": "B2B SSL/TLS CT Log & Shadow-IT Attack Surface Audit",
        "rapidapi_url": "https://rapidapi.com/b2bquantapis/api/b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
        "apify_url": "https://apify.com/b2b-quant-apis/b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
    },
    "vendor-kyb-sanctions": {
        "slug": "global-sanctions-pep-interpol-watchlist-screener",
        "title": "Global OFAC/UN/EU Sanctions, GLEIF LEI & KYB Audit",
        "rapidapi_url": "https://rapidapi.com/b2bquantapis/api/global-sanctions-pep-interpol-watchlist-screener",
        "apify_url": "https://apify.com/b2b-quant-apis/global-sanctions-pep-interpol-watchlist-screener",
    },
    "gov-tenders-radar": {
        "slug": "us-sam-gov-federal-procurement-auditor",
        "title": "Global B2G Government Procurement & Tenders Radar",
        "rapidapi_url": "https://rapidapi.com/b2bquantapis/api/b2b-quant-mcp-server",
        "apify_url": "https://apify.com/b2b-quant-apis/us-sam-gov-federal-procurement-auditor",
    },
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
KNOWN_CRITICAL_KEV_SAMPLE = {
    "CVE-2024-3094", "CVE-2023-4966", "CVE-2024-21762",
    "CVE-2023-34362", "CVE-2024-4577", "CVE-2021-44228",
}


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None and val != "" else default
    except (ValueError, TypeError):
        return default


def parse_bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    val = str(raw).strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default


def parse_max_results(raw: str | None, default: int = 10) -> int:
    try:
        val = int(float(str(raw or default).strip()))
        return max(1, min(100, val))
    except (ValueError, TypeError):
        return default


def parse_targets(raw_targets: str | None) -> list[str]:
    if not raw_targets or not str(raw_targets).strip():
        return []
    text = str(raw_targets).strip()
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                return [str(x).strip() for x in arr if str(x).strip()][:100]
        except Exception:
            pass
    candidate_path = Path(text)
    if len(text) < 240 and candidate_path.is_file():
        try:
            content = candidate_path.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("["):
                arr = json.loads(content)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()][:100]
            text = content
        except Exception:
            pass
    tokens = re.split(r"[,\n\r;]+", text)
    cleaned = [t.strip() for t in tokens if t and t.strip()]
    return cleaned[:100]


def build_actor_payload(mode: str, targets: list[str], max_results: int) -> dict[str, Any]:
    """Constrói payload 100% aderente ao `.actor/input_schema.json` oficial de cada Ator."""
    if mode == "cisa-kev-scan":
        first_kw = targets[0] if targets else "CVE-2024-3094"
        cve_m = CVE_PATTERN.search(first_kw)
        vendor_kw = cve_m.group(0).upper() if cve_m else first_kw
        return {
            "vendorKeyword": vendor_kw,
            "onlyRansomware": False,
            "maxResults": max_results,
        }
    if mode == "domain-attack-surface":
        domains = [t.lower().replace("https://", "").replace("http://", "").split("/")[0] for t in targets]
        domains = [d for d in domains if d]
        return {
            "rootDomain": domains[0] if domains else "example.com",
            "excludeExpired": False,
            "maxResults": max_results,
        }
    if mode == "vendor-kyb-sanctions":
        return {
            "entityName": targets[0] if targets else "Acme Global Trading Ltd",
            "entityType": "ANY",
            "maxResults": max_results,
        }
    return {
        "keyword": " ".join(targets[:3]) if targets else "cybersecurity",
        "maxResults": max_results,
    }


def _unwrap_mcp_or_dataset(raw_response: Any) -> Any:
    if isinstance(raw_response, list) and len(raw_response) == 1 and isinstance(raw_response[0], dict):
        env = raw_response[0].get("mcpJsonRpcEnvelope")
        if isinstance(env, dict):
            live = (env.get("result") or {}).get("liveDatasetItems")
            if isinstance(live, list):
                return live
    if isinstance(raw_response, dict) and "mcpJsonRpcEnvelope" in raw_response:
        live = ((raw_response.get("mcpJsonRpcEnvelope") or {}).get("result") or {}).get("liveDatasetItems")
        if isinstance(live, list):
            return live
    return raw_response


def http_json_request(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 25.0,
    retries: int = 2,
) -> Any:
    req_headers = {
        "Accept": "application/json",
        "User-Agent": "B2BComplianceSecurityAction/1.0 (+https://github.com/jesleytassili-glitch/b2b-compliance-security-action)",
    }
    if headers:
        req_headers.update(headers)
    body_bytes = None
    if payload is not None and method.upper() != "GET":
        body_bytes = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    ctx = ssl.create_default_context()
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url=url, data=body_bytes, headers=req_headers, method=method.upper())
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else []
        except Exception as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(0.8 * attempt)
    raise RuntimeError(f"HTTP request failed after {retries} attempts ({url}): {last_err}")


def normalize_records_and_risk(mode: str, raw_response: Any) -> tuple[list[dict[str, Any]], int]:
    unwrapped = _unwrap_mcp_or_dataset(raw_response)
    if isinstance(unwrapped, dict):
        items = unwrapped.get("items") or unwrapped.get("data") or unwrapped.get("results")
        records = list(items) if isinstance(items, list) else [unwrapped]
    elif isinstance(unwrapped, list):
        records = [r for r in unwrapped if isinstance(r, dict)]
    else:
        records = []

    high_risk = 0
    for rec in records:
        risk_str = json.dumps(rec).lower()
        if mode == "cisa-kev-scan" and (
            rec.get("inCisaKev") is True
            or str(rec.get("knownRansomwareCampaignUse") or "").lower() == "known"
            or "critical" in risk_str
            or _safe_float(rec.get("threatSeverityScore") or rec.get("riskScore")) >= 75.0
        ):
            high_risk += 1
        elif mode == "domain-attack-surface" and (
            rec.get("expiredCertificate") is True
            or rec.get("isExpired") is True
            or _safe_float(rec.get("attackSurfaceScore") or rec.get("riskScore")) >= 75.0
        ):
            high_risk += 1
        elif mode == "vendor-kyb-sanctions" and (
            rec.get("isSanctioned") is True
            or rec.get("matchFound") is True
            or _safe_float(rec.get("sanctionsRiskScore") or rec.get("riskScore")) >= 75.0
        ):
            high_risk += 1
        elif mode == "gov-tenders-radar" and (
            _safe_float(rec.get("riskScore") or rec.get("complianceRiskScore")) >= 75.0
        ):
            high_risk += 1
    return records, high_risk


def run_zero_key_preview(mode: str, targets: list[str], max_results: int) -> tuple[list[dict[str, Any]], int, bool]:
    """Executa pré-auditoria determinística instantânea + ping opcional ao catálogo $0.00 quando sem chave."""
    catalog_reachable = False
    try:
        cat = http_json_request(FREE_CATALOG_URL, method="GET", timeout=5.0, retries=1)
        catalog_reachable = bool(cat)
    except Exception:
        catalog_reachable = False

    effective_targets = (targets or ["CVE-2024-3094"])[:max_results]
    preview_records: list[dict[str, Any]] = []
    high_risk = 0

    for item in effective_targets:
        if mode == "cisa-kev-scan":
            cve_match = CVE_PATTERN.search(item)
            cve_id = cve_match.group(0).upper() if cve_match else item.upper()
            is_sample_kev = cve_id in KNOWN_CRITICAL_KEV_SAMPLE
            if is_sample_kev:
                high_risk += 1
            preview_records.append(
                {
                    "target": cve_id,
                    "validCveFormat": bool(cve_match),
                    "previewKevFlag": is_sample_kev,
                    "riskLevel": "HIGH" if is_sample_kev else "PREVIEW_ONLY",
                    "note": "Configure rapidapi_key or apify_token for live CISA KEV + ransomware campaign telemetry.",
                }
            )
        elif mode == "domain-attack-surface":
            clean_dom = item.lower().replace("https://", "").replace("http://", "").split("/")[0]
            valid_dom = bool(DOMAIN_PATTERN.match(clean_dom))
            preview_records.append(
                {
                    "target": clean_dom,
                    "validDomainSyntax": valid_dom,
                    "riskLevel": "PREVIEW_ONLY",
                    "note": "Configure rapidapi_key or apify_token for live Certificate Transparency & Shadow-IT subdomain scan.",
                }
            )
        elif mode == "vendor-kyb-sanctions":
            preview_records.append(
                {
                    "target": item,
                    "riskLevel": "PREVIEW_ONLY",
                    "note": "Configure rapidapi_key or apify_token for live OFAC, UN, EU & Interpol watchlist screening.",
                }
            )
        else:
            preview_records.append(
                {
                    "target": item,
                    "riskLevel": "PREVIEW_ONLY",
                    "note": "Configure rapidapi_key or apify_token for live US SAM.gov, EU TED & Brazil PNCP tenders.",
                }
            )

    return preview_records, high_risk, catalog_reachable


def format_step_summary(
    mode: str,
    provider: str,
    records: list[dict[str, Any]],
    high_risk_count: int,
    catalog_reachable: bool,
) -> str:
    meta = MODE_TO_ACTOR.get(mode, MODE_TO_ACTOR["cisa-kev-scan"])
    lines = [
        f"## 🛡️ {meta['title']} (`{mode}`)",
        "",
        f"- **Execution Rail:** `{provider}` | **Records Analyzed:** `{len(records)}` | **High-Risk Flags:** `{high_risk_count}`",
        "",
        "| # | Target / Identifier | Risk / Status | Summary |",
        "| :---: | :--- | :---: | :--- |",
    ]
    for idx, rec in enumerate(records[:15], start=1):
        ident = (
            rec.get("target")
            or rec.get("cveId")
            or rec.get("domain")
            or rec.get("subdomain")
            or rec.get("entityName")
            or rec.get("numeroControlePNCP")
            or rec.get("awardId")
            or f"Record #{idx}"
        )
        risk = (
            rec.get("riskLevel")
            or rec.get("severity")
            or ("HIGH" if rec.get("inCisaKev") or rec.get("isSanctioned") else "VERIFIED")
        )
        summary = (
            rec.get("note")
            or rec.get("vulnerabilityName")
            or rec.get("summary")
            or rec.get("objetoCompra")
            or "Cloud telemetry enriched"
        )
        safe_summary = str(summary).replace("|", "/").replace("\n", " ")[:110]
        lines.append(f"| {idx} | `{ident}` | **{risk}** | {safe_summary} |")

    if provider == "zero-key-preview":
        lines.extend(
            [
                "",
                "---",
                "### ⚡ Unlock Full Live Cloud Telemetry (31 B2B Compliance & Cyber Engines)",
                f" Running in **Zero-Key Instant Preview** (`catalogOnline={catalog_reachable}`). Add a secret to `.github/workflows/` for full live cloud datasets:",
                f"- **RapidAPI Hub (`BASIC $0/15 req` → `PRO $19/mo`):** [{meta['slug']} on RapidAPI]({meta['rapidapi_url']})",
                f"- **Apify Store (`Pay-Per-Event`):** [{meta['slug']} on Apify]({meta['apify_url']})",
                "- **Python & MCP SDKs:** `pip install b2b-compliance-sdk` • `npx -y b2b-compliance-mcp-cli`",
                "- **MCP Registry & 37 n8n Workflows:** [Documentation & OpenAPI 3.0 Specs](https://jesleytassili-glitch.github.io/b2b-quant-mcp-n8n-suite/)",
            ]
        )
    return "\n".join(lines) + "\n"


def write_github_outputs(outputs: dict[str, str]) -> None:
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if not gh_out:
        return
    with open(gh_out, "a", encoding="utf-8") as fh:
        for key, val in outputs.items():
            fh.write(f"{key}={val}\n")


def _invoke_cloud_single(
    slug: str,
    payload: dict[str, Any],
    rapidapi_key: str,
    apify_token: str,
    zyla_key: str,
    zyla_url: str,
) -> tuple[str, Any]:
    if rapidapi_key:
        if slug in RAPIDAPI_PUBLIC_SLUGS:
            host = f"{slug}.p.rapidapi.com"
            url = f"https://{host}/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            return "rapidapi", http_json_request(
                url=url,
                method="POST",
                headers={"X-RapidAPI-Key": rapidapi_key, "X-RapidAPI-Host": host},
                payload=payload,
            )
        host = f"{MASTER_ROUTER_SLUG}.p.rapidapi.com"
        url = f"https://{host}/v2/acts/{APIFY_OWNER}~{MASTER_ROUTER_SLUG}/run-sync-get-dataset-items"
        return "rapidapi", http_json_request(
            url=url,
            method="POST",
            headers={"X-RapidAPI-Key": rapidapi_key, "X-RapidAPI-Host": host},
            payload={"operationMode": "invoke_tool", "toolName": slug, "toolArguments": payload},
        )
    if apify_token:
        url = f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
        return "apify", http_json_request(
            url=url,
            method="POST",
            headers={"Authorization": f"Bearer {apify_token}"},
            payload=payload,
        )
    target_url = zyla_url or ZYLA_ENDPOINTS.get(slug) or f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
    return "zyla", http_json_request(
        url=target_url,
        method="POST",
        headers={"Authorization": f"Bearer {zyla_key}"},
        payload=payload,
    )


def execute_gate(env: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    cfg = env if env is not None else dict(os.environ)
    raw_mode = str(cfg.get("INPUT_MODE") or "cisa-kev-scan").strip().lower()
    mode = raw_mode if raw_mode in MODE_TO_ACTOR else "cisa-kev-scan"
    slug = MODE_TO_ACTOR[mode]["slug"]

    targets = parse_targets(cfg.get("INPUT_TARGETS"))
    max_results = parse_max_results(cfg.get("INPUT_MAX_RESULTS"), default=10)
    fail_on_high_risk = parse_bool(cfg.get("INPUT_FAIL_ON_HIGH_RISK"), default=False)

    rapidapi_key = str(cfg.get("INPUT_RAPIDAPI_KEY") or "").strip()
    zyla_key = str(cfg.get("INPUT_ZYLA_API_KEY") or "").strip()
    zyla_url = str(cfg.get("INPUT_ZYLA_ENDPOINT_URL") or "").strip()
    apify_token = str(cfg.get("INPUT_APIFY_TOKEN") or "").strip()

    provider_used = "zero-key-preview"
    catalog_reachable = True
    upstream_error = ""

    try:
        if rapidapi_key or apify_token or zyla_key:
            batch_targets = targets[:5] if (len(targets) > 1 and mode != "gov-tenders-radar") else [None]
            merged_records: list[dict[str, Any]] = []
            merged_high_risk = 0
            for single_t in batch_targets:
                sub_targets = [single_t] if single_t is not None else targets
                payload = build_actor_payload(mode, sub_targets, max_results)
                provider_used, raw_resp = _invoke_cloud_single(
                    slug, payload, rapidapi_key, apify_token, zyla_key, zyla_url
                )
                recs, hr = normalize_records_and_risk(mode, raw_resp)
                merged_records.extend(recs)
                merged_high_risk += hr
            records, high_risk_count = merged_records, merged_high_risk
        else:
            records, high_risk_count, catalog_reachable = run_zero_key_preview(mode, targets, max_results)
    except Exception as cloud_err:
        upstream_error = str(cloud_err)
        print(f"::warning::Cloud endpoint fallback triggered ({provider_used}): {cloud_err}", file=sys.stderr)
        provider_used = "zero-key-preview"
        records, high_risk_count, catalog_reachable = run_zero_key_preview(mode, targets, max_results)

    gate_failed = bool(fail_on_high_risk and high_risk_count > 0)
    status = "failed_gate" if gate_failed else (
        "completed_preview" if provider_used == "zero-key-preview" else "completed_cloud"
    )

    report = {
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "engineSlug": slug,
        "providerUsed": provider_used,
        "status": status,
        "recordsAnalyzed": len(records),
        "highRiskCount": high_risk_count,
        "records": records,
    }
    if upstream_error:
        report["upstreamFallbackReason"] = upstream_error

    out_dir = Path(cfg.get("RUNNER_TEMP") or tempfile.gettempdir())
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"b2b_compliance_report_{mode}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary_md = format_step_summary(mode, provider_used, records, high_risk_count, catalog_reachable)
    step_summary_path = cfg.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        with open(step_summary_path, "a", encoding="utf-8") as sf:
            sf.write(summary_md)
    else:
        print(summary_md)

    if cfg.get("GITHUB_OUTPUT"):
        with open(cfg["GITHUB_OUTPUT"], "a", encoding="utf-8") as of:
            of.write(f"status={status}\n")
            of.write(f"provider_used={provider_used}\n")
            of.write(f"records_analyzed={len(records)}\n")
            of.write(f"high_risk_count={high_risk_count}\n")
            of.write(f"report_json_path={report_path.as_posix()}\n")

    return (1 if gate_failed else 0), report


if __name__ == "__main__":
    code, _ = execute_gate()
    raise SystemExit(code)
