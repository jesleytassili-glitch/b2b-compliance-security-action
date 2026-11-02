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
FREE_CATALOG_URL = "https://jesleytassili-glitch.github.io/v1/free-catalog-status"

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
        "rapidapi_url": "https://rapidapi.com/b2bquantapis/api/us-sam-gov-federal-procurement-auditor",
        "apify_url": "https://apify.com/b2b-quant-apis/us-sam-gov-federal-procurement-auditor",
    },
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
KNOWN_CRITICAL_KEV_SAMPLE = {
    "CVE-2024-3094", "CVE-2023-4966", "CVE-2024-21762",
    "CVE-2023-34362", "CVE-2024-4577", "CVE-2021-44228",
}


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
    candidate_path = Path(text)
    if len(text) < 240 and candidate_path.is_file():
        try:
            content = candidate_path.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("["):
                arr = json.loads(content)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()]
            text = content
        except Exception:
            pass
    tokens = re.split(r"[,\n\r;]+", text)
    cleaned = [t.strip() for t in tokens if t and t.strip()]
    return cleaned[:100]


def build_actor_payload(mode: str, targets: list[str], max_results: int) -> dict[str, Any]:
    if mode == "cisa-kev-scan":
        cves = [m.upper() for t in targets for m in CVE_PATTERN.findall(t)]
        return {
            "cveIds": cves or ["CVE-2024-3094"],
            "ransomwareOnly": False,
            "maxResults": max_results,
        }
    if mode == "domain-attack-surface":
        domains = [t.lower().replace("https://", "").replace("http://", "").split("/")[0] for t in targets]
        domains = [d for d in domains if d]
        return {
            "domains": domains or ["example.com"],
            "maxSubdomains": max_results,
        }
    if mode == "vendor-kyb-sanctions":
        return {
            "entities": targets or ["Acme Global Trading Ltd"],
            "fuzzyThreshold": 0.82,
            "maxResults": max_results,
        }
    return {
        "keywords": targets or ["cybersecurity", "cloud"],
        "maxResults": max_results,
    }


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
    if isinstance(raw_response, dict):
        items = raw_response.get("items") or raw_response.get("data") or raw_response.get("results")
        records = list(items) if isinstance(items, list) else [raw_response]
    elif isinstance(raw_response, list):
        records = [r for r in raw_response if isinstance(r, dict)]
    else:
        records = []

    high_risk = 0
    for rec in records:
        risk_str = json.dumps(rec).lower()
        if mode == "cisa-kev-scan" and (
            rec.get("inCisaKev") is True
            or rec.get("knownRansomwareCampaignUse", "").lower() == "known"
            or "critical" in risk_str
            or float(rec.get("riskScore") or 0) >= 75
        ):
            high_risk += 1
        elif mode == "domain-attack-surface" and (
            rec.get("expiredCertificate") is True
            or float(rec.get("attackSurfaceScore") or rec.get("riskScore") or 0) >= 75
        ):
            high_risk += 1
        elif mode == "vendor-kyb-sanctions" and (
            rec.get("isSanctioned") is True
            or rec.get("matchFound") is True
            or float(rec.get("riskScore") or 0) >= 75
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

    payload = build_actor_payload(mode, targets, max_results)
    provider_used = "zero-key-preview"
    catalog_reachable = True

    try:
        if rapidapi_key:
            provider_used = "rapidapi"
            url = f"https://{slug}.p.rapidapi.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            raw_resp = http_json_request(
                url=url,
                method="POST",
                headers={
                    "X-RapidAPI-Key": rapidapi_key,
                    "X-RapidAPI-Host": f"{slug}.p.rapidapi.com",
                },
                payload=payload,
            )
            records, high_risk_count = normalize_records_and_risk(mode, raw_resp)
        elif apify_token:
            provider_used = "apify"
            url = f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            raw_resp = http_json_request(
                url=url,
                method="POST",
                headers={"Authorization": f"Bearer {apify_token}"},
                payload=payload,
            )
            records, high_risk_count = normalize_records_and_risk(mode, raw_resp)
        elif zyla_key:
            provider_used = "zyla"
            target_url = zyla_url or f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            raw_resp = http_json_request(
                url=target_url,
                method="POST",
                headers={"Authorization": f"Bearer {zyla_key}"},
                payload=payload,
            )
            records, high_risk_count = normalize_records_and_risk(mode, raw_resp)
        else:
            records, high_risk_count, catalog_reachable = run_zero_key_preview(mode, targets, max_results)
    except Exception as cloud_err:
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
