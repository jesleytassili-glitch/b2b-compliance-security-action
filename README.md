# 🛡️ B2B Cyber CVE, Sanctions & KYB Compliance Gate (`GitHub Action`)

[![Marketplace Release](https://img.shields.io/github/v/release/jesleytassili-glitch/b2b-compliance-security-action?color=brightgreen&label=Marketplace%20Release)](https://github.com/jesleytassili-glitch/b2b-compliance-security-action/releases/tag/v1.0.0)
[![Model Context Protocol Registry](https://img.shields.io/badge/Official_MCP_Registry-io.github.jesleytassili-glitch-6366F1)](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.jesleytassili-glitch)
[![RapidAPI Hub](https://img.shields.io/badge/RapidAPI-@b2bquantapis-0055FF)](https://rapidapi.com/user/b2bquantapis)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Drop-in **DevSecOps, Supply-Chain KYB & Regulatory Compliance Gate** for GitHub Actions (`pull_request`, `push`, and scheduled `cron` pipelines). Powered by **31 stateless B2B Compliance & Cyber Intelligence Engines** with zero Docker build overhead (`<3s` startup on `ubuntu-latest`, `macos-latest`, or `windows-latest`).

---

## 🚀 Quick Start (Works Immediately in Zero-Key Preview or Full Cloud Mode)

### 1. Pull Request CISA KEV Ransomware CVE & Attack Surface Gate
```yaml
name: Security & Compliance Gate
on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  compliance-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan Critical CVEs against CISA KEV Catalog
        uses: jesleytassili-glitch/b2b-compliance-security-action@v1
        with:
          mode: 'cisa-kev-scan'
          targets: 'CVE-2024-3094,CVE-2023-4966'
          rapidapi_key: ${{ secrets.RAPIDAPI_KEY }} # Optional on 1st test (runs Zero-Key Preview if omitted)
          fail_on_high_risk: 'false'
```

### 2. Scheduled Vendor KYB & OFAC/UN/EU Sanctions Screening (`vendors.txt`)
```yaml
      - name: Weekly Supplier Sanctions & KYB Screening
        uses: jesleytassili-glitch/b2b-compliance-security-action@v1
        with:
          mode: 'vendor-kyb-sanctions'
          targets: 'Acme Global Trading Ltd, Siemens AG'
          rapidapi_key: ${{ secrets.RAPIDAPI_KEY }}
```

---

## 🔑 Supported Cloud API Keys (Choose Any Billing Rail)

| Input Parameter | Marketplace / Provider | Tier Options |
| :--- | :--- | :--- |
| `rapidapi_key` | **[RapidAPI Studio (`@b2bquantapis`)](https://rapidapi.com/user/b2bquantapis)** | `BASIC` (**Free** 15 req/mo) • `PRO` (**$19/mo**) • `ULTRA` (**$49/mo**) • `MEGA` (**$149/mo**) |
| `apify_token` | **[Apify Store (`@b2b-quant-apis`)](https://apify.com/b2b-quant-apis)** | **Pay-Per-Event** (`$0.01–$0.04` per audited record, zero monthly commitment) |
| `zyla_api_key` | **[Zyla API Hub](https://zylalabs.com)** | Enterprise B2B Monthly Subscriptions |
| *(Omitted)* | **Zero-Key Instant Preview** | **$0.00** deterministic syntax/KEV pre-check + Markdown Job Summary |

---

## 📊 Supported Modes

1. `cisa-kev-scan` — Active ransomware & exploited CVEs (`cisa-kev-ransomware-vulnerability-auditor`).
2. `domain-attack-surface` — Certificate Transparency (`crt.sh`) Shadow-IT subdomains & SSL hygiene (`b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor`).
3. `vendor-kyb-sanctions` — Consolidated OFAC, UN, EU & PEP sanctions screening (`global-sanctions-pep-interpol-watchlist-screener`).
4. `gov-tenders-radar` — Live B2G public procurement monitoring (`us-sam-gov-federal-procurement-auditor`).
