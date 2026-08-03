<div align="center">

```
██████╗  ██████╗ ███████╗███████╗██╗███████╗██████╗
██╔══██╗██╔═══██╗██╔════╝██╔════╝██║██╔════╝██╔══██╗
██║  ██║██║   ██║███████╗███████╗██║█████╗  ██████╔╝
██║  ██║██║   ██║╚════██║╚════██║██║██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝███████║███████║██║███████╗██║  ██║
╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
```

**One-command OSINT intelligence report generator**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=flat-square&logo=fastapi)](/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

*Domain, IP, or email → comprehensive HTML intelligence report in seconds.*

</div>

---

## What it does

`dossier domain.com` → generates a beautiful, self-contained HTML report with:

| Section | Data |
|---------|------|
| **WHOIS** | Registrar, creation/expiry dates, registrant |
| **DNS** | A, MX, NS, TXT, CNAME, SOA records |
| **Subdomains** | crt.sh certificate transparency enumeration |
| **SSL** | Certificate chain, validity, SANs, cipher suites |
| **HTTP** | Security headers audit (CSP, HSTS, X-Frame, etc.) |
| **GeoIP** | Country, city, ASN, organization |
| **Shodan** | Open ports, services, known vulnerabilities (optional) |
| **VirusTotal** | Malware history, reputation score (optional) |
| **Email Security** | SPF, DKIM, DMARC configuration audit |
| **Technology** | Web tech fingerprinting (Wappalyzer-style) |
| **Screenshots** | Automated site screenshots via Playwright |

## Quick Start

```bash
git clone https://github.com/nadirzhon/dossier
cd dossier
pip install -r requirements.txt

# Basic scan (no API keys needed)
python dossier.py -t example.com

# Full scan with all sources
python dossier.py -t example.com \
  --shodan YOUR_KEY \
  --virustotal YOUR_KEY \
  --screenshot

# Scan IP or email
python dossier.py -t 8.8.8.8
python dossier.py -t admin@example.com --hibp

# Output formats
python dossier.py -t example.com -o report.html  # default
python dossier.py -t example.com -o report.json
python dossier.py -t example.com -o report.pdf
```

## Output preview

```
┌─────────────────────────────────────────────────────────────┐
│  DOSSIER INTELLIGENCE REPORT                                │
│  Target: example.com  |  Generated: 2026-08-04 12:00 UTC   │
├──────────────────┬──────────────────────────────────────────┤
│ ● RISK SCORE     │  42/100 — MODERATE                       │
│                  │  ████████████░░░░░░░░  42%               │
├──────────────────┼──────────────────────────────────────────┤
│ WHOIS            │  Registrar: GoDaddy                      │
│                  │  Created: 1995-08-13  Expires: 2030-08-13│
│                  │  Age: 30 years (established)             │
├──────────────────┼──────────────────────────────────────────┤
│ DNS RECORDS      │  A: 93.184.216.34                        │
│                  │  MX: mail.example.com (priority 10)      │
│                  │  NS: a.iana-servers.net                  │
├──────────────────┼──────────────────────────────────────────┤
│ SUBDOMAINS (12)  │  www, mail, api, dev, staging, blog...   │
├──────────────────┼──────────────────────────────────────────┤
│ SECURITY HEADERS │  ✗ CSP missing   ✓ HSTS present          │
│                  │  ✗ X-Frame-Options missing               │
├──────────────────┼──────────────────────────────────────────┤
│ EMAIL SECURITY   │  ✓ SPF: v=spf1 include:... -all         │
│                  │  ✗ DMARC missing                         │
│                  │  ✗ DKIM not configured                   │
└──────────────────┴──────────────────────────────────────────┘
```

## Use cases

- **Penetration testing recon** — fast target profiling before engagement
- **Bug bounty** — enumerate attack surface quickly
- **Due diligence** — assess a company's security posture before partnership
- **Threat intelligence** — investigate suspicious domains/IPs
- **Red team** — automated initial reconnaissance

## Architecture

```
CLI (dossier.py)
    │
    ├── modules/whois_module.py
    ├── modules/dns_module.py
    ├── modules/ssl_module.py
    ├── modules/headers_module.py
    ├── modules/subdomains_module.py
    ├── modules/geoip_module.py
    ├── modules/shodan_module.py      (optional)
    ├── modules/virustotal_module.py  (optional)
    └── modules/email_security.py
          │
          ▼
    report/generator.py
          │
          ▼
    output.html  (self-contained, no external dependencies)
```

## Config

```bash
cp config.example.json config.json
# Add optional API keys:
{
  "shodan_key": "",
  "virustotal_key": "",
  "hibp_key": ""
}
```

## License

MIT
