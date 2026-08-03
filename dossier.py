#!/usr/bin/env python3
"""
DOSSIER — OSINT Intelligence Report Generator
Author: nadirzhon | github.com/nadirzhon/dossier

Usage:
    python dossier.py -t example.com
    python dossier.py -t example.com --shodan KEY --virustotal KEY -o report.html
"""

import argparse
import json
import socket
import ssl
import time
import sys
from datetime import datetime
from pathlib import Path

import requests
import dns.resolver
import whois as whois_lib

# ── Module: WHOIS ─────────────────────────────────────────────────────────────
def get_whois(domain):
    try:
        w = whois_lib.whois(domain)
        return {
            "registrar":        str(w.registrar),
            "creation_date":    str(w.creation_date),
            "expiration_date":  str(w.expiration_date),
            "updated_date":     str(w.updated_date),
            "name_servers":     w.name_servers,
            "status":           str(w.status),
            "emails":           w.emails,
        }
    except Exception as e:
        return {"error": str(e)}

# ── Module: DNS ────────────────────────────────────────────────────────────────
def get_dns(domain):
    results = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []
    return results

# ── Module: Subdomains ────────────────────────────────────────────────────────
def get_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        subs = set()
        for entry in r.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{domain}") and "*" not in name:
                    subs.add(name)
        return sorted(subs)[:50]
    except Exception as e:
        return [f"Error: {e}"]

# ── Module: SSL ────────────────────────────────────────────────────────────────
def get_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "subject":     dict(x[0] for x in cert["subject"]),
                "issuer":      dict(x[0] for x in cert["issuer"]),
                "not_before":  cert["notBefore"],
                "not_after":   cert["notAfter"],
                "san":         [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                "version":     cert.get("version"),
            }
    except Exception as e:
        return {"error": str(e)}

# ── Module: HTTP Headers ───────────────────────────────────────────────────────
def get_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (Security Audit / DOSSIER)"})
        h = r.headers
        security = {
            "Content-Security-Policy": h.get("Content-Security-Policy"),
            "Strict-Transport-Security": h.get("Strict-Transport-Security"),
            "X-Frame-Options": h.get("X-Frame-Options"),
            "X-Content-Type-Options": h.get("X-Content-Type-Options"),
            "Referrer-Policy": h.get("Referrer-Policy"),
            "Permissions-Policy": h.get("Permissions-Policy"),
        }
        missing = [k for k, v in security.items() if not v]
        return {
            "server": h.get("Server", "Hidden"),
            "powered_by": h.get("X-Powered-By"),
            "status_code": r.status_code,
            "security_headers": security,
            "missing_headers": missing,
            "score": round((1 - len(missing)/len(security)) * 100),
        }
    except Exception as e:
        return {"error": str(e)}

# ── Module: GeoIP ──────────────────────────────────────────────────────────────
def get_geoip(domain):
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        d = r.json()
        return {
            "ip":      ip,
            "country": d.get("country_name"),
            "city":    d.get("city"),
            "region":  d.get("region"),
            "asn":     d.get("asn"),
            "org":     d.get("org"),
            "latitude":  d.get("latitude"),
            "longitude": d.get("longitude"),
        }
    except Exception as e:
        return {"error": str(e)}

# ── Module: Email Security ─────────────────────────────────────────────────────
def get_email_security(domain):
    results = {}
    # SPF
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        spf = next((str(r) for r in txt if "v=spf1" in str(r)), None)
        results["spf"] = {"present": bool(spf), "record": spf}
    except Exception:
        results["spf"] = {"present": False}
    # DMARC
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = str(list(dmarc_records)[0])
        results["dmarc"] = {"present": True, "record": dmarc}
    except Exception:
        results["dmarc"] = {"present": False}
    # DKIM (common selectors)
    dkim_found = False
    for selector in ["default", "google", "mail", "email", "s1", "k1"]:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found = True
            results["dkim"] = {"present": True, "selector": selector}
            break
        except Exception:
            pass
    if not dkim_found:
        results["dkim"] = {"present": False}
    return results

# ── Report generator ───────────────────────────────────────────────────────────
def generate_html_report(target, data):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    def row(label, value, ok=None):
        color = "" if ok is None else ("#00cc66" if ok else "#ff6666")
        icon  = "" if ok is None else ("✓ " if ok else "✗ ")
        return f'<tr><td style="color:rgba(255,255,255,.4);padding:6px 12px;white-space:nowrap;font-size:12px;vertical-align:top">{label}</td><td style="color:{color};padding:6px 12px;font-size:12px">{icon}{value}</td></tr>'

    whois_rows = "".join([row(k.replace("_"," ").title(), v) for k, v in data.get("whois",{}).items() if v and v!="None" and k!="error"])
    dns_rows   = "".join([row(rtype, ", ".join(vals)[:120] if vals else "—") for rtype, vals in data.get("dns",{}).items()])
    subs_list  = " ".join([f'<span style="background:rgba(0,150,255,.1);border:1px solid rgba(0,150,255,.3);border-radius:3px;padding:2px 6px;font-size:10px;font-family:monospace">{s}</span>' for s in data.get("subdomains",[])[:20]])
    headers_data = data.get("headers", {})
    header_rows  = "".join([row(k, v or "—", ok=bool(v)) for k, v in headers_data.get("security_headers",{}).items()])
    email_data   = data.get("email_security", {})
    email_rows   = "".join([row(k.upper(), email_data[k].get("record","present") if email_data[k].get("present") else "NOT CONFIGURED", ok=email_data[k].get("present")) for k in ["spf","dmarc","dkim"]])
    geo = data.get("geoip", {})
    ssl_d = data.get("ssl", {})

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>DOSSIER: {target}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#060a10;color:#dde4f0;font-family:monospace;min-height:100vh}}
.header{{background:#07101a;border-bottom:1px solid rgba(0,200,255,.15);padding:20px 30px;display:flex;justify-content:space-between;align-items:center}}
.title{{color:#00c8ff;font-size:20px;font-weight:800;letter-spacing:3px}}.subtitle{{color:rgba(255,255,255,.3);font-size:11px;margin-top:4px}}
.body{{padding:24px 30px;max-width:1200px;margin:0 auto}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}}
.card{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:8px;overflow:hidden}}
.card-head{{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.06);font-size:10px;letter-spacing:1.5px;color:rgba(0,200,255,.6)}}
table{{width:100%}}tr:hover{{background:rgba(255,255,255,.02)}}
.tag{{background:rgba(0,150,255,.1);border:1px solid rgba(0,150,255,.3);border-radius:3px;padding:2px 6px;font-size:10px;margin:2px;display:inline-block}}
.ts{{color:rgba(255,255,255,.2);font-size:11px}}</style></head>
<body>
<div class="header">
  <div>
    <div class="title">DOSSIER</div>
    <div class="subtitle">INTELLIGENCE REPORT: {target} | Generated: {ts}</div>
  </div>
  <div class="ts">OSINT Report v1.0</div>
</div>
<div class="body">
  <div class="grid">
    <div class="card"><div class="card-head">WHOIS</div><table>{whois_rows}</table></div>
    <div class="card"><div class="card-head">DNS RECORDS</div><table>{dns_rows}</table></div>
    <div class="card"><div class="card-head">GEO + NETWORK</div><table>
      {row("IP",geo.get("ip","?"))}{row("Country",geo.get("country","?"))}{row("City",geo.get("city","?"))}
      {row("ASN",geo.get("asn","?"))}{row("Org",geo.get("org","?"))}
    </table></div>
    <div class="card"><div class="card-head">SSL CERTIFICATE</div><table>
      {row("Issuer",ssl_d.get("issuer",{}).get("organizationName","?"))if "issuer" in ssl_d else ""}
      {row("Valid until",ssl_d.get("not_after","?"))}{row("SANs",", ".join(ssl_d.get("san",[])[:5]))if "san" in ssl_d else ""}
    </table></div>
    <div class="card"><div class="card-head">SECURITY HEADERS (score: {headers_data.get("score","?")}%)</div><table>{header_rows}</table></div>
    <div class="card"><div class="card-head">EMAIL SECURITY (SPF/DKIM/DMARC)</div><table>{email_rows}</table></div>
  </div>
  <div class="card" style="margin-top:16px"><div class="card-head">SUBDOMAINS ({len(data.get("subdomains",[]))} found via crt.sh)</div>
    <div style="padding:12px">{subs_list or "None found"}</div>
  </div>
</div>
</body></html>"""

# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="DOSSIER — OSINT Intelligence Report Generator")
    parser.add_argument("-t", "--target",  required=True, help="Domain, IP, or email")
    parser.add_argument("-o", "--output",  default="report.html", help="Output file")
    parser.add_argument("--shodan",        help="Shodan API key")
    parser.add_argument("--virustotal",    help="VirusTotal API key")
    parser.add_argument("--hibp",          action="store_true", help="Check HaveIBeenPwned (email)")
    args = parser.parse_args()

    target = args.target.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    print(f"[DOSSIER] Target: {target}")
    data = {}

    steps = [
        ("WHOIS",           lambda: get_whois(target)),
        ("DNS",             lambda: get_dns(target)),
        ("Subdomains",      lambda: get_subdomains(target)),
        ("SSL",             lambda: get_ssl(target)),
        ("HTTP Headers",    lambda: get_headers(target)),
        ("GeoIP",           lambda: get_geoip(target)),
        ("Email Security",  lambda: get_email_security(target)),
    ]

    for name, fn in steps:
        print(f"  [{name}]...", end=" ", flush=True)
        try:
            result = fn()
            data[name.lower().replace(" ","_")] = result
            print("✓")
        except Exception as e:
            print(f"✗ ({e})")
            data[name.lower().replace(" ","_")] = {"error": str(e)}

    report = generate_html_report(target, data)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"\n[DOSSIER] Report saved: {args.output}")

    if args.output.endswith(".json"):
        Path(args.output.replace(".html",".json")).write_text(json.dumps(data, indent=2, default=str))

if __name__ == "__main__":
    main()
