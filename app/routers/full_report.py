# app/routers/full_report.py

from fastapi import APIRouter, HTTPException
from services.full_report_service import fetch_all_data
from utils.pdf_converter import markdown_to_pdf
from datetime import datetime
import json

router = APIRouter()

def format_to_markdown(data: dict, domain: str) -> str:
    md = ""
    
    # -------------------------
    # DNS Section
    # -------------------------
    md += "## 🌐 DNS Records\n"
    dns_data = data.get('dns', {})
    if dns_data:
        md += "| Record Type | Values |\n|-------------|--------|\n"
        for record, values in dns_data.items():
            if record == 'AAAA' and 'Error' in values[0]:
                values = [f"❗ {values[0]}"]
            formatted = ', '.join(values) if isinstance(values, list) else values
            md += f"| {record} | {formatted} |\n"
    else:
        md += "DNS data unavailable\n"

    # -------------------------
    # WHOIS Section
    # -------------------------
    md += "\n## 📄 WHOIS Information\n"
    whois_data = data.get('whois', {})
    if whois_data:
        md += "| Field | Value |\n|-------|-------|\n"
        for key, value in whois_data.items():
            if key == 'raw_data':
                continue
            else:
                md += f"| {key.replace('_', ' ').title()} | {value or 'N/A'} |\n"
    else:
        md += "WHOIS data unavailable\n"

    # -------------------------
    # Subdomains Section
    # -------------------------
    md += "\n## 🏗️ Subdomain Inventory\n"
    subs = data.get('subdomains', {}).get('subdomains', [])
    if subs:
        md += "| Subdomain |\n|-----------|\n"
        for sub in subs:
            md += f"| {sub} |\n"
    else:
        md += "No subdomains detected\n"

    # -------------------------
    # SSL/TLS Section
    # -------------------------
    md += "\n## 🔒 SSL/TLS Analysis\n"
    ssl_data = data.get('ssl_tls', {})

    # 1) Certificate Expiry (Using `crt_sh` per prior JSON structure)
    md += "### 📅 Certificate Expiry\n"
    cert = ssl_data.get('crt_sh', {}).get('latest_certificate', {})
    if cert:
        try:
            not_after = cert.get('not_after', 'N/A')
            expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
            days_left = (expiry - datetime.utcnow()).days
            status = "Valid" if days_left > 0 else "Expired"
        except:
            status = "Unknown"
            days_left = "N/A"

        md += "| Parameter    | Value |\n|--------------|-------|\n"
        md += f"| Issuer       | {cert.get('issuer_name', 'N/A')} |\n"
        md += f"| Subject      | {cert.get('common_name', 'N/A')} |\n"
        md += f"| Valid From   | {cert.get('not_before', 'N/A')} |\n"
        md += f"| Valid Until  | {not_after} |\n"
        md += f"| Status       | {status} ({days_left} days left) |\n"
    else:
        md += "Certificate data unavailable\n"

    # 2) SSL Labs Report (Using `ssl_labs_cached`)
    md += "\n### 🛡️ SSL Labs Report\n"
    ssl_labs = ssl_data.get('ssl_labs_cached', {})
    if ssl_labs:
        md += f"**Grade:** {ssl_labs.get('grade', 'N/A')}\n\n"
        
        # Vulnerabilities Table
        md += "| Vulnerability | Status |\n|---------------|--------|\n"
        vulns = ssl_labs.get('vulnerabilities', {})
        for name, vuln_status in vulns.items():
            if vuln_status is None:
                status_mark = "⚠️ Unknown"
            elif vuln_status is False:
                status_mark = "✅ Not Vulnerable"
            elif vuln_status is True:
                status_mark = "❌ Vulnerable"
            else:
                status_mark = str(vuln_status)
            md += f"| {name.replace('_', ' ').title()} | {status_mark} |\n"

        # Supported Protocols
        md += "\n**Supported Protocols:**\n"
        protocols = ssl_labs.get('protocols', [])
        if protocols:
            md += ", ".join([f"{p.get('name', 'N/A')} {p.get('version', 'N/A')}" for p in protocols])
        else:
            md += "None detected"

        # Cipher Suites
        cipher_suites = ssl_labs.get('cipher_suites', [])
        if cipher_suites:
            md += "\n\n### 🛠️ Preferred Cipher Suites (TLS 1.2)\n"
            md += "| Cipher Suite | Strength | Key Exchange |\n|--------------|----------|--------------|"
            suites_list = cipher_suites[0].get('list', [])
            for suite in suites_list:
                name = suite.get('name', 'N/A')
                cipher_strength = suite.get('cipherStrength', 'N/A')
                kx_type = suite.get('kxType', 'N/A')
                kx_strength = suite.get('kxStrength', 'N/A')
                md += f"\n| {name} | {cipher_strength} | {kx_type} ({kx_strength}) |"
        else:
            md += "\nNo cipher suites detected for TLS 1.2.\n"
    else:
        md += "SSL Labs analysis unavailable\n"

    # 3) HSTS Configuration (Using `hsts_check`)
    md += "\n### 🔒 HSTS Configuration\n"
    hsts = ssl_data.get('hsts_check', {})
    if hsts:
        md += "| Parameter           | Value |\n|---------------------|-------|\n"
        md += f"| HSTS Enabled        | {'✅' if hsts.get('hsts_enabled') else '❌'} |\n"
        md += f"| Max Age             | {hsts.get('max_age', 'N/A')} |\n"
        md += f"| Include Subdomains  | {'✅' if hsts.get('include_subdomains') else '❌'} |\n"
        md += f"| Preload             | {'✅' if hsts.get('preload') else '❌'} |\n"
    else:
        md += "HSTS data unavailable\n"

    # 4) TLS Versions (Using `tls_versions`)
    md += "\n### 🔑 TLS Versions\n"
    tls = ssl_data.get('tls_versions', {})
    if tls:
        md += "| Parameter             | Value |\n|-----------------------|-------|\n"
        md += f"| Negotiated TLS        | {tls.get('negotiated_tls', 'N/A')} |\n"
        md += f"| Supports TLS 1.2      | {'✅' if tls.get('supports_tls_1_2') else '❌'} |\n"
        md += f"| Supports TLS 1.3      | {'✅' if tls.get('supports_tls_1_3') else '❌'} |\n"
        deprecated_list = tls.get('deprecated_versions', [])
        deprecated = ', '.join(deprecated_list) if deprecated_list else "None"
        md += f"| Deprecated Versions   | {deprecated} |\n"
    else:
        md += "TLS version data unavailable\n"

    # -------------------------
    # Technologies Section
    # -------------------------
    md += "\n## 🤖 Technology Stack\n"
    tech_data = data.get('technologies', {})
    techs = tech_data.get('Technologies', {})
    waf = tech_data.get('WAF', 'Not Detected')
    if techs:
        md += "| Product | Version | WAF |\n|---------|---------|-----|\n"
        for tech, version in techs.items():
            # Show a checkmark under WAF column if it matches the WAF detected
            is_waf = "✅" if tech == waf else ""
            md += f"| {tech} | {version or 'N/A'} | {is_waf} |\n"
    else:
        md += "No technologies detected\n"

    # -------------------------
    # CVE Analysis Section
    # -------------------------
    md += "\n## 🚨 Vulnerabilities Identified\n"
    cves = data.get('cve2', [])
    if cves:
        for item in cves:
            product = item.get('product', 'Unknown Product')
            version = item.get('version', 'Unknown Version')
            md += f"### {product} ({version})\n"
            md += "| Severity | CVE ID | CVSS Score | Mitigation |\n"
            md += "|----------|--------|------------|-----------|\n"
            for cve in item.get('cves', []):
                severity = cve.get('severity', 'Medium').upper()
                severity_class = severity.lower()
                cve_id = cve.get('cve_id', 'N/A')
                cvss_score = cve.get('cvss_score', 'N/A')
                mitigation = cve.get('mitigation', 'N/A').replace('\n', ' ')
                md += (
                    f"| <span class='{severity_class}'>{severity}</span> | "
                    f"{cve_id} | "
                    f"{cvss_score} | "
                    f"{mitigation} |\n"
                )
    else:
        md += "No vulnerabilities detected\n"

    return md


@router.get("/combined/{domain}")
async def combined_recon(domain: str):
    """
    Endpoint that gathers all data, then formats a comprehensive PDF report.
    Adjusted to match the 'ssl_labs_cached', 'crt_sh', 'hsts_check', 
    'tls_versions', and 'technologies' naming conventions.
    """
    try:
        # 1) Fetch all service data
        data = await fetch_all_data(domain)
        
        # 2) Generate Markdown content
        md_content = format_to_markdown(data, domain)
        
        # 3) Convert to PDF and return
        return markdown_to_pdf(
            md_content=md_content,
            domain=domain,
            report_type="Comprehensive Data Collection Report"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
