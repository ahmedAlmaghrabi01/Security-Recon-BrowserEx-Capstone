from fastapi import APIRouter, HTTPException, Query
from services.ssl_tls_service import ssl_tls_analysis
from utils.pdf_converter import markdown_to_pdf
from datetime import datetime
import json

router = APIRouter()

def format_ssl_to_markdown(data: dict, domain: str) -> str:
    # Initialize md as an empty string
    md = ""

    # Certificate Expiry Analysis Section (Using `crt_sh` as in your sample JSON)
    md += "## 📅 Certificate Expiry Analysis\n"
    ssl_expiry = data.get("crt_sh", {}).get("latest_certificate")
    if ssl_expiry:
        not_before = ssl_expiry.get("not_before", "N/A")
        not_after = ssl_expiry.get("not_after", "N/A")
        issuer = ssl_expiry.get("issuer_name", "N/A")
        common_name = ssl_expiry.get("common_name", "N/A")
        san = ssl_expiry.get("name_value", "N/A").replace("\n", ", ")
        
        try:
            expiry_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
            status_str = "Expired" if expiry_date < datetime.utcnow() else "Valid"
            days_remaining = (expiry_date - datetime.utcnow()).days if status_str == "Valid" else 0
        except Exception:
            status_str = "Unknown"
            days_remaining = "N/A"
        
        md += "| Field               | Value |\n"
        md += "|---------------------|-------|\n"
        md += f"| **Issuer**          | {issuer} |\n"
        md += f"| **Common Name**     | {common_name} |\n"
        md += f"| **Subject Alt Names** | {san} |\n"
        md += f"| **Valid From**      | {not_before} |\n"
        md += f"| **Valid To**        | {not_after} |\n"
        md += f"| **Status**          | {status_str} |\n"
        md += f"| **Days Remaining**  | {days_remaining} |\n"
        md += f"| **Serial Number**   | {ssl_expiry.get('serial_number', 'N/A')} |\n\n"
    else:
        md += "Certificate expiry data unavailable.\n\n"
    
    # SSL Labs Report Section (Using `ssl_labs_cached` as in your sample JSON)
    md += "## 🛡️ SSL Labs Report\n"
    ssl_labs = data.get("ssl_labs_cached", {})
    if ssl_labs:
        grade = ssl_labs.get("grade", "N/A")
        md += f"**Grade:** {grade}\n\n"
        
        # Vulnerabilities Table
        md += "### Vulnerabilities\n"
        md += "| Vulnerability    | Status |\n"
        md += "|------------------|--------|\n"
        vulnerabilities = ssl_labs.get("vulnerabilities", {})
        for vuln, status in vulnerabilities.items():
            vuln_name = vuln.replace("_", " ").title()
            if isinstance(status, bool):
                # If status is a boolean: False → "Not Vulnerable", True → "Vulnerable"
                status_str = "Not Vulnerable ✅" if status is False else "Vulnerable ❌"
            elif status is None:
                status_str = "Status Unknown ⚠️"
            else:
                status_str = str(status)
            md += f"| {vuln_name} | {status_str} |\n"
        md += "\n"
        
        # Supported Protocols Table
        protocols = ssl_labs.get("protocols", [])
        md += "### Supported Protocols\n"
        md += "| Protocol | Version |\n"
        md += "|----------|---------|\n"
        for proto in protocols:
            md += f"| {proto.get('name', 'N/A')} | {proto.get('version', 'N/A')} |\n"
        md += "\n"
        
        # Preferred Cipher Suites Table (from the first cipher block, if any)
        cipher_suites = ssl_labs.get("cipher_suites", [])
        if cipher_suites:
            first_cipher_block = cipher_suites[0]
            md += "### Preferred Cipher Suites\n"
            md += "| Cipher Suite Name | Cipher Strength | Key Exchange Type | Key Exchange Strength |\n"
            md += "|-------------------|-----------------|-------------------|-----------------------|\n"
            for suite in first_cipher_block.get("list", []):
                name = suite.get("name", "N/A")
                cipher_strength = suite.get("cipherStrength", "N/A")
                kx_type = suite.get("kxType", "N/A")
                kx_strength = suite.get("kxStrength", "N/A")
                md += f"| {name} | {cipher_strength} | {kx_type} | {kx_strength} |\n"
            md += "\n"
    else:
        md += "SSL Labs data unavailable.\n\n"
    
    # HSTS Configuration Section
    md += "## 🔒 HSTS Configuration\n"
    hsts = data.get("hsts_check", {})
    if hsts:
        md += "| HSTS Enabled | Max Age | Include Subdomains | Preload |\n"
        md += "|--------------|---------|--------------------|---------|\n"
        md += f"| {hsts.get('hsts_enabled', 'N/A')} | {hsts.get('max_age', 'N/A')} | {hsts.get('include_subdomains', 'N/A')} | {hsts.get('preload', 'N/A')} |\n\n"
    else:
        md += "HSTS configuration data unavailable.\n\n"
    
    # TLS Versions Section
    md += "## 🔑 TLS Versions\n"
    tls = data.get("tls_versions", {})
    if tls:
        md += "| Negotiated TLS | Supports TLS 1.2 | Supports TLS 1.3 | Deprecated Versions |\n"
        md += "|----------------|------------------|------------------|---------------------|\n"
        deprecated_list = tls.get("deprecated_versions", [])
        deprecated = ', '.join(deprecated_list) if deprecated_list else "None"
        md += f"| {tls.get('negotiated_tls', 'N/A')} | {tls.get('supports_tls_1_2', 'N/A')} | {tls.get('supports_tls_1_3', 'N/A')} | {deprecated} |\n\n"
    else:
        md += "TLS version data unavailable.\n\n"
    
    return md


@router.get("/ssl_tls/{domain}")
async def ssl_tls_lookup(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    """
    Endpoint to fetch SSL/TLS analysis data and optionally export as PDF.
    
    - /ssl_tls/{domain}?format=json -> Returns JSON.
    - /ssl_tls/{domain}?format=pdf -> Returns PDF with a Markdown-based report.
    """
    try:
        # 1) Perform the SSL/TLS analysis (which presumably returns the JSON structure you showed).
        result = await ssl_tls_analysis(domain)
        data = json.loads(result)  # 'result' is a JSON string, so parse to dict

        # 2) Decide on output format
        if format.lower() == "pdf":
            md_content = format_ssl_to_markdown(data, domain)
            return markdown_to_pdf(
                md_content=md_content,
                domain=domain,
                report_type="SSL/TLS Security Report"
            )
        else:
            # Return the raw JSON
            return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL/TLS analysis failed: {str(e)}")
