from fastapi import APIRouter, HTTPException, Query
import aiohttp
import asyncio
from services.cve_service import process_technology, ensure_indexes
from wappalyzer import analyze
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

def format_cve_to_markdown(data: list, domain: str) -> str:
    md_lines = [""]
    if not data:
        md_lines.append("⚠️ No CVEs found for detected technologies\n")
        return "".join(md_lines)

    severity_order = ["Critical", "High", "Medium", "Low"]
    for severity in severity_order:
        filtered_cves = [
            {"product": entry.get("product", "Unknown"), "version": entry.get("version", ""), **cve}
            for entry in data
            for cve in entry.get("cves", [])
            if cve.get("severity", "Medium").capitalize() == severity
        ]
        if filtered_cves:
            md_lines.append(f"## {severity.upper()} VULNERABILITIES ({len(filtered_cves)})\n")
            # Updated table header with new columns
            md_lines.append("| SEVERITY | CVE ID | VULNERABLE TECHNOLOGY | TECHNOLOGY VERSION | CVSS SCORE | REFERENCES |\n")
            md_lines.append("|----------|--------|-----------------------|--------------------|------------|------------|\n")
            for cve in filtered_cves:
                # Extract and escape fields to prevent Markdown table breakage
                product = cve.get("product", "Unknown").replace("|", "\\|")
                version = cve.get("version", "N/A").replace("|", "\\|")
                severity_val = cve.get("severity", "Medium").upper()
                severity_class = cve.get("severity", "medium").lower()
                cve_id = cve.get("cve_id", "N/A")
                cvss_score = cve.get("cvss_score", "N/A")
                ref_link = cve.get("cve_link", "N/A")
                ref_markdown = f"[NVD Link]({ref_link})" if ref_link != "N/A" else "N/A"
                # Updated row with new columns
                md_lines.append(
                    f"| <span class='{severity_class}'>{severity_val}</span> "
                    f"| {cve_id} "
                    f"| {product} "
                    f"| {version} "
                    f"| {cvss_score} "
                    f"| {ref_markdown} |\n"
                )
            md_lines.append("\n")
    return "".join(md_lines)

@router.get("/cve/{domain}")
async def analyze_domain(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    try:
        await ensure_indexes()  # Ensure indexes are set up
        results = analyze(f"https://{domain}")
        product_versions = {
            tech_name: details.get("version", "").strip()
            for _, techs in results.items()
            for tech_name, details in techs.items()
            if details.get("version")
        }

        async with aiohttp.ClientSession() as session:
            tasks = [process_technology(product, version) for product, version in product_versions.items()]
            output_data = await asyncio.gather(*tasks, return_exceptions=True)

        filtered_data = [result for result in output_data if isinstance(result, dict) and result]

        if format.lower() == "pdf":
            md_content = format_cve_to_markdown(filtered_data, domain)
            return markdown_to_pdf(md_content, domain, "CVEs Detection")

        return {"target_domain": domain, "results": filtered_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")