from fastapi import APIRouter, HTTPException, Query
from services.tech_service import analyze_technologies
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

def format_tech_to_markdown(data: dict, domain: str) -> str:
    """
    Format technology data into Markdown efficiently.
    Assumes 'data' follows the structure:
    {
      "Technologies": { <tech>: <version> },
      "WAF": "<WAF Name or 'Not Detected'>"
    }
    """
    md_lines = ["## Detected Tech Stack\n"]
    techs = data.get("Technologies", {})

    # Build main table
    if techs:
        md_lines.extend([
            "| Product | Version | WAF |\n",
            "|---------|---------|-----|\n"
        ])
        waf_str = data.get("WAF", "").lower()  # e.g., "imperva", "not detected", etc.
        for tech, version in techs.items():
            # Put a checkmark if this tech matches the WAF name
            waf_status = "✅" if tech.lower() == waf_str else ""
            md_lines.append(f"| {tech} | {version or 'N/A'} | {waf_status} |\n")
    else:
        md_lines.append("No technologies detected.\n")

    # Conditionally show callout if a WAF is truly detected
    # (i.e., not empty, not "Not Detected", etc.)
    actual_waf = data.get("WAF", "")
    if actual_waf and actual_waf.lower() != "not detected":
        md_lines.append(
            f"\n\n<div class='callout-red'>**WAF Detected**: {actual_waf}</div>\n"
        )
    
    return "".join(md_lines)

@router.get("/tech/{domain}")
async def tech_detection(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    """
    Detect website technologies with JSON/PDF output options asynchronously.
    """
    try:
        # Ensure proper URL formatting
        if not domain.startswith(("http://", "https://")):
            domain = "https://" + domain

        # Call the asynchronous service function
        tech_data = await analyze_technologies(domain)
        
        # Return PDF or JSON based on query parameter
        if format.lower() == "pdf":
            md_content = format_tech_to_markdown(tech_data, domain)
            return markdown_to_pdf(
                md_content,
                domain=domain,
                report_type="Tech Stack Detection"
            )
        
        # Default to JSON response
        return tech_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
