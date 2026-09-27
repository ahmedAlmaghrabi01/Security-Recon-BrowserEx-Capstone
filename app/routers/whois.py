from fastapi import APIRouter, HTTPException, Query
from services.whois_service import get_whois_data
from utils.pdf_converter import markdown_to_pdf
import json

router = APIRouter()

def format_whois_to_markdown(data: dict, domain: str) -> str:
    """
    Format WHOIS data into a professional Markdown report with enhanced styling for raw data.
    """
    # Initialize md as an empty string
    md = ""
    
    # General Information Section
    md += "## 📋 Registration Information\n"
    md += "| Field | Value |\n|-------|-------|\n"
    md += f"| Registrar | {data.get('registrar', 'Not available')} |\n"
    md += f"| Creation Date | {data.get('creation_date', 'Not available')} |\n"
    md += f"| Expiration Date | {data.get('expiration_date', 'Not available')} |\n"
    md += f"| Status | {data.get('status', 'Not available')} |\n\n"
    
    # Technical Details Section
    md += "## 🔧 Technical Details\n"
    md += "| Name Servers | DNSSEC |\n|-------------|--------|\n"
    name_servers = ', '.join(data.get('name_servers', [])) if isinstance(data.get('name_servers'), list) else 'Not available'
    dnssec_status = data.get('dnssec', 'Not enabled')
    md += f"| {name_servers} | {dnssec_status} |\n\n"
    
    # Raw WHOIS Data Section
    raw_data = data.get('raw_data', '{}')
    if isinstance(raw_data, dict):
        raw_data = json.dumps(raw_data, indent=2)  # Ensure JSON is properly formatted
    elif not isinstance(raw_data, str):
        raw_data = str(raw_data)  # Convert non-string types to string
    
    # Add a visually appealing block for raw data
    md += "## 📄 Raw WHOIS Data\n"
    md += "<div style='background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto;'>\n"
    md += f"<pre style='font-family: monospace; white-space: pre-wrap;'>{raw_data}</pre>\n"
    md += "</div>\n"

    return md

@router.get("/whois/{domain}")
async def whois_lookup(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    """
    Retrieve WHOIS information for a domain with format options.
    - `format`: Specify 'json' for raw JSON output or 'pdf' for a styled PDF report.
    """
    try:
        # Fetch WHOIS data
        whois_data = get_whois_data(domain)
        
        # Return as PDF if requested
        if format.lower() == "pdf":
            md_content = format_whois_to_markdown(whois_data, domain)
            return markdown_to_pdf(md_content, domain, "WHOIS Records")
        
        # Default to JSON response
        return whois_data
    
    except Exception as e:
        # Log the error and raise an HTTP exception
        print(f"Error fetching WHOIS data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve WHOIS data: {str(e)}")