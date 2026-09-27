from fastapi import APIRouter, HTTPException, Query
from services.subdomain_service import find_subdomains
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

def format_subdomains_to_markdown(domain: str, subdomains: list) -> str:
    # Initialize md with a title
    md = ""
    
    # Add the subdomains section
    md += "## Discovered Subdomains\n\n"
    md += "| Subdomain |\n|----------|\n"
    for sub in subdomains:
        md += f"| {sub} |\n"
    
    return md


@router.get("/subdomains/{domain}")
def subdomain_lookup(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    try:
        data = find_subdomains(domain)
        if "error" in data:
            raise HTTPException(status_code=500, detail=data["error"])
        
        if format.lower() == "pdf":
            md_content = format_subdomains_to_markdown(domain, data.get("subdomains", []))
            return markdown_to_pdf(md_content, domain, "Subdomains Inventory")
        
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
