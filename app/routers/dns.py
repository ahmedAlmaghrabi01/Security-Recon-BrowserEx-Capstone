from fastapi import APIRouter, HTTPException, Query
from services.dns_service import get_dns_records
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

def format_dns_to_markdown(data: dict, domain: str) -> str:
    md = ""
    
    for record_type, records in data.items():
        md += f"## {record_type} Records\n\n"
        if record_type == "MX":
            md += "| Priority | Server |\n|----------|--------|\n"
            for record in records:
                priority, server = record.split(maxsplit=1)
                md += f"| {priority} | {server} |\n"
        else:
            md += "| Record |\n|--------|\n"
            for record in records:
                md += f"| {record} |\n"
        md += "\n"
    return md

@router.get("/dns/{domain}")
def dns_lookup(
    domain: str,
    format: str = Query("json", description="Response format: 'json' or 'pdf'")
):
    try:
        dns_data = get_dns_records(domain)
        
        if format.lower() == "pdf":
            md_content = format_dns_to_markdown(dns_data, domain)
            return markdown_to_pdf(md_content, domain, "DNS Records")
        
        return dns_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))