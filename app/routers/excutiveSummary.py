from fastapi import APIRouter, HTTPException
import aiohttp
from services.ExcutiveSummary_service import fetch_recon_data, generate_nontechnical_roadmap
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

@router.get("/report/{domain}")
async def analyze_domain(domain: str):
    async with aiohttp.ClientSession() as session:
        try:
            # Pass both the session and domain
            recon_data = await fetch_recon_data(session, domain)
            roadmap = await generate_nontechnical_roadmap(session, domain, recon_data)
            return markdown_to_pdf(roadmap, domain, "Non-Techincal Security Report")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))