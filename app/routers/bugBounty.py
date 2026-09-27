from fastapi import APIRouter, HTTPException
import aiohttp
from services.bugBounty_service import fetch_recon_data, generate_attack_roadmap
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

@router.get("/analyze/{domain}")
async def analyze_domain(domain: str):
    async with aiohttp.ClientSession() as session:
        try:
            # Pass both the session and domain
            recon_data = await fetch_recon_data(session, domain)
            roadmap = await generate_attack_roadmap(session, domain, recon_data)
            return markdown_to_pdf(roadmap, domain, "Offensive Security Report")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
