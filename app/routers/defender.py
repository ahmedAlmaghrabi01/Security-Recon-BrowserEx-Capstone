from fastapi import APIRouter, HTTPException
import aiohttp
from services.defender_service import fetch_recon_data, generate_defense_roadmap
from utils.pdf_converter import markdown_to_pdf

router = APIRouter()

@router.get("/roadmap/{domain}")
async def analyze_domain(domain: str):
    async with aiohttp.ClientSession() as session:
        try:
            # Pass both the session and domain
            recon_data = await fetch_recon_data(session, domain)
            roadmap = await generate_defense_roadmap(session, domain, recon_data)
            return markdown_to_pdf(roadmap, domain, "Defensive Security Report")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))