from fastapi import APIRouter
import aiohttp
import asyncio
from services.config import API_ENDPOINTS, CVE2_ENDPOINT

router = APIRouter()

async def fetch_api_data(session: aiohttp.ClientSession, key: str, base_url: str, domain: str, recon_data: dict):
    """
    Helper function to fetch data from a single endpoint.
    Stores the result in the provided recon_data dict.
    """
    url = f"{base_url}{domain}"
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                recon_data[key] = await resp.json()
            else:
                recon_data[key] = {"error": f"Status code: {resp.status}"}
    except Exception as e:
        recon_data[key] = {"error": str(e)}

async def fetch_cve_data(session: aiohttp.ClientSession, tech_data: dict, recon_data: dict):
    """
    If technology data is available, post it to the CVE2 endpoint for vulnerability analysis.
    """
    post_body = {"Technologies": tech_data.get("Technologies", {})}
    try:
        async with session.post(CVE2_ENDPOINT, json=post_body) as cve2_resp:
            if cve2_resp.status == 200:
                cve2_data = await cve2_resp.json()
                recon_data["cve2"] = cve2_data.get("cve_results", [])
            else:
                recon_data["cve2"] = {"error": f"Status code: {cve2_resp.status}"}
    except Exception as e:
        recon_data["cve2"] = {"error": str(e)}

async def fetch_all_data(domain: str) -> dict:
    """
    Fetches DNS, WHOIS, Subdomains, Technologies concurrently.
    If technologies data is available, it posts the tech data to the CVE2 endpoint
    to retrieve vulnerability analysis. Returns a unified JSON dictionary.
    """
    recon_data = {}
    tasks = []

    async with aiohttp.ClientSession() as session:
        # Fetch DNS, WHOIS, Subdomains, and Technologies concurrently.
        for key, base_url in API_ENDPOINTS.items():
            tasks.append(fetch_api_data(session, key, base_url, domain, recon_data))
        await asyncio.gather(*tasks)

        # If technology data is available, post to the CVE2 endpoint.
        tech_data = recon_data.get("technologies")
        if isinstance(tech_data, dict):
            await fetch_cve_data(session, tech_data, recon_data)
        print(recon_data)
    return recon_data
