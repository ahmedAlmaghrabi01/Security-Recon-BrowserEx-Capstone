import aiohttp
import asyncio
from wappalyzer import analyze
from typing import Dict, Any, Optional
import logging
import json

# Set up logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def fetch_response(url: str) -> Optional[Dict[str, str]]:
    """
    Fetch HTTP response headers asynchronously with a timeout,
    using a typical browser-like User-Agent and standard headers.
    """
    browser_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/90.0.4430.85 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=browser_headers,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=False
            ) as response:
                response.raise_for_status()
                # Convert headers to lowercase keys and values for easier matching
                return {k.lower(): v.lower() for k, v in response.headers.items()}
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching {url}")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

def detect_waf(headers: Dict[str, str]) -> str:
    """
    Detect Web Application Firewall (WAF) based on HTTP response headers.
    Uses a mapping of known WAF signatures to identify the service.
    """
    waf_signatures = {
        # Popular Cloud-Based WAFs
        "cloudflare": "Cloudflare",
        "cf-ray": "Cloudflare",
        "akamai": "Akamai",
        "imperva": "Imperva",
        "incapsula": "Imperva Incapsula",
        "aws": "AWS WAF",
        "azure": "Azure Front Door WAF",
        "google": "Google Cloud Armor",
        # Enterprise and Hardware-Based WAFs
        "f5": "F5 BIG-IP",
        "barracuda": "Barracuda WAF",
        "citrix": "Citrix ADC",
        "fortinet": "FortiWeb",
        "paloalto": "Palo Alto Prisma Cloud",
        "radware": "Radware AppWall",
        # Open Source and Community WAFs
        "mod_security": "ModSecurity",
        "denyall": "DenyALL",
        "naxsi": "NAXSI",
        "owasp": "OWASP Core Rule Set",
        # CDN and Security Providers
        "sucuri": "Sucuri",
        "stackpath": "StackPath",
        "maxcdn": "MaxCDN WAF",
        "varnish": "Varnish Cache",
        "limelight": "Limelight Networks",
        # Other Common WAFs
        "dotdefender": "dotDefender",
        "binarysec": "BinarySec",
        "comodo": "Comodo WAF",
        "profense": "Profense",
        "wallarm": "Wallarm",
        "indusface": "Indusface WAS",
        "reblaze": "Reblaze",
        "perimeterx": "PerimeterX",
        "signal_sciences": "Signal Sciences",
        "apptrana": "AppTrana",
        "approov": "Approov",
    }

    if not headers:
        return "Not Detected"

    # Single-pass detection for efficiency.
    for key, value in headers.items():
        key_lower = key.lower()
        value_lower = value.lower()
        if key_lower in waf_signatures:
            return waf_signatures[key_lower]
        for signature, name in waf_signatures.items():
            if signature in value_lower:
                return name

    return "Not Detected"

async def analyze_technologies(domain: str) -> Dict[str, Any]:
    """
    Analyze technologies used on a website using Wappalyzer and detect WAF asynchronously.
    Returns a dictionary with detected technologies and WAF information.
    """
    try:
        # Ensure the domain has an HTTP/HTTPS prefix.
        url = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"

        # Fetch headers asynchronously.
        headers = await fetch_response(url)
        if not headers:
            return {"error": "Failed to fetch website response."}

        # Detect WAF.
        waf_detected = detect_waf(headers)

        # Analyze technologies using Wappalyzer (assumed synchronous).
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, lambda: analyze(url=url))
        technologies = {
            tech: details.get("version", "Unknown")
            for detected_url, techs in results.items()
            for tech, details in techs.items()
        }

        return {
            "Technologies": technologies,
            "WAF": waf_detected
        }

    except aiohttp.ClientError as e:
        logger.error(f"Network error analyzing {domain}: {e}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error analyzing {domain}")
        return {"error": f"An error occurred: {str(e)}"}

if __name__ == "__main__":
    domain = input("Enter the domain name: ").strip()
    result = asyncio.run(analyze_technologies(domain))
    print(json.dumps(result, indent=4))