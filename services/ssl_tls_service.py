import asyncio
import aiohttp
import ssl
import socket
import json
from aiohttp import ClientSession
from datetime import datetime

# -----------------------------
# Passive SSL Labs Check (Cached Only)
# -----------------------------
async def check_ssl_labs_cached(domain: str, session: ClientSession) -> dict:
    """
    Query SSL Labs API for a given domain using fromCache=on.
    This will NOT trigger a new scan. If no cached results exist, 
    it returns an error instead of scanning the target anew.
    """
    base_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {
        "host": domain,
        "publish": "off",
        "all": "on",
        "fromCache": "on",  # <-- This ensures we do NOT trigger a fresh scan
    }

    try:
        async with session.get(base_url, params=params, timeout=10) as resp:
            data = await resp.json()
    except Exception as e:
        return {"status": "error", "message": f"SSL Labs check failed: {e}"}

    status = data.get("status")
    if status is None:
        # Means no data/cached results at all
        return {"status": "no_cached_data", "message": "No cached SSL Labs data found."}

    if status in ["READY", "ERROR"]:
        if status == "READY":
            endpoints = data.get("endpoints", [])
            if not endpoints:
                return {"status": "error", "message": "No endpoints returned in cached data."}
            details = endpoints[0].get("details", {})
            return {
                "status": "READY",
                "grade": endpoints[0].get("grade"),
                "vulnerabilities": {
                    "heartbleed": details.get("heartbleed"),
                    "poodle": details.get("poodle"),
                    "freak": details.get("freak"),
                    "logjam": details.get("logjam"),
                    "drown": details.get("drownVulnerable"),
                    "openSslCcs": details.get("openSslCcs"),
                },
                "protocols": details.get("protocols"),
                "cipher_suites": details.get("suites"),
            }
        else:
            return {"status": "error", "message": data.get("statusMessage", "Unknown error")}
    else:
        # Something else: e.g., "IN_PROGRESS" or no status
        # We do NOT wait/poll because we never want to trigger or wait for new scans
        return {"status": "no_cached_data", "message": f"Current status: {status}"}


# -----------------------------
# Passive SSL Expiry Check (crt.sh)
# -----------------------------
async def check_ssl_expiry(domain: str, session: ClientSession) -> dict:
    """
    Checks SSL certificate data from crt.sh for the given domain.
    This is a purely passive check from the domain's perspective.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        async with session.get(url, timeout=10) as resp:
            if resp.status == 200:
                certs = await resp.json()
                if certs:
                    # Return the most recent certificate record
                    return {"latest_certificate": certs[0]}
                else:
                    return {"error": "No SSL certificates found on crt.sh."}
            else:
                return {"error": f"crt.sh error. HTTP Status: {resp.status}"}
    except asyncio.TimeoutError:
        return {"error": "crt.sh request timed out."}
    except Exception as e:
        return {"error": f"crt.sh request failed: {e}"}


# -----------------------------
# Low-Noise HSTS Header Check (Optional)
# -----------------------------
async def check_hsts(domain: str, session: ClientSession) -> dict:
    """
    Sends ONE HTTPS request to check for HSTS (Strict-Transport-Security) headers.
    If you want a fully passive approach, omit calling this function.
    """
    url = f"https://{domain}"
    try:
        async with session.get(url, timeout=10, allow_redirects=True) as resp:
            hsts_header = resp.headers.get('Strict-Transport-Security', '')
            return {
                "hsts_enabled": bool(hsts_header),
                "max_age": _parse_max_age(hsts_header),
                "include_subdomains": "includesubdomains" in hsts_header.lower(),
                "preload": "preload" in hsts_header.lower(),
            }
    except asyncio.TimeoutError:
        return {"error": "HSTS check timed out (low-noise request)."}
    except Exception as e:
        return {"error": f"HSTS check failed (low-noise request): {e}"}

def _parse_max_age(hsts_header: str) -> int:
    """
    Extract the max-age value from the HSTS header if present.
    """
    if 'max-age=' in hsts_header.lower():
        try:
            part = hsts_header.lower().split('max-age=')[1].split(';')[0].strip()
            return int(part)
        except ValueError:
            pass
    return 0


# -----------------------------
# Low-Noise TLS Version Check (Optional)
# -----------------------------
def check_tls_versions(domain: str) -> dict:
    """
    Opens exactly ONE TCP connection to domain:443 to see the negotiated TLS version.
    If you want a purely passive approach, omit calling this function.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                negotiated_version = ssock.version()
                return {
                    "negotiated_tls": negotiated_version,
                    "supports_tls_1_3": (negotiated_version == "TLSv1.3"),
                    "supports_tls_1_2": (negotiated_version == "TLSv1.2"),
                    "deprecated_versions": [
                        v for v in ["TLSv1", "TLSv1.1"] if v in negotiated_version
                    ],
                }
    except Exception as e:
        return {"error": f"Failed to check TLS versions (low-noise request): {e}"}


# -----------------------------
# Comprehensive Analysis (Passive + Low Noise)
# -----------------------------
async def ssl_tls_analysis(domain: str, do_low_noise_checks: bool = True) -> str:
    """
    - Retrieves cached SSL Labs data (PASSIVE - no new scans).
    - Retrieves certificate data from crt.sh (PASSIVE).
    - Optionally does single HSTS check (LOW NOISE).
    - Optionally does single TLS handshake check (LOW NOISE).
    
    Returns a JSON-formatted string with collected results.
    """
    async with aiohttp.ClientSession() as session:
        # Passive checks:
        ssl_labs_task = asyncio.create_task(check_ssl_labs_cached(domain, session))
        ssl_expiry_task = asyncio.create_task(check_ssl_expiry(domain, session))

        if do_low_noise_checks:
            hsts_check_task = asyncio.create_task(check_hsts(domain, session))
            tls_versions_task = asyncio.create_task(asyncio.to_thread(check_tls_versions, domain))
            ssl_labs_res, ssl_expiry_res, hsts_res, tls_res = await asyncio.gather(
                ssl_labs_task, ssl_expiry_task, hsts_check_task, tls_versions_task
            )
        else:
            ssl_labs_res, ssl_expiry_res = await asyncio.gather(ssl_labs_task, ssl_expiry_task)
            hsts_res = {"skipped": "HSTS check disabled"}
            tls_res = {"skipped": "TLS version check disabled"}

    results = {
        "domain": domain,
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "ssl_labs_cached": ssl_labs_res,    # passive
        "crt_sh": ssl_expiry_res,          # passive
        "hsts_check": hsts_res,            # low-noise
        "tls_versions": tls_res            # low-noise
    }

    return json.dumps(results, indent=4)


# -----------------------------
# Main Execution Example
# -----------------------------
if __name__ == "__main__":
    # Example usage:
    test_domain = input("Enter a domain: ").strip()
    # Set do_low_noise_checks=False if you want purely passive
    print(asyncio.run(ssl_tls_analysis(test_domain, do_low_noise_checks=True)))
