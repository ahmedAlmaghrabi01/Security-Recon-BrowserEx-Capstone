"""Shared runtime configuration loaded from environment variables."""

import os


INTERNAL_API_BASE_URL = os.getenv("INTERNAL_API_BASE_URL", "http://localhost:8000").rstrip("/")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")


def api_url(path: str) -> str:
    return f"{INTERNAL_API_BASE_URL}/{path.lstrip('/')}"


API_ENDPOINTS = {
    "dns": api_url("api/dns/dns/"),
    "whois": api_url("api/whois/whois/"),
    "subdomains": api_url("api/subdomains/subdomains/"),
    "technologies": api_url("api/tech/tech/"),
    "ssl_tls": api_url("api/ssl_tls/ssl_tls/"),
}

CVE2_ENDPOINT = api_url("api/cve2/process")
