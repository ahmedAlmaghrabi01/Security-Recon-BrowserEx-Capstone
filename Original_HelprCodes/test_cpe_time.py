import asyncio
import aiohttp
import urllib.parse
import time
import os

# API Key for NVD API
API_KEY = os.getenv("NVD_API_KEY", "")

# API Rate Limit Handling
MAX_RETRIES = 5
TIMEOUT = 30

async def fetch(session, url, params=None):
    """Handles asynchronous API calls with retry logic."""
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, headers=headers, params=params, timeout=TIMEOUT) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    wait_time = (2 ** attempt) + 1
                    print(f"Rate limit reached. Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    print(f"API Error {response.status}: {await response.text()}")
                    return None
        except Exception as e:
            print(f"Request failed (Attempt {attempt + 1}/{MAX_RETRIES}): {e}")
            await asyncio.sleep(2)
    return None

import urllib.parse
import re
import aiohttp

# 1. Known Vendors Mapping
known_vendors = {
    # Microsoft Ecosystem
    "windows": "microsoft",
    "office": "microsoft",
    "excel": "microsoft",
    "word": "microsoft",
    "powerpoint": "microsoft",
    "onenote": "microsoft",
    "sharepoint": "microsoft",
    "sql_server": "microsoft",
    "ms_sql_server": "microsoft",
    "edge": "microsoft",
    "internet_explorer": "microsoft",
    "visual_studio": "microsoft",
    "visual_studio_code": "microsoft",
    "dotnet": "microsoft",
    "dotnet_core": "microsoft",
    "xbox": "microsoft",

    # Google Ecosystem
    "chrome": "google",
    "android": "google",
    "chrome_os": "google",
    "google_cloud_platform": "google",

    # Mozilla Ecosystem
    "firefox": "mozilla",
    "thunderbird": "mozilla",

    # Oracle Ecosystem
    "java": "oracle",
    "mysql": "oracle",
    "solaris": "oracle",
    "virtualbox": "oracle",
    "peoplesoft": "oracle",
    "siebel": "oracle",

    # Apache Ecosystem
    "http_server": "apache",
    "apache_http_server": "apache",
    "tomcat": "apache",
    "maven": "apache",
    "cassandra": "apache",
    "zookeeper": "apache",
    "kafka": "apache",
    "openoffice": "apache",
    "couchdb": "apache",

    # Red Hat & Similar
    "rhel": "redhat",
    "redhat_enterprise_linux": "redhat",
    "fedora": "fedora",
    "centos": "centos",
    "almalinux": "almalinux",
    "rocky_linux": "rocky",

    # Linux Distros
    "ubuntu": "canonical",
    "debian": "debian",
    "suse": "suse",
    "opensuse": "suse",
    "arch_linux": "arch",
    "amazon_linux": "amazon",

    # IBM Ecosystem
    "aix": "ibm",
    "db2": "ibm",
    "websphere": "ibm",
    "lotus_notes": "ibm",
    "domino": "ibm",

    # Apple Ecosystem
    "ios": "apple",
    "mac_os": "apple",
    "macos": "apple",

    # Adobe Ecosystem
    "flash_player": "adobe",
    "acrobat": "adobe",
    "adobe_reader": "adobe",
    "photoshop": "adobe",
    "illustrator": "adobe",
    "magento": "adobe",

    # F5 Ecosystem
    "nginx": "f5",

    # OpenSSL
    "openssl": "openssl",

    # Web CMS / Platforms
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",

    # Atlassian Ecosystem
    "confluence": "atlassian",
    "jira": "atlassian",
    "bitbucket": "atlassian",
    "bamboo": "atlassian",
    "crowd": "atlassian",
    "fisheye": "atlassian",
    "crucible": "atlassian",

    # Docker / CNCF
    "docker": "docker",
    "kubernetes": "cncf",
    "prometheus": "cncf",
    "helm": "cncf",
    "etcd": "cncf",

    # Languages & Runtimes
    "php": "php",
    "python": "python",
    "perl": "perl",
    "ruby": "ruby",
    "rails": "rubyonrails",
    "golang": "golang",
    "nodejs": "nodejs",

    # Databases
    "postgresql": "postgresql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "redis": "redis",
    "couchbase": "couchbase",

    # Git / DevOps
    "gitlab": "gitlab",
    "github_desktop": "github",
    "jenkins": "jenkins",

    # Other Notables
    "lighttpd": "lighttpd",
    "haproxy": "haproxy",
    "iis": "microsoft",
    "varnish": "varnish",
    "nghttp2": "nghttp2",

    # Security Tools
    "wireshark": "wireshark",
    "nmap": "insecure_org",  # "insecure.org" is official vendor
    "metasploit": "rapid7",
    "nessus": "tenable",
}


def _guess_vendor(component: str) -> str:
    """
    Attempt to guess a vendor name based on the known_vendors map.
    If no match is found, returns a sanitized version of the component.
    """
    normalized = component.lower().replace(" ", "_")
    return known_vendors.get(normalized, normalized)


def _build_fallback_cpe(component: str, version: str) -> str:
    """
    Build a 'best guess' fallback CPE string if no valid matches were found.
    Incorporates guessed vendor, sanitized product name, and version number.
    """
    vendor = _guess_vendor(component)
    product = component.replace(" ", "_").lower()
    # Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


async def find_cpes(session, component: str, version: str, max_results: int = 40):
    """
    Searches the NVD 2.0 CPE API for a given component and version.

    1. Builds a query string using 'component' + 'version'.
    2. Fetches up to 100 results from the NVD CPE 2.0 endpoint.
    3. Collects any valid CPE URIs (v2.2 or v2.3).
    4. Filters:
       a) Exact version matches (":<version>:").
       b) Partial product name matches.
       c) Truncates if more than max_results remain.
    5. If no matches, returns a best-guess fallback CPE.

    Parameters
    ----------
    session : aiohttp.ClientSession
        Active session for making asynchronous HTTP requests.
    component : str
        Name of the component (e.g., 'nginx' or 'http_server').
    version : str
        Specific version number (e.g., '1.18.0').
    max_results : int, optional
        Maximum number of CPE URIs to return, by default 40.

    Returns
    -------
    List[str]
        A filtered/truncated list of CPE URIs, or a fallback in case no results.
    """
    # Sanity check
    if not component or not version:
        return []

    # Prepare the query
    base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    query = f"{component} {version}".strip()
    encoded_query = urllib.parse.quote(query)
    url = f"{base_url}?keywordSearch={encoded_query}&resultsPerPage=100"

    # Fetch data from NVD
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return [_build_fallback_cpe(component, version)]
            data = await resp.json()
    except Exception:
        # Network or JSON parsing failure
        return [_build_fallback_cpe(component, version)]

    # NVD returns results in "products" or "cpes"
    cpes_data = data.get("products", []) or data.get("cpes", [])

    # Collect all discovered CPE URIs
    all_cpes = {
        item.get("cpe", {}).get("cpeName", "") or item.get("cpe23Uri", "")
        for item in cpes_data
        if item.get("cpe", {}).get("cpeName", "") or item.get("cpe23Uri", "")
    }

    if not all_cpes:
        # No valid CPEs found from NVD
        return [_build_fallback_cpe(component, version)]

    # STEP 1: Filter by exact version if possible
    exact_matches = {
        cpe for cpe in all_cpes
        if f":{version}:" in cpe
    }
    if exact_matches:
        if len(exact_matches) <= max_results:
            return sorted(exact_matches)
        return sorted(exact_matches)[:max_results]

    # STEP 2: If no exact matches, try partial name matching
    component_regex = re.escape(component.lower())
    name_matches = {
        cpe for cpe in all_cpes
        if re.search(rf":[^:]*{component_regex}[^:]*:", cpe.lower())
    }
    if name_matches:
        if len(name_matches) <= max_results:
            return sorted(name_matches)
        return sorted(name_matches)[:max_results]

    # STEP 3: If neither filter yielded results, or we have too many, truncate or fallback
    if len(all_cpes) > max_results:
        return sorted(all_cpes)[:max_results]

    # If we have fewer than max_results, just return everything
    return sorted(all_cpes)


async def main():
    # Manual input for technology and version
    component = input("Enter the technology (e.g., Apache HTTP Server): ").strip()
    version = input("Enter the version (e.g., 2.4.41): ").strip()

    start_time = time.time()  # Start timing

    async with aiohttp.ClientSession() as session:
        cpe_list = await find_cpes(session, component, version)

    end_time = time.time()  # End timing

    if cpe_list:
        print(f"\nFound {len(cpe_list)} CPEs for {component} {version}:")
        for cpe in cpe_list:
            print(cpe)
    else:
        print(f"\nNo CPEs found for {component} {version}.")

    print(f"\nTime taken: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    asyncio.run(main())
