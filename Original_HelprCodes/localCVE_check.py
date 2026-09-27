import asyncio
import aiohttp
import json
import urllib.parse
import time
import re
import os
from wappalyzer import analyze
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from packaging import version

import motor.motor_asyncio

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "cve_db"
COLLECTION_NAME = "cve"

# Create Motor client and collection reference
mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
cve_collection = mongo_client[DB_NAME][COLLECTION_NAME]

# API Key for NVD API
API_KEY = os.getenv("NVD_API_KEY", "")

# API Rate Limit Handling
MAX_RETRIES = 5
TIMEOUT = 30


def get_cvss_severity(score):
    """Classifies CVSS scores into severity levels."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "N/A"

def get_mitigation_recommendation(severity):
    """Generates mitigation advice based on severity and reference URLs."""
    base_advice = {
        "Critical": "Immediate action required. Apply patches immediately. Isolate affected systems if possible.",
        "High": "Prioritize patching. Implement temporary workarounds while update is pending.",
        "Medium": "Schedule update during next maintenance window. Monitor for exploit attempts.",
        "Low": "Evaluate impact and update when convenient. Consider security controls.",
        "N/A": "Review vulnerability details for appropriate action."
    }.get(severity, "Review vulnerability details for appropriate action.")

    return base_advice

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

def in_version_range(
    user_version_str: str,
    version_start_including: str = None,
    version_end_including: str = None,
    version_start_excluding: str = None,
    version_end_excluding: str = None,
) -> bool:
    if not user_version_str:
        return False
    
    user_v = version.parse(user_version_str)

    if version_start_including and user_v < version.parse(version_start_including):
        return False
    if version_start_excluding and user_v <= version.parse(version_start_excluding):
        return False
    if version_end_including and user_v > version.parse(version_end_including):
        return False
    if version_end_excluding and user_v >= version.parse(version_end_excluding):
        return False

    return True


async def find_cpes(session, component: str, version: str, max_results: int = 40):
    """
    Searches the NVD 2.0 CPE API for a given component and version.
    """
    start_time = time.time()  # Start timer for CPE retrieval

    if not component or not version:
        return []

    base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    query = f"{component} {version}".strip()
    encoded_query = urllib.parse.quote(query)
    url = f"{base_url}?keywordSearch={encoded_query}&resultsPerPage=100"

    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return [_build_fallback_cpe(component, version)]
            data = await resp.json()
    except Exception:
        return [_build_fallback_cpe(component, version)]

    cpes_data = data.get("products", []) or data.get("cpes", [])
    all_cpes = {
        item.get("cpe", {}).get("cpeName", "") or item.get("cpe23Uri", "")
        for item in cpes_data
        if item.get("cpe", {}).get("cpeName", "") or item.get("cpe23Uri", "")
    }

    if not all_cpes:
        return [_build_fallback_cpe(component, version)]

    end_time = time.time()  # End timer for CPE retrieval
    print(f"CPE Retrieval Time: {end_time - start_time:.2f} seconds")

    exact_matches = {cpe for cpe in all_cpes if f":{version}:" in cpe}
    if exact_matches:
        return sorted(exact_matches)[:max_results]

    component_regex = re.escape(component.lower())
    name_matches = {cpe for cpe in all_cpes if re.search(rf":[^:]*{component_regex}[^:]*:", cpe.lower())}
    return sorted(name_matches)[:max_results] if name_matches else sorted(all_cpes)[:max_results]


async def get_cves_for_cpe_local(cpe_uri_with_version: str, user_version: str):
    """
    1) Query local dataset for the exact 'cpe_uri_with_version'.
    2) If none found, convert cpe_uri_with_version to a wildcard version form,
       e.g. "cpe:2.3:a:jquery:jquery_ui:*:*:*:*:*:*:*:*"
    3) For each matching doc, check the user_version is within the doc's range fields.
    4) Return only those CVEs that truly affect user_version.
    """
    start_time = time.time()

    # Step A: Attempt exact match
    print(f"Trying exact match for {cpe_uri_with_version}")
    cursor = cve_collection.find({
        "configurations.nodes.cpe_match.cpe23Uri": cpe_uri_with_version
    })

    docs = [doc async for doc in cursor]
    if not docs:
        # Step B: Fallback to wildcard
        # Replace the version in field #4 with '*'
        # cpe:2.3:a:vendor:product:version => cpe:2.3:a:vendor:product:*
        # "cpe:2.3:a:jquery:jquery_ui:1.10.4:*:*:*:*:*:*:*"
        #   => "cpe:2.3:a:jquery:jquery_ui:*:*:*:*:*:*:*:*"
        parts = cpe_uri_with_version.split(":")
        if len(parts) >= 6:
            parts[5] = "*"  # index 5 is the version
            wildcard_cpe = ":".join(parts)
            print(f"No exact match, trying wildcard => {wildcard_cpe}")

            cursor = cve_collection.find({
                "configurations.nodes.cpe_match.cpe23Uri": wildcard_cpe
            })
            docs = [doc async for doc in cursor]

    # Now 'docs' could be empty or a list of CVE documents referencing either the exact CPE or wildcard
    results = []
    for doc in docs:
        cve_id = doc.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue
        
        # Check if user_version is in the doc's version range
        in_range_flag = False

        # We must iterate all cpe_match objects
        for node in doc.get("configurations", {}).get("nodes", []):
            for cpe_m in node.get("cpe_match", []):
                if cpe_m.get("cpe23Uri") not in (cpe_uri_with_version, wildcard_cpe if docs else None):
                    # skip if cpe23Uri is something else
                    continue

                # Extract range fields
                v_start_incl = cpe_m.get("versionStartIncluding")
                v_start_excl = cpe_m.get("versionStartExcluding")
                v_end_incl   = cpe_m.get("versionEndIncluding")
                v_end_excl   = cpe_m.get("versionEndExcluding")

                if (v_start_incl or v_start_excl or v_end_incl or v_end_excl):
                    if in_version_range(user_version, v_start_incl, v_end_incl, v_start_excl, v_end_excl):
                        in_range_flag = True
                        break
                else:
                    # no range => assume it's valid
                    in_range_flag = True
                    break
            if in_range_flag:
                break
        
        if not in_range_flag:
            continue

        # If we reached here => user_version is in range
        cvss_score = 0.0
        severity = "N/A"

        impact = doc.get("impact", {})
        base_metric_v3 = impact.get("baseMetricV3")
        if base_metric_v3 and "cvssV3" in base_metric_v3:
            cvss_score = base_metric_v3["cvssV3"]["baseScore"]
            severity = base_metric_v3.get("severity", "N/A")
        else:
            base_metric_v2 = impact.get("baseMetricV2")
            if base_metric_v2 and "cvssV2" in base_metric_v2:
                cvss_score = base_metric_v2["cvssV2"]["baseScore"]
                severity = base_metric_v2.get("severity", "N/A")

        if severity == "N/A":
            severity = get_cvss_severity(cvss_score)

        desc_data = doc.get("cve", {}).get("description", {}).get("description_data", [])
        english_desc = ""
        for d in desc_data:
            if d.get("lang") == "en":
                english_desc = d.get("value", "")
                break
        
        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score if cvss_score else "N/A",
            "severity": severity,
            "cve_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": english_desc,
            "mitigation": get_mitigation_recommendation(severity),
        })

    end_time = time.time()
    print(f"CVE Retrieval Time: {end_time - start_time:.2f} seconds")

    results.sort(key=lambda x: float(x["cvss_score"]) if x["cvss_score"] != "N/A" else 0.0, reverse=True)
    return {
        "total_cves": len(results),
        "cves": results[:10]
    }

async def process_technology(session, tech_name, user_version):
    # Build a plausible 'exact' cpe manually or from your find_cpes
    # For example, if find_cpes gave you "cpe:2.3:a:jquery:jquery_ui:1.10.4:*:*:*:*:*:*:*"
    # Then you do:
    cpe_uri_with_version = f"cpe:2.3:a:{_guess_vendor(tech_name)}:{tech_name.replace(' ','_').lower()}:{user_version}:*:*:*:*:*:*:*"

    cve_data = await get_cves_for_cpe_local(cpe_uri_with_version, user_version)
    if not cve_data["cves"]:
        print(f"No local CVEs found for {tech_name} {user_version}.")
        return None

    return {
        "product": tech_name,
        "version": user_version,
        "total_cves": cve_data["total_cves"],
        "cves": cve_data["cves"]
    }



async def main():
    start_time = time.time()

    target_url = input("Enter the URL to analyze: ").strip()

    results = analyze(url=target_url)
    product_versions = {tech_name: details.get("version", "").strip() for _, techs in results.items() for tech_name, details in techs.items()}

    async with aiohttp.ClientSession() as session:
        tasks = [process_technology(session, product, version) for product, version in product_versions.items()]
        output_data = await asyncio.gather(*tasks)

    output_data = [result for result in output_data if result]

    print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds.\n")
    print(json.dumps(output_data, indent=4))

if __name__ == "__main__":
    asyncio.run(main())
