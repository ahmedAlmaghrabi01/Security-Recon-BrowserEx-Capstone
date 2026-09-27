import os
import sys
import time
import json
import re
import asyncio
import requests
from sublist3r import main as sublist3r_main
from packaging.version import parse, InvalidVersion
from wappalyzer import analyze
from datetime import datetime
import motor.motor_asyncio

#####################################
# SUBDOMAIN ENUMERATION CODE
#####################################

# Context manager to suppress output from Sublist3r
class SuppressOutput:
    """Context manager to suppress stdout and stderr."""
    def __enter__(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        self._null_file = open(os.devnull, 'w')
        sys.stdout = self._null_file
        sys.stderr = self._null_file
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr
        self._null_file.close()

def get_subdomains_from_sublist3r(domain):
    """Find subdomains using Sublist3r."""
    with SuppressOutput():
        subdomains = sublist3r_main(
            domain,
            40,           # maximum number of subdomains
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
    return subdomains

def get_subdomains_from_crtsh(domain):
    """Get subdomains from crt.sh using Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        subdomains = {entry['common_name'] for entry in data}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching from crt.sh: {e}")
        subdomains = set()
    return subdomains

def find_subdomains(domain):
    """Find subdomains using Sublist3r and crt.sh, then combine and return the results."""
    start_time = time.time()
    sublist3r_subdomains = get_subdomains_from_sublist3r(domain)
    crtsh_subdomains = get_subdomains_from_crtsh(domain)

    # Combine both results using set union to avoid type errors
    all_subdomains = set(sublist3r_subdomains).union(crtsh_subdomains)
    filtered_subdomains = [sub for sub in all_subdomains if '*' not in sub]

    end_time = time.time()
    return {
        "domain": domain,
        "subdomains": sorted(filtered_subdomains),
        "time_taken": round(end_time - start_time, 2)
    }

#####################################
# CVE/TECHNOLOGY ANALYSIS CODE
#####################################

########################
# MongoDB Configuration
########################
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "cve_db"

mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = mongo_client[DB_NAME]
cve_collection = db["cve"]
vendor_map_collection = db["vendor_product_map"]

########################
# Helper Functions
########################

def get_cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "N/A"

def get_mitigation_recommendation(severity: str) -> str:
    base_advice = {
        "Critical": "Immediate action required. Apply patches immediately. Isolate affected systems if possible.",
        "High": "Prioritize patching. Implement temporary workarounds while update is pending.",
        "Medium": "Schedule update during next maintenance window. Monitor for exploit attempts.",
        "Low": "Evaluate impact and update when convenient. Consider security controls.",
        "N/A": "Review vulnerability details for appropriate action.",
    }
    return base_advice.get(severity, "Review vulnerability details for appropriate action.")

########################
# Known Vendors (Fallback)
########################
known_vendors = {
    "windows": "microsoft",
    "chrome": "google",
    "drupal": "drupal",
    "nessus": "tenable",
}

########################
# Vendor Lookup
########################
async def _lookup_vendor(component: str) -> str:
    product_key = component.replace(" ", "_").lower()
    doc = await vendor_map_collection.find_one({"product": product_key})
    if doc and "vendor" in doc:
        return doc["vendor"]
    return known_vendors.get(product_key, product_key)

def in_version_range(user_version_str: str,
                     version_start_including: str = None,
                     version_end_including: str = None,
                     version_start_excluding: str = None,
                     version_end_excluding: str = None) -> bool:
    if not user_version_str:
        return False
    try:
        user_v = parse(user_version_str)
    except InvalidVersion:
        return False

    def try_parse(vs: str):
        if not vs:
            return None
        try:
            return parse(vs)
        except InvalidVersion:
            return None

    start_incl = try_parse(version_start_including)
    end_incl   = try_parse(version_end_including)
    start_excl = try_parse(version_start_excluding)
    end_excl   = try_parse(version_end_excluding)

    if start_incl and user_v < start_incl:
        return False
    if start_excl and user_v <= start_excl:
        return False
    if end_incl and user_v > end_incl:
        return False
    if end_excl and user_v >= end_excl:
        return False
    return True

########################
# Step 1: Find local CPEs
########################
async def find_local_cpes(component: str, user_version: str, max_results: int = 40):
    start_time = time.time()
    vendor = await _lookup_vendor(component)
    product = component.replace(" ", "_").lower()

    escaped_vendor = re.escape(vendor)
    escaped_product = re.escape(product)
    pattern = rf"^cpe:2\.3:[aho]:{escaped_vendor}:{escaped_product}:.*$"

    query = {
        "configurations.nodes.cpe_match.cpe23Uri": {
            "$regex": pattern,
            "$options": "i"
        }
    }
    cursor = cve_collection.find(query)
    found_cpes = set()

    async for doc in cursor:
        nodes = doc.get("configurations", {}).get("nodes", [])
        for node in nodes:
            for cpe_m in node.get("cpe_match", []):
                cpe_uri = cpe_m.get("cpe23Uri", "")
                if not cpe_uri or not re.match(pattern, cpe_uri, re.IGNORECASE):
                    continue
                vs_incl = cpe_m.get("versionStartIncluding")
                ve_incl = cpe_m.get("versionEndIncluding")
                vs_excl = cpe_m.get("versionStartExcluding")
                ve_excl = cpe_m.get("versionEndExcluding")
                if vs_incl or ve_incl or vs_excl or ve_excl:
                    if in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                        found_cpes.add(cpe_uri)
                else:
                    found_cpes.add(cpe_uri)
    end_time = time.time()
    print(f"CPE Retrieval Time (local): {end_time - start_time:.2f} seconds")
    return sorted(found_cpes)[:max_results]

########################
# Step 2: Find matching CVEs for CPEs
########################
async def get_cves_for_cpes_local(cpe_list: list, user_version: str):
    start_time = time.time()
    if not cpe_list:
        return {"total_cves": 0, "cves": []}

    query = {
        "configurations.nodes.cpe_match.cpe23Uri": {"$in": cpe_list}
    }
    cursor = cve_collection.find(query)
    results = []

    async for doc in cursor:
        cve_id = doc.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        matched = False
        nodes = doc.get("configurations", {}).get("nodes", [])
        for node in nodes:
            for cpe_m in node.get("cpe_match", []):
                cpe_uri = cpe_m.get("cpe23Uri")
                if cpe_uri not in cpe_list:
                    continue
                vs_incl = cpe_m.get("versionStartIncluding")
                ve_incl = cpe_m.get("versionEndIncluding")
                vs_excl = cpe_m.get("versionStartExcluding")
                ve_excl = cpe_m.get("versionEndExcluding")
                if vs_incl or ve_incl or vs_excl or ve_excl:
                    if in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                        matched = True
                        break
                else:
                    matched = True
                    break
            if matched:
                break

        if not matched:
            continue

        impact = doc.get("impact", {})
        base_metric_v3 = impact.get("baseMetricV3")
        cvss_score = 0.0
        severity = "N/A"
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

        english_desc = ""
        for desc in doc.get("cve", {}).get("description", {}).get("description_data", []):
            if desc.get("lang") == "en":
                english_desc = desc.get("value", "")
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
    print(f"CVE Retrieval Time (local): {end_time - start_time:.2f} seconds")
    results.sort(key=lambda x: float(x["cvss_score"]) if x["cvss_score"] != "N/A" else 0.0, reverse=True)
    return {
        "total_cves": len(results),
        "cves": results[:10]
    }

########################
# Step 3: Process Technology for a given component/version
########################
async def process_technology(component: str, user_version: str):
    cpe_list = await find_local_cpes(component, user_version)
    if not cpe_list:
        print(f"No matching local CPEs for {component} {user_version}.")
        return None

    cve_data = await get_cves_for_cpes_local(cpe_list, user_version)
    if not cve_data["cves"]:
        print(f"No local CVEs found for {component} {user_version}.")
        return None

    return {
        "product": component,
        "version": user_version,
        "total_cves": cve_data["total_cves"],
        "cves": cve_data["cves"],
    }

########################
# ANALYSIS PER SUBDOMAIN
########################
async def analyze_subdomain(url: str):
    print(f"\nAnalyzing {url} ...")
    try:
        results = analyze(url=url)  # Synchronous Wappalyzer analysis
    except Exception as e:
        print(f"Error analyzing {url}: {e}")
        return None

    # Extract technology names with versions
    product_versions = {}
    for _, techs in results.items():
        for tech_name, details in techs.items():
            version = details.get("version", "").strip()
            if version:
                product_versions[tech_name] = version

    tasks = []
    for comp, ver in product_versions.items():
        tasks.append(process_technology(comp, ver))

    if tasks:
        analysis_results = await asyncio.gather(*tasks)
        analysis_results = [r for r in analysis_results if r]
    else:
        analysis_results = []

    return {
        "url": url,
        "technologies": product_versions,
        "analysis": analysis_results
    }

#####################################
# MAIN FUNCTION: Sequential Processing
#####################################
async def main():
    domain = input("Enter the domain name (e.g., example.com): ").strip()
    if not domain:
        print("No domain provided.")
        return

    print(f"\nFinding subdomains for {domain} ...")
    subdomain_data = find_subdomains(domain)
    subdomains = subdomain_data.get("subdomains", [])
    print(f"Found {len(subdomains)} subdomains (in {subdomain_data.get('time_taken', 0)} seconds).")

    # Process each subdomain one by one
    for sub in subdomains:
        # Prepend protocol if missing
        if not sub.startswith("http://") and not sub.startswith("https://"):
            url = "http://" + sub
        else:
            url = sub
        print(f"\nProcessing subdomain: {url}")
        analysis_result = await analyze_subdomain(url)
        if analysis_result:
            print("CVE Analysis Result:")
            print(json.dumps(analysis_result, indent=4))
        else:
            print("No analysis result available for this subdomain.")

if __name__ == "__main__":
    asyncio.run(main())
