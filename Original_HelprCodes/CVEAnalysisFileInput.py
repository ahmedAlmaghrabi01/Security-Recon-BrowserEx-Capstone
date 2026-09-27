import asyncio
import json
import time
import re
from packaging.version import parse, InvalidVersion
from wappalyzer import analyze
from datetime import datetime
import motor.motor_asyncio
from typing import Tuple, List, Optional
import concurrent.futures
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the absolute path to 'urls.txt'
urls_file_path = os.path.join(script_dir, 'urls.txt')

# Maximum number of concurrent URL analyses
MAX_CONCURRENT_ANALYSES = 10

########################
# MongoDB Configuration
########################
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "cve_db"

mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = mongo_client[DB_NAME]

cve_collection = db["cve"]
vendor_map_collection = db["vendor_product_map"]

async def ensure_indexes():
    await cve_collection.create_index([("configurations.nodes.cpe_match.cpe23Uri", 1)])

########################
# Thread Pool Setup
########################
executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)

async def run_in_executor(func, *args):
    """Helper to run synchronous functions in a thread pool using the current event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, func, *args)

########################
# Helper Functions
########################

def get_cvss_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    elif 0.1 <= score < 4.0:
        return "Low"
    elif 4.0 <= score < 7.0:
        return "Medium"
    elif 7.0 <= score < 9.0:
        return "High"
    else:
        return "Critical"

def get_mitigation_recommendation(severity: str) -> str:
    if severity.lower() == "critical":
        return "Immediate action required. Apply patches immediately. Isolate affected systems if possible."
    elif severity.lower() == "high":
        return "Prioritize patching. Implement temporary workarounds while update is pending."
    elif severity.lower() == "medium":
        return "Schedule update during next maintenance window. Monitor for exploit attempts."
    else:
        return "Monitor for any abnormal activity; patch during standard update cycles."

def in_version_range(
    user_version_str: str,
    version_start_including: str = None,
    version_end_including: str = None,
    version_start_excluding: str = None,
    version_end_excluding: str = None,
) -> bool:
    if not user_version_str:
        return False
    try:
        user_v = parse(user_version_str)
    except InvalidVersion:
        return False

    def parse_or_none(ver_str: Optional[str]):
        if not ver_str or ver_str == "*":
            return None
        try:
            return parse(ver_str)
        except InvalidVersion:
            return None

    start_incl = parse_or_none(version_start_including)
    end_incl = parse_or_none(version_end_including)
    start_excl = parse_or_none(version_start_excluding)
    end_excl = parse_or_none(version_end_excluding)

    if start_incl and user_v < start_incl:
        return False
    if start_excl and user_v <= start_excl:
        return False
    if end_incl and user_v > end_incl:
        return False
    if end_excl and user_v >= end_excl:
        return False
    return True

def simulate_version_in_cpe(cpe_uri: str, user_version: str) -> str:
    parts = cpe_uri.split(":")
    if len(parts) > 5:
        parts[5] = user_version
    return ":".join(parts)

vendor_cache = {}

async def _lookup_vendor(component: str) -> Tuple[str, str]:
    if component in vendor_cache:
        return vendor_cache[component]
    
    simplified = component.strip().lower().replace(" ", "_")
    doc_direct = await vendor_map_collection.find_one({"product": simplified})
    if doc_direct and "vendor" in doc_direct:
        vendor_cache[component] = (doc_direct["vendor"], simplified)
        return (doc_direct["vendor"], simplified)

    known_vendors_list = await vendor_map_collection.distinct("vendor")
    all_vendor_docs = vendor_map_collection.find({})
    aliases_map = {}
    async for d in all_vendor_docs:
        v = d.get("vendor")
        aliases = d.get("aliases", [])
        for alias in aliases:
            aliases_map[alias.lower()] = v

    tokens = component.lower().split()
    vendor_token = None
    for token in tokens:
        if token in known_vendors_list:
            vendor_token = token
            break
        if token in aliases_map:
            vendor_token = aliases_map[token]
            break

    if vendor_token:
        product_tokens = [t for t in tokens if t != vendor_token]
    else:
        product_tokens = tokens

    product_key = "_".join(product_tokens) if product_tokens else simplified
    doc = await vendor_map_collection.find_one({"product": product_key})
    if doc and "vendor" in doc:
        vendor_cache[component] = (doc["vendor"], product_key)
        return (doc["vendor"], product_key)
    
    vendor_cache[component] = (product_key, product_key)
    return (product_key, product_key)

def cpe_match_in_node(node_dict: dict, cpe_list: List[str], user_version: str) -> bool:
    for cpe_m in node_dict.get("cpe_match", []):
        cpe_uri = cpe_m.get("cpe23Uri", "")
        if not cpe_uri or cpe_uri not in cpe_list:
            continue
        vs_incl = cpe_m.get("versionStartIncluding")
        ve_incl = cpe_m.get("versionEndIncluding")
        vs_excl = cpe_m.get("versionStartExcluding")
        ve_excl = cpe_m.get("versionEndExcluding")
        if (vs_incl is None and ve_incl is None and 
            vs_excl is None and ve_excl is None):
            candidate = simulate_version_in_cpe(cpe_uri, user_version)
            if candidate in cpe_list:
                return True
        else:
            if in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                return True
    return False

def node_satisfied(node_dict: dict, cpe_list: List[str], user_version: str) -> bool:
    operator = node_dict.get("operator", "OR").upper()
    current_node_match = cpe_match_in_node(node_dict, cpe_list, user_version)
    child_matches = [node_satisfied(child, cpe_list, user_version) 
                     for child in node_dict.get("children", [])]
    if operator == "AND":
        return current_node_match and all(child_matches)
    else:
        return current_node_match or any(child_matches)

async def find_local_cpes(component: str, user_version: str, max_results: int = 40) -> List[str]:
    vendor, product_key = await _lookup_vendor(component)
    escaped_vendor = re.escape(vendor)
    escaped_product = re.escape(product_key)
    pattern = rf"^cpe:2\.3:[aho]:{escaped_vendor}:{escaped_product}:.*$"
    
    query = {
        "$or": [
            {"configurations.nodes.cpe_match.cpe23Uri": {"$regex": pattern, "$options": "i"}},
            {"configurations.nodes.children.cpe_match.cpe23Uri": {"$regex": pattern, "$options": "i"}}
        ]
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
                if vs_incl is None and ve_incl is None and vs_excl is None and ve_excl is None:
                    candidate_cpe = simulate_version_in_cpe(cpe_uri, user_version)
                    found_cpes.add(candidate_cpe)
                else:
                    if in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                        found_cpes.add(cpe_uri)
            for child in node.get("children", []):
                for cpe_m in child.get("cpe_match", []):
                    cpe_uri = cpe_m.get("cpe23Uri", "")
                    if not cpe_uri or not re.match(pattern, cpe_uri, re.IGNORECASE):
                        continue
                    vs_incl = cpe_m.get("versionStartIncluding")
                    ve_incl = cpe_m.get("versionEndIncluding")
                    vs_excl = cpe_m.get("versionStartExcluding")
                    ve_excl = cpe_m.get("versionEndExcluding")
                    if vs_incl is None and ve_incl is None and vs_excl is None and ve_excl is None:
                        candidate_cpe = simulate_version_in_cpe(cpe_uri, user_version)
                        found_cpes.add(candidate_cpe)
                    else:
                        if in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                            found_cpes.add(cpe_uri)
    
    return sorted(found_cpes)[:max_results]

async def get_cves_for_cpes_local(cpe_list: List[str], user_version: str, limit: int = 50) -> dict:
    if not cpe_list:
        return {"total_cves": 0, "cves": []}
    
    query = {"configurations.nodes.cpe_match.cpe23Uri": {"$in": cpe_list}}
    cursor = cve_collection.find(query)
    results = []
    
    async for doc in cursor:
        cve_id = doc.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue
        matched = False
        for node in doc.get("configurations", {}).get("nodes", []):
            if node_satisfied(node, cpe_list, user_version):
                matched = True
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
        for d_item in doc.get("cve", {}).get("description", {}).get("description_data", []):
            if d_item.get("lang") == "en":
                english_desc = d_item.get("value", "")
                break

        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score if cvss_score else "N/A",
            "severity": severity,
            "cve_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": english_desc,
            "mitigation": get_mitigation_recommendation(severity),
        })

    def score_or_zero(c):
        if c["cvss_score"] == "N/A":
            return 0.0
        return float(c["cvss_score"])

    results.sort(key=score_or_zero, reverse=True)
    return {"total_cves": len(results), "cves": results[:limit]}

async def process_technology(component: str, user_version: str) -> Optional[dict]:
    cpe_list = await find_local_cpes(component, user_version)
    if not cpe_list:
        return None
    
    cve_data = await get_cves_for_cpes_local(cpe_list, user_version)
    if not cve_data["cves"]:
        return None

    return {
        "product": component,
        "version": user_version,
        "total_cves": cve_data["total_cves"],
        "cves": cve_data["cves"],
    }

########################
# URL Analysis Functions
########################
async def analyze_url(url: str) -> dict:
    """Analyze a single URL and return its technology and CVE data."""
    try:
        results = await run_in_executor(analyze, url)
        product_versions = {
            tech_name: details.get("version", "").strip()
            for _, techs in results.items()
            for tech_name, details in techs.items()
            if details.get("version")
        }
        tasks = [process_technology(comp, ver) for comp, ver in product_versions.items()]
        output_data = await asyncio.gather(*tasks)
        output_data = [r for r in output_data if r]
        return {
            "url": url,
            "technologies": output_data
        }
    except Exception as e:
        print(f"Error analyzing {url}: {e}")
        return {
            "url": url,
            "error": str(e)
        }

async def safe_analyze_url(url: str, sem: asyncio.Semaphore) -> dict:
    """Wrapper to limit concurrent analyses and print success message."""
    async with sem:
        result = await analyze_url(url)
    if "technologies" in result:
        print(f"Successfully analyzed {url}")
    return result

########################
# Main Function
########################
async def main():
    start_time = time.time()
    
    # Ensure MongoDB indexes are set up
    await ensure_indexes()
    
    # Read URLs from the absolute path
    with open(urls_file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]
    
    # Create semaphore to limit concurrent analyses
    sem = asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)
    
    # Analyze URLs with controlled concurrency
    tasks = [safe_analyze_url(url, sem) for url in urls]
    all_results = await asyncio.gather(*tasks)
    
    # Generate timestamp for JSON filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f'analysis_results_{timestamp}.json'
    
    # Save results to JSON file
    with open(json_filename, 'w') as outfile:
        json.dump(all_results, outfile, indent=4)
    
    print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds.\n")

if __name__ == "__main__":
    asyncio.run(main())