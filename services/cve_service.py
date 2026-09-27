import time
import re
from packaging.version import parse, InvalidVersion
import motor.motor_asyncio
from typing import Tuple, List, Optional
from services.config import MONGO_URI

########################
# MongoDB Configuration
########################
DB_NAME = "cve_db"

mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = mongo_client[DB_NAME]

cve_collection = db["cve"]
vendor_map_collection = db["vendor_product_map"]

# Create index for faster queries
async def ensure_indexes():
    await cve_collection.create_index([("configurations.nodes.cpe_match.cpe23Uri", 1)])

# In-memory cache for vendor lookups
vendor_cache = {}

########################
# Helper Functions
########################

# Basic CVSS Severity Helper
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

# Mitigation Recommendation
def get_mitigation_recommendation(severity: str) -> str:
    severity = severity.lower()
    if severity == "critical":
        return "Immediate action required. Apply patches immediately. Isolate affected systems if possible."
    elif severity == "high":
        return "Prioritize patching. Implement temporary workarounds while update is pending."
    elif severity == "medium":
        return "Schedule update during next maintenance window. Monitor for exploit attempts."
    else:
        return "Monitor for any abnormal activity; patch during standard update cycles."

# Version Range Checking
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

# CPE Simulation
def simulate_version_in_cpe(cpe_uri: str, user_version: str) -> str:
    parts = cpe_uri.split(":")
    if len(parts) > 5:
        parts[5] = user_version
    return ":".join(parts)

# Vendor Lookup with Caching
async def _lookup_vendor(component: str) -> Tuple[str, str]:
    if component in vendor_cache:
        return vendor_cache[component]

    simplified = component.strip().lower().replace(" ", "_")
    doc_direct = await vendor_map_collection.find_one({"product": simplified})
    if doc_direct and "vendor" in doc_direct:
        vendor_cache[component] = (doc_direct["vendor"], simplified)
        return vendor_cache[component]

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

    product_tokens = [t for t in tokens if t != vendor_token] if vendor_token else tokens
    product_key = "_".join(product_tokens) if product_tokens else simplified
    doc = await vendor_map_collection.find_one({"product": product_key})
    result = (doc["vendor"], product_key) if doc and "vendor" in doc else (product_key, product_key)
    vendor_cache[component] = result
    return result

# CPE Match in Node
def cpe_match_in_node(node_dict: dict, cpe_list: List[str], user_version: str) -> bool:
    for cpe_m in node_dict.get("cpe_match", []):
        cpe_uri = cpe_m.get("cpe23Uri", "")
        if not cpe_uri or cpe_uri not in cpe_list:
            continue
        vs_incl = cpe_m.get("versionStartIncluding")
        ve_incl = cpe_m.get("versionEndIncluding")
        vs_excl = cpe_m.get("versionStartExcluding")
        ve_excl = cpe_m.get("versionEndExcluding")
        if vs_incl is None and ve_incl is None and vs_excl is None and ve_excl is None:
            candidate = simulate_version_in_cpe(cpe_uri, user_version)
            if candidate in cpe_list:
                return True
        elif in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
            return True
    return False

# Node Satisfaction
def node_satisfied(node_dict: dict, cpe_list: List[str], user_version: str) -> bool:
    operator = node_dict.get("operator", "OR").upper()
    current_node_match = cpe_match_in_node(node_dict, cpe_list, user_version)
    child_matches = [node_satisfied(child, cpe_list, user_version) for child in node_dict.get("children", [])]
    return current_node_match and all(child_matches) if operator == "AND" else current_node_match or any(child_matches)

# Find Local CPEs
async def find_local_cpes(component: str, user_version: str, max_results: int = 40) -> List[str]:
    start_time = time.time()
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
            for cpe_m in node.get("cpe_match", []) + sum((child.get("cpe_match", []) for child in node.get("children", [])), []):
                cpe_uri = cpe_m.get("cpe23Uri", "")
                if not cpe_uri or not re.match(pattern, cpe_uri, re.IGNORECASE):
                    continue
                vs_incl = cpe_m.get("versionStartIncluding")
                ve_incl = cpe_m.get("versionEndIncluding")
                vs_excl = cpe_m.get("versionStartExcluding")
                ve_excl = cpe_m.get("versionEndExcluding")
                if vs_incl is None and ve_incl is None and vs_excl is None and ve_excl is None:
                    found_cpes.add(simulate_version_in_cpe(cpe_uri, user_version))
                elif in_version_range(user_version, vs_incl, ve_incl, vs_excl, ve_excl):
                    found_cpes.add(cpe_uri)

    print(f"CPE Retrieval Time (local): {time.time() - start_time:.2f} seconds")
    return sorted(found_cpes)[:max_results]

# Retrieve CVEs for CPEs
async def get_cves_for_cpes_local(cpe_list: List[str], user_version: str, limit: int = 50) -> dict:
    start_time = time.time()
    if not cpe_list:
        return {"total_cves": 0, "cves": []}

    query = {"configurations.nodes.cpe_match.cpe23Uri": {"$in": cpe_list}}
    cursor = cve_collection.find(query)
    results = []
    async for doc in cursor:
        cve_id = doc.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id or not any(node_satisfied(node, cpe_list, user_version) for node in doc.get("configurations", {}).get("nodes", [])):
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

        english_desc = next((d.get("value", "") for d in doc.get("cve", {}).get("description", {}).get("description_data", []) if d.get("lang") == "en"), "")
        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss_score if cvss_score else "N/A",
            "severity": severity,
            "cve_link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": english_desc,
            "mitigation": get_mitigation_recommendation(severity),
        })

    print(f"CVE Retrieval Time (local): {time.time() - start_time:.2f} seconds")
    results.sort(key=lambda c: float(c["cvss_score"]) if c["cvss_score"] != "N/A" else 0.0, reverse=True)
    return {"total_cves": len(results), "cves": results[:limit]}

# Top-Level Processing
async def process_technology(component: str, user_version: str) -> Optional[dict]:
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
