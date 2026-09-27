import asyncio
import json
import time
import re
from packaging.version import parse, InvalidVersion
from wappalyzer import analyze
from datetime import datetime
import motor.motor_asyncio
from typing import Tuple, List, Optional

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

# ---------- Utility: Basic CVSS Severity Helper ----------
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

# ---------- Utility: Mitigation Recommendation (Customize as needed) ----------
def get_mitigation_recommendation(severity: str) -> str:
    if severity.lower() == "critical":
        return "Immediate action required. Apply patches immediately. Isolate affected systems if possible."
    elif severity.lower() == "high":
        return "Prioritize patching. Implement temporary workarounds while update is pending."
    elif severity.lower() == "medium":
        return "Schedule update during next maintenance window. Monitor for exploit attempts."
    else:
        return "Monitor for any abnormal activity; patch during standard update cycles."

# ---------- 1. Version Range Checking with Wildcard Support ----------
def in_version_range(
    user_version_str: str,
    version_start_including: str = None,
    version_end_including: str = None,
    version_start_excluding: str = None,
    version_end_excluding: str = None,
) -> bool:
    """
    Determines if 'user_version_str' falls within the given version range.
    Supports inclusive/exclusive boundaries, and treats '*' as 'match any'.
    """
    if not user_version_str:
        return False

    try:
        user_v = parse(user_version_str)
    except InvalidVersion:
        return False

    def parse_or_none(ver_str: Optional[str]):
        if not ver_str or ver_str == "*":
            return None  # wildcard or missing
        try:
            return parse(ver_str)
        except InvalidVersion:
            return None

    start_incl = parse_or_none(version_start_including)
    end_incl   = parse_or_none(version_end_including)
    start_excl = parse_or_none(version_start_excluding)
    end_excl   = parse_or_none(version_end_excluding)

    # start_incl => user_v >= start_incl
    if start_incl and user_v < start_incl:
        return False
    # start_excl => user_v > start_excl
    if start_excl and user_v <= start_excl:
        return False
    # end_incl => user_v <= end_incl
    if end_incl and user_v > end_incl:
        return False
    # end_excl => user_v < end_excl
    if end_excl and user_v >= end_excl:
        return False

    return True

# ---------- 2. Expanded CPE Simulation ----------
def simulate_version_in_cpe(cpe_uri: str, user_version: str) -> str:
    """
    Given a CPE URI, replace its version field (index #5) with the user-specified version.
    Optionally, you can also overwrite or wildcard other fields if needed.
    Standard CPE 2.3 format: cpe:2.3:[part]:[vendor]:[product]:[version]:[update]:[edition]:[language]:[sw_edition]:[target_sw]:[target_hw]:[other]

    Example:
        Original: cpe:2.3:a:microsoft:office:2013:*:*:*:*:*:*:*
        After sim: cpe:2.3:a:microsoft:office:1.0.0:*:*:*:*:*:*:*
    """
    parts = cpe_uri.split(":")
    # We at least ensure we have part/vendor/product/version slots
    if len(parts) > 5:
        parts[5] = user_version  # set the version

    # Optional: wildcard out other fields if desired:
    # for i in range(6, len(parts)):
    #     parts[i] = "*"

    return ":".join(parts)

# ---------- 3. Vendor Lookup with Direct Key + Alias Check ----------
async def _lookup_vendor(component: str) -> Tuple[str, str]:
    """
    1. Attempt direct lookup with simplified (lowercase, underscore) key.
    2. If no direct match, fallback to token-based approach.
    3. Also checks if any token matches known vendor aliases.
    """

    # Step A: Direct match for entire component
    simplified = component.strip().lower().replace(" ", "_")
    doc_direct = await vendor_map_collection.find_one({"product": simplified})
    if doc_direct and "vendor" in doc_direct:
        return (doc_direct["vendor"], simplified)

    # Step B: Known vendor list and known aliases
    known_vendors_list = await vendor_map_collection.distinct("vendor")
    
    # Additionally, you might store synonyms/aliases in each vendor_map doc
    # We'll just retrieve them once for all docs; in large DBs, you'd want a more optimized approach.
    all_vendor_docs = vendor_map_collection.find({})
    aliases_map = {}
    async for d in all_vendor_docs:
        v = d.get("vendor")
        aliases = d.get("aliases", [])
        # store in a dict for quick membership checks
        # e.g., aliases_map["microsoft"] = "microsoft"
        for alias in aliases:
            aliases_map[alias.lower()] = v

    # Step C: Token-based approach
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
        return (doc["vendor"], product_key)

    # Fallback: if not found at all, return the product_key for both
    return (product_key, product_key)

# ---------- 4. Handling AND/OR in NVD Configuration Nodes ----------
def cpe_match_in_node(node_dict: dict, cpe_list: List[str], user_version: str) -> bool:
    """
    Returns True if this node (its 'cpe_match' array) has any matching CPE in cpe_list
    that also passes version range checks. 
    """
    for cpe_m in node_dict.get("cpe_match", []):
        cpe_uri = cpe_m.get("cpe23Uri", "")
        if not cpe_uri or cpe_uri not in cpe_list:
            continue

        vs_incl = cpe_m.get("versionStartIncluding")
        ve_incl = cpe_m.get("versionEndIncluding")
        vs_excl = cpe_m.get("versionStartExcluding")
        ve_excl = cpe_m.get("versionEndExcluding")

        # If no version boundaries, we simulate version
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
    """
    Evaluates a configuration node (and its children) respecting the 'operator' field 
    ('AND' or 'OR'). For 'AND', all must match; for 'OR', any match suffices.
    """
    operator = node_dict.get("operator", "OR").upper()
    # Check current node's cpe_match array
    current_node_match = cpe_match_in_node(node_dict, cpe_list, user_version)

    # Recursively evaluate children
    child_matches = []
    for child in node_dict.get("children", []):
        child_matches.append(node_satisfied(child, cpe_list, user_version))

    if operator == "AND":
        # Must match the node itself AND all children
        return current_node_match and all(child_matches)
    else:
        # OR is default
        return current_node_match or any(child_matches)

# ---------- 5. Finding Local CPEs ----------
async def find_local_cpes(component: str, user_version: str, max_results: int = 40) -> List[str]:
    """
    1. Looks up vendor/product from user input using _lookup_vendor.
    2. Regex-searches cpe23Uri fields in the 'configurations.nodes' array for potential matches.
    3. Checks version ranges. If no range, we 'simulate_version_in_cpe'.
    4. Returns up to 'max_results' sorted matches.
    """
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
            # For cpe_match in the node
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

            # For children
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
    
    end_time = time.time()
    print(f"CPE Retrieval Time (local): {end_time - start_time:.2f} seconds")

    # Return sorted list, up to max_results
    return sorted(found_cpes)[:max_results]

# ---------- 6. Retrieving CVEs for Local CPEs ----------
async def get_cves_for_cpes_local(cpe_list: List[str], user_version: str, limit: int = 50) -> dict:
    """
    1. Query for all CVEs whose 'configurations.nodes' might match any cpe in cpe_list.
    2. Use 'node_satisfied' to respect AND/OR logic.
    3. Return up to 'limit' CVEs, sorted by CVSS score descending.
    """
    start_time = time.time()
    if not cpe_list:
        return {"total_cves": 0, "cves": []}
    
    # We query where at least one cpe23Uri in the doc's config is in our cpe_list
    # This is a broad filter; we'll do final matching via node_satisfied
    query = {"configurations.nodes.cpe_match.cpe23Uri": {"$in": cpe_list}}
    cursor = cve_collection.find(query)
    results = []
    
    async for doc in cursor:
        cve_id = doc.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        # Evaluate each top-level node with AND/OR logic
        matched = False
        for node in doc.get("configurations", {}).get("nodes", []):
            if node_satisfied(node, cpe_list, user_version):
                matched = True
                break
        if not matched:
            continue

        # If matched, gather CVSS details
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

        # Extract English description
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
    
    end_time = time.time()
    print(f"CVE Retrieval Time (local): {end_time - start_time:.2f} seconds")

    # Sort descending by score
    def score_or_zero(c):
        if c["cvss_score"] == "N/A":
            return 0.0
        return float(c["cvss_score"])

    results.sort(key=score_or_zero, reverse=True)

    return {
        "total_cves": len(results),
        "cves": results[:limit]  # Return up to 'limit' CVEs
    }

########################
# Top-Level Processing
########################
async def process_technology(component: str, user_version: str) -> Optional[dict]:
    cpe_list = await find_local_cpes(component, user_version)
    if not cpe_list:
        print(f"No matching local CPEs for {component} {user_version}.")
        return None
    print("Found CPEs:", cpe_list)
    
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

async def main():
    start_time = time.time()
    target_url = input("Enter the URL to analyze: ").strip()
    results = analyze(url=target_url)
    print('tech stack results:', results)
    product_versions = {
        tech_name: details.get("version", "").strip()
        for _, techs in results.items()
        for tech_name, details in techs.items()
        if details.get("version")
    }
    tasks = [process_technology(comp, ver) for comp, ver in product_versions.items()]
    output_data = await asyncio.gather(*tasks)
    output_data = [r for r in output_data if r]
    print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds.\n")
    print(json.dumps(output_data, indent=4))

if __name__ == "__main__":
    asyncio.run(main())
