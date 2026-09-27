
'''
import requests

def get_vulnerabilities(vendor, product):
    base_url = "https://vulnerability.circl.lu/api"
    search_url = f"{base_url}/search/{vendor}/{product}"
    response = requests.get(search_url)
    if response.status_code == 200:
        vulnerabilities = response.json()
        return vulnerabilities
    else:
        print(f"Error: Unable to fetch data (Status Code: {response.status_code})")
        return None

# Example usage
vendor = "microsoft"
product = "office"
vulnerabilities = get_vulnerabilities(vendor, product)

if vulnerabilities:
    for vuln in vulnerabilities:
        print(f"CVE ID: {vuln['id']}")
        print(f"Summary: {vuln['summary']}")
        print(f"Published Date: {vuln['Published']}")
        print(f"CVSS Score: {vuln.get('cvss', 'N/A')}")
        print("-" * 40)
'''
'''
from pycvesearch import CVESearch

# Use the CIRCL public instance or your local instance URL
cve = CVESearch("https://cve.circl.lu")

results = cve.cpe23('cpe:2.3:a:wordpress:wordpress:6.1.4:*:*:*:*:*:*:*')
print(results)
'''

import requests
import urllib.parse


def find_cpes(component, version):
    """
    Searches the NVD 2.0 CPE API for a given component and version.
    Returns a list of full CPE URIs (e.g., 'cpe:2.3:a:wordpress:wordpress:6.3:*:*:*:*:*:*:*').
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    # Combine component and version into a simple keyword query
    query = f"{component} {version}"
    encoded_query = urllib.parse.quote(query)

    # Build the endpoint with the keywordSearch parameter
    url = f"{base_url}?keywordSearch={encoded_query}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # For the NVD 2.0 CPE API, check 'products' or 'cpes'
        cpes_data = data.get('products', []) or data.get('cpes', [])
        cpe_matches = []

        for item in cpes_data:
            # Each 'item' might have 'cpe23Uri' or 'cpe' -> 'cpeName'
            cpe_uri = item.get('cpe', {}).get('cpeName', '') or item.get('cpe23Uri', '')
            if cpe_uri and cpe_uri.startswith("cpe:2.3:"):
                cpe_matches.append(cpe_uri)

        return cpe_matches

    except requests.RequestException as e:
        print(f"Error fetching CPEs: {e}")
        return []


def main():
    # 1) Prompt the user for product and version
    product = input("Enter product (e.g., wordpress): ").strip()
    version = input("Enter version (e.g., 6.3.1): ").strip()

    # 2) Retrieve all matching CPE strings using find_cpes
    cpe_list = find_cpes(product, version)
    if not cpe_list:
        print(f"No CPEs found for '{product} {version}'.")
        return

    # Truncate to a maximum of 30 CPEs
    MAX_CPE = 10
    if len(cpe_list) > MAX_CPE:
        print(f"Found {len(cpe_list)} CPEs. Truncating to the first {MAX_CPE} for this request.")
        cpe_list = cpe_list[:MAX_CPE]

    print(f"Using {len(cpe_list)} CPE(s) for '{product} {version}':")
    for idx, cpe_uri in enumerate(cpe_list, start=1):
        print(f"[{idx}] {cpe_uri}")
    print()

    # 3) Build a SINGLE request to the CVE 2.0 endpoint with multiple cpeName params
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # We'll create a list of (key, value) tuples for 'params'
    # e.g., [('cpeName','cpe1'), ('cpeName','cpe2'), ...]
    params = []
    for cpe_uri in cpe_list:
        params.append(('cpeName', cpe_uri))

    try:
        # Single request with multiple cpeName=...
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        cve_data = response.json()

        # 4) Print all CVEs returned (combined), without mapping back to specific CPE
        vulnerabilities = cve_data.get("vulnerabilities", [])
        if vulnerabilities:
            print(f"CVEs found for the combined CPE list ({len(vulnerabilities)} total):")
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve", {}).get("id", "N/A")
                desc_list = vuln.get("cve", {}).get("descriptions", [])
                description = desc_list[0].get("value") if desc_list else "No description."
                print(f"  - CVE ID: {cve_id}")
                print(f"    Description: {description}")
            print("-" * 50)
        else:
            print("No CVEs found for the combined CPE list.")

    except requests.RequestException as e:
        print(f"Error fetching CVEs: {e}")


if __name__ == "__main__":
    main()
