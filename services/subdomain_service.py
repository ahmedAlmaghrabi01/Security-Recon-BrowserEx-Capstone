import requests
from sublist3r import main as sublist3r_main

def get_subdomains_from_sublist3r(domain):
    """
    Get subdomains using Sublist3r, normalizing them (lowercase, remove trailing dot).
    """
    try:
        subdomains = sublist3r_main(
            domain=domain,
            savefile=None,           # Do not save to a file
            ports=None,              # No port scanning
            silent=True,             # Suppress console output
            verbose=False,           # Disable verbose mode
            enable_bruteforce=False, # Do not use brute force
            engines=None,            # Use all default engines
            threads=10               # Number of threads
        )
        # Normalize each subdomain (lowercase, remove trailing '.')
        return [s.lower().rstrip('.') for s in subdomains]
    except Exception as e:
        return {"error": str(e)}

def get_subdomains_from_crtsh(domain):
    """
    Get subdomains from crt.sh (Certificate Transparency logs), normalized.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        # Normalize subdomains from CRT.sh
        subdomains = {entry['common_name'].lower().rstrip('.') for entry in data}
        return subdomains
    except requests.exceptions.RequestException as e:
        return {"error": f"Error fetching from crt.sh: {e}"}

def find_subdomains(domain):
    """
    Find subdomains using Sublist3r and crt.sh, then combine, filter, and normalize.
    """
    try:
        sublist3r_subdomains = get_subdomains_from_sublist3r(domain)
        crtsh_subdomains = get_subdomains_from_crtsh(domain)

        # Check for errors from either source
        if "error" in sublist3r_subdomains:
            return {"error": sublist3r_subdomains["error"]}
        if "error" in crtsh_subdomains:
            return {"error": crtsh_subdomains["error"]}

        # Combine results using set union
        all_subdomains = set(sublist3r_subdomains) | set(crtsh_subdomains)

        # Filter out wildcard entries (*)
        filtered_subdomains = [s for s in all_subdomains if '*' not in s]

        return {
            "domain": domain,
            "subdomains": sorted(filtered_subdomains)
        }
    except Exception as e:
        return {"error": str(e)}
