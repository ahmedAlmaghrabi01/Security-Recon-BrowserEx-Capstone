import os
import sys
import time
import requests
from sublist3r import main as sublist3r_main

# Suppress Sublist3r output
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
        self._null_file.close()  # Close the suppressed output file

# Function to fetch subdomains from Sublist3r
def get_subdomains_from_sublist3r(domain):
    """Find subdomains using Sublist3r."""
    with SuppressOutput():
        subdomains = sublist3r_main(
            domain,
            40,  # max number of subdomains
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
    return subdomains

# Function to fetch subdomains from crt.sh
def get_subdomains_from_crtsh(domain):
    """Get subdomains from crt.sh using Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise error for bad responses
        data = response.json()
        subdomains = {entry['common_name'] for entry in data}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching from crt.sh: {e}")
        subdomains = set()
    return subdomains

# Main function to combine both approaches
def find_subdomains(domain):
    """Find subdomains using Sublist3r and crt.sh, then combine and return the results."""
    start_time = time.time()

    # Get subdomains from both methods
    sublist3r_subdomains = get_subdomains_from_sublist3r(domain)
    crtsh_subdomains = get_subdomains_from_crtsh(domain)

    # Combine subdomains and remove duplicates
    all_subdomains = set(sublist3r_subdomains + list(crtsh_subdomains))

    # Remove subdomains with wildcards
    filtered_subdomains = [sub for sub in all_subdomains if '*' not in sub]

    end_time = time.time()

    # Return the filtered list of subdomains
    return {
        "domain": domain,
        "subdomains": sorted(filtered_subdomains),
        "time_taken": round(end_time - start_time, 2)
    }

# Example usage
if __name__ == "__main__":
    domain = input("Enter the domain name (e.g., example.com): ").strip()
    if not domain:
        print({"error": "No domain provided."})
    else:
        result = find_subdomains(domain)
        print(result)
