import dns.resolver
import requests

def get_dns_records(domain):
    """
    Queries the DNS records of a domain using dns.resolver.
    Returns a dictionary where keys are record types and values are lists of results.
    """
    dns_info = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS"]
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_info[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            dns_info[record_type] = [f"Error: {e}"]
    
    return dns_info

def get_crtsh_records(domain):
    """
    Queries crt.sh for certificate transparency records for a domain.
    It returns a list of unique domain names found in the 'name_value' fields.
    """
    # The query uses %25. as the URL-encoded form for "%" so we can search for all subdomains.
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        data = response.json()
        
        crt_domains = set()
        for entry in data:
            # The 'name_value' field may contain multiple domain names separated by newlines.
            if 'name_value' in entry:
                names = entry['name_value'].split('\n')
                for name in names:
                    crt_domains.add(name.strip())
        return list(crt_domains)
    except Exception as e:
        return [f"Error: {e}"]

def get_combined_dns_info(domain):
    """
    Combines DNS records from both dns.resolver and crt.sh.
    The results from both sources are merged into a single list without duplicates.
    """
    # Get DNS records from dns.resolver (dictionary of record types)
    dns_info = get_dns_records(domain)
    
    # Get certificate transparency domains from crt.sh
    crt_records = get_crtsh_records(domain)
    
    # Create a set to combine unique results.
    combined = set()
    
    # Add all DNS records (irrespective of type) to the combined set.
    for record_list in dns_info.values():
        for record in record_list:
            combined.add(record)
    
    # Add crt.sh results to the combined set.
    for record in crt_records:
        combined.add(record)
    
    return list(combined)