import whois
from whois.parser import PywhoisError

def get_whois_data(domain: str) -> dict:
    """
    Retrieve WHOIS data for a given domain using the python-whois library.
    """
    try:
        # Perform WHOIS lookup
        w = whois.whois(domain)

        # Helper function to convert datetime objects for JSON serialization
        def convert_datetime(value):
            if isinstance(value, list):
                return [v.isoformat() if hasattr(v, 'isoformat') else v for v in value]
            return value.isoformat() if hasattr(value, 'isoformat') else value

        # Parse WHOIS data into a structured dictionary
        whois_data = {}
        for key, value in w.items():
            whois_data[key] = convert_datetime(value)

        # Ensure all expected fields are present, including null values where data is missing
        return {
            "domain_name": whois_data.get("domain_name"),
            "registrar": whois_data.get("registrar"),
            "registrar_url": whois_data.get("registrar_url"),
            "reseller": whois_data.get("reseller"),
            "whois_server": whois_data.get("whois_server"),
            "referral_url": whois_data.get("referral_url"),
            "updated_date": whois_data.get("updated_date"),
            "creation_date": whois_data.get("creation_date"),
            "expiration_date": whois_data.get("expiration_date"),
            "name_servers": whois_data.get("name_servers", []),
            "status": whois_data.get("status"),
            "emails": whois_data.get("emails"),
            "dnssec": whois_data.get("dnssec"),
            "name": whois_data.get("name"),
            "organization": whois_data.get("org"),
            "address": whois_data.get("address"),
            "city": whois_data.get("city"),
            "state": whois_data.get("state"),
            "postal_code": whois_data.get("registrant_postal_code"),
            "country": whois_data.get("country"),
            "raw_data": str(w)  # Optional: raw WHOIS dump as a string
        }

    except PywhoisError as e:
        # Handle cases where the domain does not exist or has no WHOIS data
        return {"error": f"WHOIS lookup failed: {str(e)}"}
    except Exception as ex:
        # Catch-all for other errors
        return {"error": f"An unexpected error occurred: {str(ex)}"}

# Example Usage
if __name__ == "__main__":
    domain = input("Enter the domain name: ").strip()
    print(get_whois_data(domain))
