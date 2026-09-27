import json
import requests
import socket
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse
from wappalyzer import analyze

def fetch_response(url):
    """Fetch HTTP response headers with a timeout."""
    try:
        return requests.get(url, timeout=15, allow_redirects=False)
    except requests.exceptions.RequestException:
        return None

def detect_waf(headers):
    """Detect Web Application Firewall based on HTTP response headers."""
    waf_signatures = {
        "cloudflare": "Cloudflare",
        "cf-ray": "Cloudflare",
        "akamai": "Akamai",
        "imperva": "Imperva",
        "incapsula": "Imperva Incapsula",
        "sucuri": "Sucuri",
        "barracuda": "Barracuda",
        "f5": "F5 BIG-IP",
        "aws": "AWS WAF",
        "mod_security": "ModSecurity",
        "denyall": "DenyALL"
    }
    
    if not headers:
        return "Not Detected"

    combined_headers = json.dumps({k.lower(): v.lower() for k, v in headers.items()})
    
    for signature, name in waf_signatures.items():
        if signature.lower() in combined_headers:
            return name

    return "Not Detected"

def analyze_ssl(domain):
    """Analyze SSL certificate details."""
    try:
        context = SSL.Context(SSL.SSLv23_METHOD)
        sock = socket.create_connection((domain, 443), timeout=10)
        ssl_sock = SSL.Connection(context, sock)
        ssl_sock.set_tlsext_host_name(domain.encode())
        ssl_sock.do_handshake()

        cert_bin = ssl_sock.get_peer_certificate().to_cryptography()
        ssl_sock.close()
        sock.close()

        cert = x509.load_der_x509_certificate(cert_bin.public_bytes(serialization.Encoding.DER),
                                              default_backend())

        return {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Not Before": cert.not_valid_before.isoformat(),
            "Not After": cert.not_valid_after.isoformat(),
            "Serial Number": hex(cert.serial_number),
            "Signature Hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown",
            "Public Key": cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
        }
    except Exception:
        return {"Error": "Failed to retrieve SSL details"}

def analyze_security(domain):
    """Perform WAF detection, security headers analysis, and SSL checks."""
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"

    response_http = fetch_response(http_url)
    response_https = fetch_response(https_url)

    waf_detected = detect_waf(response_http.headers if response_http else {})

    security_headers = {}
    if response_https:
        security_headers.update({
            "Strict-Transport-Security": response_https.headers.get("Strict-Transport-Security", "Not Found"),
        })
    if response_http:
        security_headers.update({
            "Content-Security-Policy": response_http.headers.get("Content-Security-Policy", "Not Found"),
            "X-Frame-Options": response_http.headers.get("X-Frame-Options", "Not Found"),
            "X-XSS-Protection": response_http.headers.get("X-XSS-Protection", "Not Found"),
            "X-Content-Type-Options": response_http.headers.get("X-Content-Type-Options", "Not Found"),
            "Referrer-Policy": response_http.headers.get("Referrer-Policy", "Not Found"),
            "Permissions-Policy": response_http.headers.get("Permissions-Policy", "Not Found"),
            "Cross-Origin-Opener-Policy": response_http.headers.get("Cross-Origin-Opener-Policy", "Not Found"),
            "Cross-Origin-Resource-Policy": response_http.headers.get("Cross-Origin-Resource-Policy", "Not Found"),
            "Cross-Origin-Embedder-Policy": response_http.headers.get("Cross-Origin-Embedder-Policy", "Not Found"),
        })

    cors_policy = {}
    if response_http:
        cors_policy.update({
            "Access-Control-Allow-Origin": response_http.headers.get("Access-Control-Allow-Origin", "Not Found"),
            "Access-Control-Allow-Methods": response_http.headers.get("Access-Control-Allow-Methods", "Not Found"),
            "Access-Control-Allow-Headers": response_http.headers.get("Access-Control-Allow-Headers", "Not Found"),
        })

    ssl_info = analyze_ssl(domain)

    return {
        "Web Application Firewall": waf_detected,
        "Security Headers": security_headers,
        "SSL Info": ssl_info,
        "CORS Policy": cors_policy,
    }

def analyze_technologies(domain: str):
    """
    Analyze the technologies used on a website, detect WAF, analyze SSL, and security headers.
    """
    try:
        # Ensure the domain is prefixed with HTTPS
        if not domain.startswith("http://") and not domain.startswith("https://"):
            url = f"https://{domain}"
        else:
            url = domain

        # Analyze the website with Wappalyzer
        results = analyze(url=url)

        # Extract only technologies with versions
        technologies = {
            tech: details.get("version", "")
            for detected_url, techs in results.items()
            for tech, details in techs.items()
            if details.get("version")  # Include only those with versions
        }

        # Perform security analysis (WAF, SSL, Headers)
        security_analysis = analyze_security(domain)

        return {
            "Technologies": technologies,
            "Security Analysis": security_analysis
        }

    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

# Example Usage
if __name__ == "__main__":
    domain = input("Enter the domain name: ").strip()
    print(json.dumps(analyze_technologies(domain), indent=4))
