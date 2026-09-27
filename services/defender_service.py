import aiohttp
import asyncio
import time  # Import the time module
import json  # Import the json module
import os
from services.config import API_ENDPOINTS, CVE2_ENDPOINT

# Set your OpenRouter API key and optional header values
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Correct headers for OpenRouter API, with optional headers added
HEADERS = {
    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    "Content-Type": "application/json",
    "HTTP-Referer": "<YOUR_SITE_URL>",  # Optional. Site URL for rankings on openrouter.ai.
    "X-Title": "<YOUR_SITE_NAME>"       # Optional. Site title for rankings on openrouter.ai.
}

async def fetch_api_data(session, key, base_url, domain, recon_data):
    """Helper function to fetch data from a single endpoint."""
    url = f"{base_url}{domain}"
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                recon_data[key] = await resp.json()
            else:
                recon_data[key] = f"Error: {resp.status}"
    except aiohttp.ClientError as e:
        recon_data[key] = f"Error: {str(e)}"

async def fetch_recon_data(session, domain: str) -> dict:
    """
    1. Fetch DNS, WHOIS, Subdomains, Technologies in parallel.
    2. Once we have 'technologies', POST them to CVE2 endpoint.
    3. Return final data with recon_data["cve2"] included.
    """
    # Start time for recon data retrieval
    recon_start_time = asyncio.get_event_loop().time()

    recon_data = {}
    tasks = []

    # Parallel fetch for DNS, WHOIS, Subdomains, Technologies
    for key, base_url in API_ENDPOINTS.items():
        tasks.append(fetch_api_data(session, key, base_url, domain, recon_data))

    await asyncio.gather(*tasks)

    # Now we have recon_data["technologies"]
    cve2_url = CVE2_ENDPOINT
    tech_data = recon_data.get("technologies")

    if isinstance(tech_data, dict):
        post_body = {
            "Technologies": tech_data.get("Technologies", {})
        }

        # POST to the new cve2 process endpoint
        try:
            async with session.post(cve2_url, json=post_body) as cve2_resp:
                if cve2_resp.status == 200:
                    cve2_data = await cve2_resp.json()
                    recon_data["cve2"] = cve2_data.get("cve_results", [])
                else:
                    recon_data["cve2"] = f"Error: {cve2_resp.status}"
        except Exception as e:
            recon_data["cve2"] = f"Error: {str(e)}"

    # Calculate recon data retrieval time
    recon_end_time = asyncio.get_event_loop().time()
    recon_time = recon_end_time - recon_start_time
    print(f"Time taken to retrieve recon data: {recon_time:.2f} seconds")

    return recon_data

async def generate_defense_roadmap(session, domain: str, reconnaissance_data: dict):
    ai_start_time = asyncio.get_event_loop().time()

    prompt = f"""
    **Role**: Cybersecurity Architect creating a defense roadmap for **{domain}**  
    **Audience**: Sysadmins/DevOps teams requiring detailed, technical remediation guidance  
    **Format**: Markdown with tables, clear headings, and actionable steps  

    ---

    ## Core Objectives  
    1. **Analyze Recon Data**: Deeply examine the provided recon data (e.g., WHOIS, technologies, SSL/TLS, DNS, subdomains, CVEs) to identify vulnerabilities, misconfigurations, and exposure risks specific to the domain.  
    2. **Prioritize Threats**: Rank issues by severity (Critical > High > Medium > Low) using CVSS scores, exploit availability, and potential impact derived from the data.  
    3. **Map to Infrastructure**: Categorize issues into infrastructure layers (e.g., [Web], [Network], [Application]) based on detected technologies, subdomains, and services.  
    4. **Recommend Actionable Steps**: Provide precise, OS-specific commands, configuration changes, and hardening techniques tailored to the technologies and versions identified in the recon data.  
    5. **Validate Fixes**: Suggest at least three validation methods per issue (e.g., version checks, scans, log reviews) specific to the affected components.  
    6. **Ensure Compliance**: Reference relevant standards (e.g., **OWASP**, **PCI-DSS**, **CIS Benchmarks**) based on the domain’s technologies and context.  
    7. **Proactive Analysis**: Identify patterns (e.g., shared vulnerabilities across subdomains) and recommend systemic fixes to address root causes.  

    ---

    ## Input Data  
    {json.dumps(reconnaissance_data, indent=2)}

    ---

    ## Data Analysis Guidelines  
    - **WHOIS**: Assess domain registration details (e.g., registrar, name servers) for risks like domain hijacking or incomplete data exposure.  
    - **Technologies**: Evaluate software stacks and versions (e.g., Drupal 7, jQuery 1.8.3) to flag outdated, end-of-life (EOL), or vulnerable components.  
    - **SSL/TLS**: Review certificate validity, SSL Labs grade, vulnerabilities (e.g., Heartbleed), supported protocols, cipher suites, and HSTS status for encryption weaknesses.  
    - **DNS**: Analyze A, AAAA, MX, TXT, and NS records for misconfigurations, exposed services, or weak SPF/DMARC policies.  
    - **Subdomains**: Investigate listed subdomains for additional attack surfaces or shared vulnerabilities with the main domain.  
    - **CVEs**: Prioritize vulnerabilities with CVSS scores ≥ 7.0, focusing on Critical (≥ 9.0) and High (7.0–8.9) severity, and note exploit availability or mitigation steps.  

    ---

    ## Output Structure  

    ### 1. Domain Health Snapshot  
    - **Critical Threats**: List vulnerabilities with CVSS ≥ 9.0 or known exploits (e.g., **CVE-2018-7600**).  
    - **Outdated/EOL Components**: Highlight software versions no longer supported or with known issues (e.g., Drupal 7).  
    - **Exposure Map**: Summarize attack surfaces (e.g., open services, subdomains) from DNS and subdomain data.  

    ---

    ### 2. Threat and Misconfiguration Analysis  
    For each significant issue (Critical, High, or notable Medium severity):  
    - **Issue Type**: Specify if it’s a vulnerability (e.g., **CVE-2018-7600**) or misconfiguration (e.g., HSTS disabled).  
    - **Severity**: Assign Critical, High, or Medium, justified by CVSS score and exploit status from the CVE data.  
    - **Affected Layer**: Tag as [Web], [Network], [Application], etc., based on the technology or subdomain affected.  
    - **Details**: Explain the issue’s impact (e.g., remote code execution, SSL stripping risk).  
    - **Note exploit availability** (e.g., “Exploit available on Exploit-DB”).  
    - **Remediation Steps**:  
      - Provide specific commands (e.g., `sudo apt-get install drupal=7.82`) or config changes (e.g., `Strict-Transport-Security: max-age=31536000` in nginx).  
      - Tailor to detected technologies and versions from the recon data.  
    - **Validation Methods** (at least three):  
      - Version check (e.g., `drupal --version`).  
      - Scan (e.g., `nmap -sV --script ssl-enum-ciphers {domain}`).  
      - Log review (e.g., `grep -i 'exploit' /var/log/nginx/error.log`).  
    - **Compliance**: Link to standards (e.g., **OWASP Top 10** for web vulnerabilities, **PCI-DSS** for SSL/TLS).  
    - **Urgency**: Assign Immediate (≤24h), Short-Term (7d), or Long-Term (30d) based on severity and exploit risk.  

    ---

    ### 3. Remediation Timeline  
    - **Immediate (≤24h)**: Address Critical CVEs and severe misconfigurations (e.g., patch **CVE-2018-7600**, disable weak ciphers).  
    - **Short-Term (7d)**: Update outdated software (e.g., jQuery to 3.6.0) and apply initial hardening (e.g., enable HSTS).  
    - **Long-Term (30d)**: Implement systemic improvements (e.g., network segmentation, monitoring enhancements).  

    ---

    ### 4. Compliance and Standards  
    - Check for compliance with **OWASP**, **PCI-DSS**, **CIS Benchmarks**, and other relevant standards based on the domain’s technologies and context.  
    - **MITRE ATT&CK**: Map findings to relevant tactics and include links (e.g., T1190 for public-facing app exploits, T1071 for C2 communications).  

    ---

    ## Style Rules  
    - Use `backticks` for commands and paths (e.g., `sudo yum update`).  
    - Link CVEs and MITRE ATT&CK techniques in-line  
    - Specify exact versions for updates (e.g., `jquery=3.6.0`).  
    - Note exploit availability (e.g., “Exploit available on Exploit-DB”).  
    - Dynamically adapt content to the reconnaissance data

    ---

    ## AI Instructions  
    - **Base Response on Recon Data**: Use the provided recon_data to generate all recommendations, analyzing specific technologies, versions, CVEs, and configurations.  
    - **Avoid Copy-Paste**: Do not reuse placeholder examples or generic text; tailor all content to the input data.  
    - **Handle Variability**: Adapt to missing or incomplete sections (e.g., no SSL/TLS data) by noting the gap and suggesting further analysis if needed.  
    - **Prioritize Dynamically**: Focus on Critical (CVSS ≥ 9.0) and High (CVSS 7.0–8.9) issues first, using data-driven severity metrics.  
    - **Infer Patterns**: If subdomains or technologies show recurring issues (e.g., outdated versions), recommend systemic fixes.  
    - **Generate Specific Commands**: Provide remediation steps matching the OS and tech stack inferred from the data (e.g., Drupal on PHP likely uses Linux commands like `apt-get`).  
    - **Stay Comprehensive**: Address all recon data components (WHOIS, DNS, etc.), not just CVEs, for a holistic roadmap.    
    """

    payload = {
        "model": "deepseek/deepseek-r1-distill-llama-70b:free",  # Updated to use the free model
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.5
    }

    # Use data=json.dumps(payload) to send the payload as a JSON string
    async with session.post(OPENROUTER_URL, data=json.dumps(payload), headers=HEADERS) as response:
        if response.status == 200:
            result = await response.json()
            # Calculate AI roadmap generation time
            ai_end_time = asyncio.get_event_loop().time()
            ai_time = ai_end_time - ai_start_time
            print(f"Time taken for AI roadmap generation: {ai_time:.2f} seconds")
            return result.get("choices", [{}])[0].get("message", {}).get("content", "No response")
        else:
            error_text = await response.text()
            raise Exception(f"Failed to retrieve AI response: {error_text}")

async def main(domain: str):
    """
    Unified entry point:
    1) Gather local recon data + CVE2.
    2) Pass the results to the OpenRouter prompt.
    3) Return the final AI-generated roadmap.
    """
    # Start time for the entire process
    total_start_time = asyncio.get_event_loop().time()

    async with aiohttp.ClientSession() as session:
        # Step 1: Fetch Recon Data
        recon_data = await fetch_recon_data(session, domain)

        # Step 2: Generate Defense Roadmap from OpenRouter
        roadmap = await generate_defense_roadmap(session, domain, recon_data)

        # Calculate total time
        total_end_time = asyncio.get_event_loop().time()
        total_time = total_end_time - total_start_time
        print(f"Total time taken for the entire process: {total_time:.2f} seconds")

        return roadmap

if __name__ == "__main__":
    DOMAIN = "example.com"
    # Run everything
    final_report = asyncio.run(main(DOMAIN))
    print("\n--- AI-Generated Defense Roadmap ---")
    print(final_report)
