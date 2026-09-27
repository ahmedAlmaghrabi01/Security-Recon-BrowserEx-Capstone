import aiohttp
import asyncio
import json
import os
from services.config import API_ENDPOINTS, CVE2_ENDPOINT

# Set your OpenRouter API key and optional header values
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
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
    except Exception as e:
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

async def generate_attack_roadmap(session, domain: str, reconnaissance_data: dict) -> str:
    """
    Sends the final request to OpenRouter for the adversarial simulation roadmap with an enhanced prompt.
    """
    # Start time for AI roadmap generation
    ai_start_time = asyncio.get_event_loop().time()

    prompt = f"""
    **Role**: Red Team Lead conducting adversarial simulation on **{domain}**  
    **Audience**: Technical security teams requiring actionable intelligence  
    **Format**: Markdown with tables, code blocks, clear hierarchy, and color-coded severity  

    ---

    ## Core Objectives  
    1. Prioritize vulnerabilities by CVSS score (Critical > High > Medium)  
    2. Map vulnerabilities to MITRE ATT&CK® techniques with references for both  
    3. Provide validated exploit chains and potential attack vectors  
    4. Include a machine-parseable vulnerability matrix with PoC and reference links for all CVEs with medium and above severity  
    5. Analyze and reason about the reconnaissance data to identify key weaknesses and recommend offensive strategies, assuming a standard level of security is implemented  

    ---

    ## Input Data  
    {json.dumps(reconnaissance_data, indent=2)}  

    ---

    ## Data Clarification  
    - The provided reconnaissance data includes:  
      - DNS, WHOIS, subdomains, technologies, and SSL/TLS information for the main domain **{domain}**.  
      - CVEs derived from the technologies detected on the main domain.  
      - Subdomains are listed, but specific technology or CVE data for subdomains is not provided.  
    - When analyzing the attack surface, consider that subdomains may share similar technologies and vulnerabilities as the main domain, unless indicated otherwise in the subdomains data.  
    - Focus the vulnerability analysis on the provided CVEs for the main domain, but include subdomains in potential attack paths where relevant.  
    - **Pay attention to SSL/TLS findings**, as weak configurations can enable attacks like man-in-the-middle or downgrade attacks.  
    - **Consider WHOIS data** for potential social engineering or domain hijacking opportunities.  

    ---

    ## Output Structure  

    ### 1. Attack Surface Summary  
    • **Primary Targets**: Most vulnerable subdomains/services based on reconnaissance data  
    • **Critical Pathways**: Potential exploit chains (e.g., "Subdomain X → CVE-2020-XXX → Domain takeover")  
    • **Key Weaknesses**: Vulnerable components with versions (e.g., "Outdated Apache Tomcat (v8.5.4)")  

    ### 2. Vulnerability Analysis and Exploit Blueprint  
    For each significant vulnerability (Critical and High severity), provide:  
    - **Severity**: Critical/High with a brief rationale (e.g., "CVSS 9.8, RCE potential")  
    - **MITRE ATT&CK**: Technique ID and name (e.g., "T1190 - Exploit Public-Facing Application") with a link  
    - **Exploit Steps**: Brief steps for exploitation (e.g., "1. Access via HTTP, 2. Execute payload")  
    - **Weaponized Command**: Inline code (e.g., `curl -X POST http://vuln.endpoint -d "payload"`)  
    - **Impact**: Potential consequences (e.g., "Full server compromise")  
    - **PoC Availability**: Link to PoC or "No PoC found"  

    ### 3. CVE Table  
    Provide a Markdown table for the **top 10 most relevant CVEs with medium and above severity**:  
    | CVE ID        | Description            | CVSS Score | Severity | MITRE ATT&CK | PoC Available | References            |  
    |---------------|------------------------|------------|----------|--------------|---------------|-----------------------|  
    | CVE-XXXX-XXXX | Brief vuln description | X.X        | Critical | TXXXX        | Yes (link)    | [Link], [Link]        |  

    ### 4. Offensive Strategy Recommendations  
    • **Prioritized Attack Vectors**: Recommend the top 2-3 attack vectors based on the reconnaissance data.  
    • **Exploit Chain Suggestions**: Suggest multi-step exploit chains (e.g., "Use CVE-XXXX SQL injection to extract credentials, then SSH into subdomain Y, and escalate via CVE-YYYY").  
    • **Tool Recommendations**: Recommend tools appropriate for the vulnerabilities and target’s tech stack (e.g., for Apache, suggest `metasploit` or Apache Killer).  

    ### 5. Assumptions  
    • Assume a standard level of security is implemented (e.g., basic firewalls, default configurations).  
    • List additional assumptions made during analysis.  
    • Note areas where further reconnaissance is recommended.  

    ---

    ## Style Rules  
    ✓ Use `backticks` for commands/files (NO code blocks unless necessary)  
    ✓ Link CVEs and MITRE ATT&CK techniques in-line  
    ✓ Ensure the CVE table is well-formatted and concise  
    ✓ **Ensure 'Weaponized Command' entries are concise (max 80 characters) or use code blocks for complex commands/scripts**  
    ✓ Dynamically adapt content to the reconnaissance data  

    ---

    ## Additional Instructions for the AI  
    - **Analyze and Reason**: Identify patterns and attack paths from the data.  
    - **Focus on Offense**: Avoid defensive recommendations.  
    - **Be Comprehensive**: Cover all relevant vulnerabilities with high impact or exploitability.  
    - **Use Real Data**: Reference actual CVEs, MITRE techniques, and tools.  
    - **Prioritize Clarity**: Present critical information first.  
    - **Assume Standard Security**: Unless specified otherwise in the data.    
    """

    payload = {
        "model": "deepseek/deepseek-r1-distill-llama-70b:free",
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

        # Step 2: Generate Attack Roadmap from OpenRouter
        roadmap = await generate_attack_roadmap(session, domain, recon_data)

        # Calculate total time
        total_end_time = asyncio.get_event_loop().time()
        total_time = total_end_time - total_start_time
        print(f"Total time taken for the entire process: {total_time:.2f} seconds")

        return roadmap

if __name__ == "__main__":
    DOMAIN = "example.com"
    # Run everything
    final_report = asyncio.run(main(DOMAIN))
    print("\n--- AI-Generated Attack Roadmap ---")
    print(final_report)
