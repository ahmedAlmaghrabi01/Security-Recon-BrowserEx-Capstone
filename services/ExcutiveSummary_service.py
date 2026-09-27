import aiohttp
import asyncio
import json
import os

# Set your OpenRouter API key and optional header values
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
HEADERS = {
    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    "Content-Type": "application/json",
}

API_ENDPOINTS = {
    "dns": "http://localhost:8000/api/dns/dns/",
    "whois": "http://localhost:8000/api/whois/whois/",
    "subdomains": "http://localhost:8000/api/subdomains/subdomains/",
    "technologies": "http://localhost:8000/api/tech/tech/",
    "ssl_tls": "http://localhost:8000/api/ssl_tls/ssl_tls/"
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
    cve2_url = "http://localhost:8000/api/cve2/process"
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

async def generate_nontechnical_roadmap(session, domain: str, reconnaissance_data: dict) -> str:
    # Start time for AI roadmap generation
    ai_start_time = asyncio.get_event_loop().time()

    prompt = f"""
    **Role**: Cybersecurity Advisor creating an easy-to-understand summary for **{domain}**  
    **Audience**: Staff from all departments (e.g., marketing, HR, finance) who need to know how security risks affect their work, without technical details  
    **Format**: Simple, friendly language in short paragraphs, like explaining to a friend  

    ---
    
        ## Input Data  
        {json.dumps(reconnaissance_data, indent=2)}  

    ---

    ## Objective  
    Give a clear, detailed, and thoughtful summary of security risks for **{domain}** based on the data below. Focus on:  
    - What these findings mean for the whole company, explained simply (e.g., "like leaving a door unlocked").  
    - How problems could hurt daily work—like losing customer info, stopping website sales, or embarrassing the company.  
    - Easy, practical steps everyone can support, showing why they help and how soon we need to act.  
    - A fair look at what’s going well and what needs fixing, so everyone feels informed, not scared.  

    ---

    ## Guidelines for Analysis  
    - **Technologies**: Look at the tools running our website (e.g., Drupal, jQuery). If they’re old or weak, compare them to “an outdated phone that’s slow and easy to hack”—explain how that puts us at risk.  
    - **Vulnerabilities**: Pick the biggest security flaws (like holes with a score of 7 or higher). Say they’re “like leaving cash on the table for thieves” and if bad guys are already using them, without techy terms.  
    - **SSL/TLS**: Check our website’s safety lock (encryption). Describe it as “a front door lock”—is it strong, rusty, or missing a deadbolt?  
    - **Subdomains**: Spot extra website pages (e.g., “side entrances”) that might let trouble in. Are they locked or wide open?  
    - **DNS/WHOIS**: See if our online address book leaks personal details (like names or emails) or if email tricks (phishing) could fool staff or customers.  
    - **Reasoning**: Connect risks to things staff care about—sales dropping, angry customers, or extra work—and rank them by how bad and likely they are.  

    ---

    ## Output Structure  

    ### 1. How Safe Is Our Website Right Now?  
    - Sum up our situation in 2-3 sentences. Point out what’s strong (e.g., “our safety lock works well”) and what’s shaky (e.g., “old tools have cracks hackers can use”). Keep it short and clear.  

    ### 2. Big Problems We Should Know About  
    - Pick 3-5 main worries from the data (e.g., weak spots, easy-to-trick setups). For each:  
      - **What’s Wrong**: Explain simply (e.g., “our website runs on old software anyone can break into”).  
      - **How It Hurts Us**: Show the impact (e.g., “customer info gets stolen, or our site goes down during a big sale”).  
      - **How Likely**: Is this something hackers often try, or already hitting others like us?  

    ### 3. What We Can Do About It  
    - List 3-5 simple fixes anyone can understand (e.g., “swap old tools for new ones,” “add an extra lock to our website”). For each:  
      - **Why It Helps**: Say how it stops trouble (e.g., “keeps hackers out so orders keep coming”).  
      - **When to Act**: Suggest “do it now” for big risks or “soon” for others—make it feel doable.  

    ### 4. What This All Means for Us  
    - Wrap up with a fair take: what’s solid, what’s shaky, and how worried we should be (e.g., “we’re okay but need quick fixes”).  
    - Highlight the upside of acting—like happier customers, smoother workdays, and a stronger company reputation.  

    ---

    ## Style Rules  
    - Use friendly, everyday words (e.g., “website” not “domain,” “weak spots” not “vulnerabilities”).  
    - Skip numbers or geeky terms—say “big risks” instead of “CVSS 9.8.”  
    - Keep it short and upbeat, like chatting with a coworker.  
    - Show we can handle this (e.g., “we’ve got this if we act soon”)—no doom and gloom.  

    ---

    ## Instructions  
    - Stick to the data provided—don’t guess about stuff we don’t know (say “we’d need more info” if something’s missing).  
    - Focus on risks that hit departments—like sales, customer trust, or staff email safety—not just tech details.  
    - Sort problems by how much they could mess us up and how soon they might happen.  
    - Keep fixes simple and team-friendly—no tech skills needed to get the idea.    
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
    1) Gather local recon data + cve2.
    2) Pass the results to the OpenRouter prompt.
    3) Return the final AI-generated roadmap.
    """
    # Start time for the entire process
    total_start_time = asyncio.get_event_loop().time()

    async with aiohttp.ClientSession() as session:
        # Step 1: Fetch Recon Data
        recon_data = await fetch_recon_data(session, domain)

        # Step 2: Generate Attack Roadmap from OpenRouter
        roadmap = await generate_nontechnical_roadmap(session, domain, recon_data)

        # Calculate total time
        total_end_time = asyncio.get_event_loop().time()
        total_time = total_end_time - total_start_time
        print(f"Total time taken for the entire process: {total_time:.2f} seconds")

        return roadmap

if __name__ == "__main__":
    DOMAIN = "example.com"
    # Run everything
    final_report = asyncio.run(main(DOMAIN))
    print("\n--- AI-Generated Non-Tech Summary ---")
    print(final_report)
