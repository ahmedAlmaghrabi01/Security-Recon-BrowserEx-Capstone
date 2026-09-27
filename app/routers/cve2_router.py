from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import asyncio
from services.cve_service import process_technology
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Define the expected input structure with Pydantic
class TechInput(BaseModel):
    Technologies: dict[str, str]

@router.post("/process")
async def process_cves_for_technologies(tech_data: TechInput):
    """
    Endpoint to process detected technologies and retrieve their CVEs.

    Expected JSON structure:
    {
      "Technologies": {
         "Drupal": "7.58",
         "jQuery": "1.8.3",
         ...
      }
    }

    - "Technologies": A dictionary where keys are technology names (str) and values are versions (str).
    - Returns a dictionary with "cve_results" (list of CVE data) and "total_technologies" (int).
    - Each call to process_technology(product, version) is executed concurrently.
    """
    product_versions = tech_data.Technologies
    logger.info(f"Processing {len(product_versions)} technologies")

    # Create async tasks for each technology
    tasks = []
    for product, version in product_versions.items():
        tasks.append(process_technology(product, version))

    # Process tasks concurrently, capturing exceptions
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter results and log errors
    final_results = []
    for product, result in zip(product_versions.keys(), results):
        if isinstance(result, Exception):
            logger.error(f"Error processing {product}: {str(result)}")
        elif result:  # Exclude None values
            final_results.append(result)

    logger.info(f"Found CVEs for {len(final_results)} technologies")
    return {
        "total_technologies": len(product_versions),
        "cve_results": final_results
    }