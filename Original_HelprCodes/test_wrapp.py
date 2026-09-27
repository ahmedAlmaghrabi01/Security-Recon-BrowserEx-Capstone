import time
import json
from wappalyzer import analyze

start_time = time.time()

# Analyze the website
results = analyze(
    url='https://www.qiib.com.qa/',
)

end_time = time.time()

# Extract product names and versions
product_versions = {}
for url, technologies in results.items():
    for tech, details in technologies.items():
        product_versions[tech] = details.get('version', '')  # Use empty string if version is not available

# Convert to JSON
product_versions_json = json.dumps(product_versions, indent=4)

# Print the JSON
print(product_versions_json)

# Print time taken
print(f"Time taken: {end_time - start_time:.2f} seconds")
