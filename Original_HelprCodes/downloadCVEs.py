import requests
import os

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS = range(2002, 2025)  # Adjust based on your needs

os.makedirs("nvd_data", exist_ok=True)

file_name = f"nvdcve-1.1-{2025}.json.gz"
url = BASE_URL + file_name
response = requests.get(url, stream=True)
    
if response.status_code == 200:
    with open(f"nvd_data/{file_name}", "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"Downloaded {file_name}")
else:
    print(f"Failed to download {file_name}")
