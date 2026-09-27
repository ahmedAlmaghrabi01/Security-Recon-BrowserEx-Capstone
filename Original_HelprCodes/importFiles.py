import os
import gzip
import json
import pymongo
from tqdm import tqdm

# Configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cve_db"
COLLECTION_NAME = "cve"
DATA_DIR = "originalCodes/nvd_data"

BATCH_SIZE = 500  # Adjust batch size based on system resources

# Connect to MongoDB
client = pymongo.MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

def is_already_imported(file_name):
    """Check if the file has already been imported."""
    return collection.count_documents({"imported_file": file_name}) > 0

def extract_and_import():
    """Extracts all .json.gz files and imports CVE data into MongoDB."""
    files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith(".json.gz")])

    for file in tqdm(files, desc="Processing Files"):
        file_path = os.path.join(DATA_DIR, file)

        # Skip already imported files
        if is_already_imported(file):
            print(f"Skipping {file}, already imported.")
            continue

        try:
            # Extract JSON from GZ
            with gzip.open(file_path, 'rt', encoding="utf-8") as f:
                data = json.load(f)

            if "CVE_Items" in data:
                cve_items = data["CVE_Items"]

                # Add metadata for tracking imported files
                for cve in cve_items:
                    cve["imported_file"] = file

                # Batch Insert for Performance
                for i in range(0, len(cve_items), BATCH_SIZE):
                    collection.insert_many(cve_items[i:i + BATCH_SIZE])

                print(f"Imported {len(cve_items)} records from {file}")

            else:
                print(f"Skipping {file} (no CVE_Items found).")

        except Exception as e:
            print(f"Error processing {file}: {e}")

if __name__ == "__main__":
    extract_and_import()
    print("Data import completed!")
