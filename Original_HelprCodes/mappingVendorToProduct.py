import pymongo

def parse_cpe(cpe23_uri: str):
    """
    Parse a cpe:2.3:<part>:<vendor>:<product>:<version>...
    Return (vendor, product) or (None, None) if invalid.
    """
    parts = cpe23_uri.split(":")
    # cpe:2.3:<part>:<vendor>:<product>:<version>...
    if len(parts) < 5:
        return (None, None)
    vendor = parts[3]
    product = parts[4]
    return (vendor, product)

def build_vendor_product_map():
    # 1. Connect to Mongo
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["cve_db"]
    cve_collection = db["cve"]
    map_collection = db["vendor_product_map"]  # new collection to store the map

    # We'll ensure an index so upserts are quick
    map_collection.create_index("product", unique=True)

    # 2. Iterate all CVE docs
    cursor = cve_collection.find({}, projection=["configurations.nodes.cpe_match.cpe23Uri"])
    count_processed = 0

    for doc in cursor:
        nodes = doc.get("configurations", {}).get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpe_match", [])
            for cpe_m in cpe_matches:
                cpe_uri = cpe_m.get("cpe23Uri")
                if not cpe_uri:
                    continue
                vendor, product = parse_cpe(cpe_uri)
                if not vendor or not product:
                    continue

                # 3. Insert or update map_collection
                # We do an upsert or we might store multiple vendors, etc.

                # Basic approach #1: If product is new, store vendor
                # If product is known, skip or replace vendor. 
                # We'll do a simple approach: store the first vendor we see.

                try:
                    map_collection.update_one(
                        {"product": product},  # filter
                        {"$setOnInsert": {
                            "vendor": vendor
                        }},
                        upsert=True
                    )
                except Exception as e:
                    print("Error updating map collection:", e)

        count_processed += 1
        if count_processed % 10000 == 0:
            print(f"Processed {count_processed} CVE docs...")

    print("Finished building vendor->product map!")

if __name__ == "__main__":
    build_vendor_product_map()
