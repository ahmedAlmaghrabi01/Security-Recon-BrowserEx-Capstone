import time

# Try to import the cpe library; if not available, define a dummy CPE class for testing
try:
    from cpe import CPE
except ModuleNotFoundError:
    class CPE:
        def __init__(self, cpe_str):
            self.cpe_str = cpe_str

        def get_vendor(self):
            parts = self.cpe_str.split(":")
            return parts[3] if len(parts) > 3 else ""

        def get_product(self):
            parts = self.cpe_str.split(":")
            return parts[4] if len(parts) > 4 else ""

        def get_version(self):
            parts = self.cpe_str.split(":")
            return parts[5] if len(parts) > 5 else ""

# Try to import cpeparser; if not available, define a dummy cpeparser with a parse method
try:
    import cpeparser
except ModuleNotFoundError:
    class cpeparser:
        @staticmethod
        def parse(cpe_str):
            parts = cpe_str.split(":")
            return {
                "vendor": parts[3] if len(parts) > 3 else "",
                "product": parts[4] if len(parts) > 4 else "",
                "version": parts[5] if len(parts) > 5 else ""
            }

# Sample CPE strings (multiplied for bulk processing)
cpe_strings = [
    "cpe:2.3:a:microsoft:windows_10:1909:*:*:*:*:*:*:*",
    "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
    "cpe:2.3:a:adobe:acrobat_reader:2020:*:*:*:*:*:*:*",
    "cpe:2.3:h:cisco:router_9000:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:http_server:2.4.46:*:*:*:*:*:*:*",
] * 1000  # Adjust multiplier as needed for bulk testing

# Benchmark using the cpe library
start_time = time.time()
parsed_cpe_cpe_lib = [CPE(cpe_str) for cpe_str in cpe_strings]
cpe_lib_time = time.time() - start_time

# Benchmark using the cpeparser library
start_time = time.time()
parsed_cpe_cpeparser = [cpeparser.parse(cpe_str) for cpe_str in cpe_strings]
cpeparser_time = time.time() - start_time

print(f"cpe library parsing time: {cpe_lib_time:.6f} seconds")
print(f"cpeparser library parsing time: {cpeparser_time:.6f} seconds")
