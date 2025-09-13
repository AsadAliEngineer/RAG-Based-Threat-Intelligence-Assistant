from config import Config
import requests

config = Config()
CSAF_OUT_DIR = config.csaf_dir
KEV_CSV_PATH = config.known_exploited_vuln_csv

CSAF_OUT_DIR.mkdir(parents=True, exist_ok=True)

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
print(f"Downloading KEV CSV from {KEV_URL} …")
r = requests.get(KEV_URL)
r.raise_for_status()
KEV_CSV_PATH.write_bytes(r.content)
print(f"  → saved to {KEV_CSV_PATH}")

API_ROOT = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white"
print("Listing ICS-OT advisories in GitHub API …")
resp = requests.get(API_ROOT)
resp.raise_for_status()
for entry in resp.json():
    if entry["type"] != "dir":
        continue
    year = entry["name"]
    print(f"  → Found year folder: {year}")
    year_resp = requests.get(entry["url"])
    year_resp.raise_for_status()
    for fileinfo in year_resp.json():
        if not fileinfo["name"].endswith(".json"):
            continue
        download_url = fileinfo["download_url"]
        out_path = CSAF_OUT_DIR / fileinfo["name"]
        if out_path.exists():
            continue
        print(f"    • downloading {fileinfo['name']} …")
        r2 = requests.get(download_url)
        r2.raise_for_status()
        out_path.write_bytes(r2.content)

print("All CISA data downloaded into:")
print("  •", KEV_CSV_PATH)
print("  •", CSAF_OUT_DIR)
