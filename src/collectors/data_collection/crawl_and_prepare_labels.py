#!/usr/bin/env python3
# data_collection/crawl_and_prepare_labels.py

import csv
import json
from pathlib import Path
from rag_pipeline.load_corpus import load_threat_docs

# 1) Paths
SCRIPT_DIR   = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent

RAW_CTI_DIR  = PROJECT_ROOT / "data" / "CTI" / "raw"
DOCS_CTI_DIR = PROJECT_ROOT / "data" / "CTI" / "docs"
SYSTEM_DIR   = PROJECT_ROOT / "data" / "systemData"
TRAINING_DIR = PROJECT_ROOT / "data" / "training"

# 2) Ensure directories exist
for d in (RAW_CTI_DIR, DOCS_CTI_DIR, TRAINING_DIR):
    d.mkdir(parents=True, exist_ok=True)

# 3) Load KEV CVEs
KEV_CSV = RAW_CTI_DIR / "known_exploited_vulnerabilities.csv"
if not KEV_CSV.exists():
    raise FileNotFoundError(
        f"Run download_cisa_data.py first; cannot find {KEV_CSV}"
    )
kev_cves = set()
with open(KEV_CSV, newline="") as f:
    for row in csv.DictReader(f):
        kev_cves.add(row["cveID"])

# 4) Load assets
ES_FILE = SYSTEM_DIR / "ES_enriched.json"
with open(ES_FILE, "r") as f:
    es = json.load(f)
assets_data = es.get("Assets", [])

# 5) Load CTI docs for snippets
cti_docs = load_threat_docs(str(DOCS_CTI_DIR))
cve_to_docs = {}
for doc in cti_docs:
    cid = doc.get("id") or doc.get("cve_id")
    content = doc.get("content", "")
    if cid and content:
        cve_to_docs.setdefault(cid, []).append(content)

# 6) Generate vuln_train.jsonl (vulnerability → EPSS)
VULN_OUT = TRAINING_DIR / "vuln_train.jsonl"
with open(VULN_OUT, "w") as fout:
    for asset in assets_data:
        for comp in asset.get("components", []):
            for vuln in comp.get("vulnerabilities", []):
                cve  = vuln["cve_id"]
                epss = vuln.get("epss", vuln.get("exploitability", 0.0))
                snippets = cve_to_docs.get(cve, [])[:3]
                text = (
                    f"CVE: {cve} | CVSS: {vuln.get('cvss')} | "
                    f"VECTOR: {vuln.get('cvssV3Vector')} | "
                    f"SNIPPETS: {' || '.join(snippets)}"
                )
                fout.write(json.dumps({"text": text, "label": epss}) + "\n")

# 7) Generate asset_train.jsonl (asset → TR(a))
ASSET_OUT = TRAINING_DIR / "asset_train.jsonl"
with open(ASSET_OUT, "w") as fout:
    for asset in assets_data:
        all_vulns = [
            v["cve_id"]
            for comp in asset.get("components", [])
            for v in comp.get("vulnerabilities", [])
        ]
        if not all_vulns:
            continue
        tr = len(set(all_vulns) & kev_cves) / len(all_vulns)
        snippets = []
        for cve in all_vulns:
            snippets.extend(cve_to_docs.get(cve, [])[:2])
        snippets = snippets[:5]
        text = (
            f"Asset ID: {asset['asset_id']} | Type: {asset['type']} | "
            f"BusinessValue: {asset['business_value']} | "
            f"Vulns: {all_vulns} | SNIPPETS: {' || '.join(snippets)}"
        )
        fout.write(json.dumps({"text": text, "label": tr}) + "\n")

# 8) Done
print(f"Generated:\n  • {VULN_OUT}\n  • {ASSET_OUT}")


def paraphrase_description(description: str) -> str:
    # Placeholder for LLM-based paraphrasing
    return description.replace("contains", "includes").replace("allows", "permits")