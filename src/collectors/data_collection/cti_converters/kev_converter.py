from pathlib import Path
from typing import Any
import csv
from src.collectors.data_collection.cti_utils import write_json, safe_str, ensure_dir

class KEVConverter:
    """Converts KEV CSV files to JSON documents."""
    def __init__(self, raw_dir: Path, docs_dir: Path, logger: Any):
        self.raw_dir = raw_dir
        self.docs_dir = docs_dir / "kev"
        self.logger = logger
        ensure_dir(self.docs_dir)

    def convert(self) -> int:
        """Convert KEV CSV files to JSON. Returns number of files converted."""
        kev_candidates = [
            self.raw_dir / "known_exploited_vulnerabilities.csv",
            self.raw_dir / "kev" / "known_exploited_vulnerabilities.csv",
            self.raw_dir / "KEV" / "known_exploited_vulnerabilities.csv"
        ]
        # Also search recursively
        kev_csv = None
        for candidate in kev_candidates:
            if candidate.exists():
                kev_csv = candidate
                self.logger.info(f"Found KEV CSV: {kev_csv}")
                break
        if not kev_csv:
            self.logger.warning("KEV CSV file not found")
            return 0
        converted_count = 0
        with open(kev_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = row.get("cveID") or row.get("CVE_ID") or row.get("CVE")
                if not cve:
                    continue
                doc = {
                    "id": cve,
                    "type": "KEV",
                    "title": f"Known Exploited Vulnerability {cve}",
                    "content": row.get("shortDescription", "") or row.get("description", ""),
                    "vendor_project": row.get("vendorProject", "") or row.get("vendor", ""),
                    "product": row.get("product", ""),
                    "vulnerability_name": row.get("vulnerabilityName", "") or row.get("name", ""),
                    "date_added": row.get("dateAdded", "") or row.get("date_added", ""),
                    "required_action": row.get("requiredAction", "") or row.get("action", ""),
                    "due_date": row.get("dueDate", "") or row.get("due_date", ""),
                    "known_ransomware": row.get("knownRansomwareCampaignUse", "") or row.get("ransomware", ""),
                    "notes": row.get("notes", "").split(";") if row.get("notes") else [],
                    "cwes": row.get("cwes", "").split(",") if row.get("cwes") else []
                }
                output_file = self.docs_dir / f"{cve}.json"
                write_json(doc, output_file)
                converted_count += 1
        self.logger.info(f"Converted {converted_count} KEV documents")
        return converted_count 