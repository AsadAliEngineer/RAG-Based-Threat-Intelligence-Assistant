from pathlib import Path
from typing import Any, List, Dict
import json
from src.collectors.data_collection.cti_utils import write_json, ensure_dir

class CSAFConverter:
    """Converts CSAF JSON files to processed JSON documents."""
    def __init__(self, raw_dir: Path, docs_dir: Path, logger: Any):
        self.raw_dir = raw_dir
        self.docs_dir = docs_dir / "csaf"
        self.logger = logger
        ensure_dir(self.docs_dir)

    def convert(self) -> int:
        """Convert CSAF JSON files to processed JSON. Returns number of files converted."""
        csaf_files = list((self.raw_dir / "csaf").glob("*.json"))
        if not csaf_files:
            csaf_files = list(self.raw_dir.glob("*.json"))
        if not csaf_files:
            csaf_files = list((self.raw_dir / "CSAF").glob("*.json"))
        if not csaf_files:
            self.logger.warning("No CSAF files found.")
            return 0
        converted_count = 0
        for fpath in csaf_files:
            try:
                with open(fpath, 'r', encoding="utf-8") as f:
                    data = json.load(f)
                if not data.get("document"):
                    self.logger.warning(f"Skipping {fpath.name} - not a valid CSAF file (no document section)")
                    continue
                doc = data.get("document", {})
                doc_id = doc.get("tracking", {}).get("id", fpath.stem)
                title = doc.get("title", "")
                # ... (other extraction logic as in the original)
                processed_doc = {
                    "id": doc_id,
                    "type": "CSAF",
                    "title": title,
                    # ... (other fields as in the original)
                }
                output_filename = f"{doc_id.upper()}.json"
                output_path = self.docs_dir / output_filename
                write_json(processed_doc, output_path)
                self.logger.info(f"Successfully converted {fpath.name} -> {output_filename}")
                converted_count += 1
            except Exception as e:
                self.logger.error(f"Error processing CSAF file {fpath}: {e}")
        self.logger.info(f"Converted {converted_count} CSAF documents")
        return converted_count 