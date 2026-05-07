from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET
from src.collectors.data_collection.cti_utils import write_json, ensure_dir

class CAPECConverter:
    """Converts CAPEC XML files to JSON documents."""
    def __init__(self, raw_dir: Path, docs_dir: Path, logger: Any):
        self.raw_dir = raw_dir
        self.docs_dir = docs_dir / "capec"
        self.logger = logger
        ensure_dir(self.docs_dir)

    def convert(self) -> int:
        """Convert CAPEC XML files to JSON. Returns number of files converted."""
        capec_candidates = list(self.raw_dir.rglob("*capec*.xml"))
        if not capec_candidates:
            self.logger.warning("CAPEC XML file not found")
            return 0
        capec_xml = capec_candidates[0]
        converted_count = 0
        try:
            tree = ET.parse(capec_xml)
            root = tree.getroot()
            ns_uri = root.tag[root.tag.find("{") + 1:root.tag.find("}")] if "{" in root.tag else ""
            ns = {"c": ns_uri} if ns_uri else {}
            pattern_xpath = ".//c:Attack_Pattern" if ns_uri else ".//Attack_Pattern"
            for ap in root.findall(pattern_xpath, ns):
                cid = ap.attrib.get("ID")
                if not cid:
                    continue
                title = ap.attrib.get("Name", cid)
                desc_xpath = "c:Description" if ns_uri else "Description"
                desc_el = ap.find(desc_xpath, ns)
                desc = "".join(desc_el.itertext()).strip() if desc_el is not None else ""
                doc = {
                    "id": cid,
                    "type": "CAPEC",
                    "title": title,
                    "content": desc
                }
                output_file = self.docs_dir / f"capec-{cid}.json"
                write_json(doc, output_file)
                converted_count += 1
            self.logger.info(f"Converted {converted_count} CAPEC patterns")
        except Exception as e:
            self.logger.error(f"Failed to convert CAPEC XML: {e}")
        return converted_count 