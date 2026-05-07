from pathlib import Path
from typing import Any
import pandas as pd
from src.collectors.data_collection.cti_utils import write_json, ensure_dir, safe_str

class AttackConverter:
    """Converts ATT&CK technique XLSX files to JSON documents."""
    def __init__(self, raw_dir: Path, docs_dir: Path, logger: Any):
        self.raw_dir = raw_dir
        self.docs_dir = docs_dir / "attack_techniques"
        self.logger = logger
        ensure_dir(self.docs_dir)

    def convert(self) -> int:
        """Convert ATT&CK technique XLSX files to JSON. Returns number of files converted."""
        technique_candidates = list(self.raw_dir.rglob("*technique*.xlsx"))
        tactics_candidates = list(self.raw_dir.rglob("*tactics*.xlsx"))
        technique_candidates = [c for c in technique_candidates if not c.name.startswith('~$')]
        tactics_candidates = [c for c in tactics_candidates if not c.name.startswith('~$')]
        technique_xlsx = technique_candidates[0] if technique_candidates else None
        tactics_xlsx = tactics_candidates[0] if tactics_candidates else None
        if not technique_xlsx or not tactics_xlsx:
            self.logger.warning("ATT&CK technique or tactics XLSX file not found")
            return 0
        # Load tactics mapping
        tactics_df = pd.read_excel(tactics_xlsx, dtype=str)
        tactic_name_to_id = {}
        for row in tactics_df.itertuples(index=False):
            tactic_id = getattr(row, 'ID', '')
            tactic_name = getattr(row, 'name', '')
            tactic_id_str = str(tactic_id).strip() if pd.notna(tactic_id) else ""
            tactic_name_str = str(tactic_name).strip() if pd.notna(tactic_name) else ""
            if tactic_id_str and tactic_name_str:
                tactic_name_to_id[tactic_name_str] = tactic_id_str
        # Load techniques
        technique_df = pd.read_excel(technique_xlsx, dtype=str)
        tactic_technique_mapping = {}
        technique_tactic_mapping = {}
        converted_count = 0
        for row in technique_df.itertuples(index=False):
            technique_id = getattr(row, 'ID', '')
            name = getattr(row, 'name', '')
            desc = getattr(row, 'description', '')
            tactics_raw = getattr(row, 'tactics', '')
            technique_id_str = str(technique_id).strip() if pd.notna(technique_id) else ""
            name_str = str(name).strip() if pd.notna(name) else ""
            desc_str = str(desc).strip() if pd.notna(desc) else ""
            tactics_raw_str = str(tactics_raw).strip() if pd.notna(tactics_raw) else ""
            if not technique_id_str:
                continue
            tactic_names = [t.strip() for t in tactics_raw_str.split(',') if t.strip()]
            tactic_ids = [tactic_name_to_id[t] for t in tactic_names if t in tactic_name_to_id]
            for tactic_id in tactic_ids:
                if tactic_id not in tactic_technique_mapping:
                    tactic_technique_mapping[tactic_id] = []
                tactic_technique_mapping[tactic_id].append(technique_id_str)
            technique_tactic_mapping[technique_id_str] = tactic_ids
            doc = {
                "id": technique_id_str,
                "type": "ATT&CK",
                "title": name_str,
                "content": desc_str,
                "tactics": tactic_names,
                "tactic_ids": tactic_ids
            }
            output_file = self.docs_dir / f"{technique_id_str}.json"
            write_json(doc, output_file)
            converted_count += 1
        # Save mappings
        mapping_file = self.docs_dir.parent / "attack_mappings.json"
        mappings = {
            "tactic_to_techniques": tactic_technique_mapping,
            "technique_to_tactics": technique_tactic_mapping,
            "tactic_name_to_id": tactic_name_to_id,
            "total_techniques": converted_count,
            "total_tactics": len(tactic_technique_mapping)
        }
        write_json(mappings, mapping_file)
        self.logger.info(f"Converted {converted_count} ATT&CK techniques with {len(tactic_technique_mapping)} tactic mappings")
        return converted_count 