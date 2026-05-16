from pathlib import Path
from typing import List, Dict, Optional
import json
import zipfile
import logging


def extract_zip_files(zip_dir: Path, json_dir: Path, logger: logging.Logger) -> None:
    """Extract all zipped CVE files from zip_dir into json_dir."""
    logger.info("Extracting zipped CVE files...")
    zip_files = list(zip_dir.glob("*.zip"))
    if not zip_files:
        logger.info("No zip files found to extract")
        return
    for zip_file in zip_files:
        logger.info(f"Extracting {zip_file.name}...")
        try:
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(json_dir)
            logger.info(f"Successfully extracted {zip_file.name}")
        except Exception as e:
            logger.error(f"Error extracting {zip_file.name}: {e}")


def load_cwe_capec_mitre_mapping(mapping_file: Path, logger: logging.Logger) -> Dict:
    """Load the CWE-CAPEC-MITRE mapping data from a JSON file."""
    if not mapping_file.exists():
        logger.warning(f"Mapping file not found: {mapping_file}")
        return {}
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            mapping = json.load(f)
        logger.info(f"Loaded CWE-CAPEC-MITRE mapping with {len(mapping)} entries")
        return mapping
    except Exception as e:
        logger.error(f"Error loading mapping file: {e}")
        return {}


def load_csaf_data(csaf_dir: Path, logger: logging.Logger) -> tuple[List[Dict], Dict[str, List[Dict]]]:
    """Load CSAF data and create a CVE-ID index."""
    csaf_files = list(csaf_dir.glob("*.json"))
    csaf_data = []
    csaf_by_cve = {}
    for file in csaf_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    cve_ids = _extract_cve_ids_from_csaf(entry)
                    for cve_id in cve_ids:
                        if cve_id not in csaf_by_cve:
                            csaf_by_cve[cve_id] = []
                        csaf_by_cve[cve_id].append(entry)
                    csaf_data.append(entry)
        except Exception as e:
            logger.error(f"Error loading CSAF file {file.name}: {e}")
    logger.info(f"Loaded {len(csaf_data)} CSAF entries with {len(csaf_by_cve)} CVE correlations")
    return csaf_data, csaf_by_cve


def load_exploitdb_data(exploitdb_dir: Path, logger: logging.Logger) -> tuple[List[Dict], Dict[str, List[Dict]]]:
    """Load ExploitDB data and create a CVE-ID index."""
    exploitdb_files = list(exploitdb_dir.glob("*.json"))
    exploitdb_data = []
    exploitdb_by_cve = {}
    for file in exploitdb_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    cve_ids = _extract_cve_ids_from_exploitdb(entry)
                    for cve_id in cve_ids:
                        if cve_id not in exploitdb_by_cve:
                            exploitdb_by_cve[cve_id] = []
                        exploitdb_by_cve[cve_id].append(entry)
                    exploitdb_data.append(entry)
        except Exception as e:
            logger.error(f"Error loading ExploitDB file {file.name}: {e}")
    logger.info(f"Loaded {len(exploitdb_data)} ExploitDB entries with {len(exploitdb_by_cve)} CVE correlations")
    return exploitdb_data, exploitdb_by_cve


def load_kev_data(kev_dir: Path, logger: logging.Logger) -> tuple[List[Dict], Dict[str, Dict]]:
    """Load KEV data and create a CVE-ID index."""
    kev_files = list(kev_dir.glob("*.json"))
    kev_data = []
    kev_by_cve = {}
    for file in kev_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                entry = json.load(f)
                cve_id = entry.get('id', '')
                if cve_id and cve_id.startswith('CVE-'):
                    kev_by_cve[cve_id] = entry
                    kev_data.append(entry)
        except Exception as e:
            logger.error(f"Error loading KEV file {file.name}: {e}")
    logger.info(f"Loaded {len(kev_data)} KEV entries")
    return kev_data, kev_by_cve


def _extract_cve_ids_from_csaf(csaf_entry: Dict) -> List[str]:
    """Extract CVE IDs from a CSAF entry."""
    cve_ids = []
    vulnerabilities = csaf_entry.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve', '')
        if cve_id and cve_id.startswith('CVE-'):
            cve_ids.append(cve_id)
    for key, value in csaf_entry.items():
        if isinstance(value, str) and 'CVE-' in value:
            import re
            cve_matches = re.findall(r'CVE-\d{4}-\d+', value)
            cve_ids.extend(cve_matches)
    return list(set(cve_ids))


def _extract_cve_ids_from_exploitdb(exploit_entry: Dict) -> List[str]:
    """Extract CVE IDs from an ExploitDB entry."""
    cve_ids = []
    cve_refs = exploit_entry.get('cve_refs', [])
    if isinstance(cve_refs, list):
        for cve_id in cve_refs:
            if cve_id and cve_id.startswith('CVE-'):
                cve_ids.append(cve_id)
    return list(set(cve_ids)) 