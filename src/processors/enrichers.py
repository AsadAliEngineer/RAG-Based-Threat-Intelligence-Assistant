from typing import Dict, List, Optional
import logging

def enrich_cve_with_cti(
    cve: Dict,
    kev_by_cve: Dict[str, Dict],
    csaf_by_cve: Dict[str, List[Dict]],
    exploitdb_by_cve: Dict[str, List[Dict]],
    cwe_capec_mitre_mapping: Dict,
    logger: Optional[logging.Logger] = None
) -> Dict:
    """Enrich a CVE entry with CTI data (KEV, CSAF, ExploitDB, CWE-CAPEC-MITRE mapping)."""
    cve_id = cve.get('cve_id') or cve.get('id')
    if not cve_id:
        if logger:
            logger.warning("CVE entry missing cve_id or id")
        return cve
    # KEV enrichment
    kev_entry = kev_by_cve.get(cve_id)
    if kev_entry:
        cve['kev'] = kev_entry
    # CSAF enrichment
    csaf_entries = csaf_by_cve.get(cve_id, [])
    if csaf_entries:
        cve['csaf'] = csaf_entries
    # ExploitDB enrichment
    exploitdb_entries = exploitdb_by_cve.get(cve_id, [])
    if exploitdb_entries:
        cve['exploitdb'] = exploitdb_entries
    # CWE-CAPEC-MITRE mapping enrichment
    cwe_id = cve.get('cwe_id')
    if cwe_id and cwe_id in cwe_capec_mitre_mapping:
        cve['cwe_capec_mitre'] = cwe_capec_mitre_mapping[cwe_id]
    return cve


def enrich_all_cves(
    cves: List[Dict],
    kev_by_cve: Dict[str, Dict],
    csaf_by_cve: Dict[str, List[Dict]],
    exploitdb_by_cve: Dict[str, List[Dict]],
    cwe_capec_mitre_mapping: Dict,
    logger: Optional[logging.Logger] = None
) -> List[Dict]:
    """Enrich all CVE entries in the list with CTI data."""
    enriched = []
    for cve in cves:
        enriched_cve = enrich_cve_with_cti(
            cve,
            kev_by_cve,
            csaf_by_cve,
            exploitdb_by_cve,
            cwe_capec_mitre_mapping,
            logger
        )
        enriched.append(enriched_cve)
    if logger:
        logger.info(f"Enriched {len(enriched)} CVEs with CTI data.")
    return enriched 