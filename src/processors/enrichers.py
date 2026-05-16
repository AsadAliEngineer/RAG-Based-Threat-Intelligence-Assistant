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
        cve['is_in_kev'] = True
        cve['kev_data'] = kev_entry
    else:
        cve['is_in_kev'] = False
    
    # CSAF enrichment
    csaf_entries = csaf_by_cve.get(cve_id, [])
    if csaf_entries:
        cve['csaf_correlations'] = csaf_entries
    else:
        cve['csaf_correlations'] = []
    
    # ExploitDB enrichment
    exploitdb_entries = exploitdb_by_cve.get(cve_id, [])
    if exploitdb_entries:
        cve['exploitdb_correlations'] = exploitdb_entries
    else:
        cve['exploitdb_correlations'] = []
    
    # CWE-CAPEC-MITRE mapping enrichment
    cwe_ids = cve.get('cwe_ids', [])
    capec_entries = []
    mitre_techniques = []
    mitre_tactics = []
    cwe_mappings = []
    
    for cwe_id in cwe_ids:
        if cwe_id in cwe_capec_mitre_mapping:
            mapping = cwe_capec_mitre_mapping[cwe_id]
            cwe_mappings.append({
                'cwe_id': cwe_id,
                'capecs': mapping.get('capecs', []),
                'mitre_techniques': mapping.get('mitre_techniques', []),
                'mitre_description': mapping.get('mitre_description', '')
            })
            
            # Collect all CAPEC entries
            capec_entries.extend(mapping.get('capecs', []))
            
            # Collect all MITRE techniques
            mitre_techniques.extend(mapping.get('mitre_techniques', []))
            
            # Extract tactics from techniques (e.g., T1548.004 -> T1548)
            for technique in mapping.get('mitre_techniques', []):
                if '.' in technique:
                    tactic = technique.split('.')[0]
                    if tactic not in mitre_tactics:
                        mitre_tactics.append(tactic)
    
    # Remove duplicates
    capec_entries = list(set(capec_entries))
    mitre_techniques = list(set(mitre_techniques))
    mitre_tactics = list(set(mitre_tactics))
    
    cve['cwe_capec_mitre_mappings'] = cwe_mappings
    cve['capec_entries'] = capec_entries
    cve['mitre_techniques'] = mitre_techniques
    cve['mitre_tactics'] = mitre_tactics
    
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
    cwe_mapping_count = 0
    capec_count = 0
    mitre_count = 0
    
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
        
        # Count enrichments for logging
        if enriched_cve.get('cwe_capec_mitre_mappings'):
            cwe_mapping_count += 1
        if enriched_cve.get('capec_entries'):
            capec_count += 1
        if enriched_cve.get('mitre_techniques'):
            mitre_count += 1
    
    if logger:
        logger.info(f"Enriched {len(enriched)} CVEs with CTI data.")
        logger.info(f"CWE-CAPEC-MITRE mappings: {cwe_mapping_count} CVEs")
        logger.info(f"CAPEC entries: {capec_count} CVEs")
        logger.info(f"MITRE techniques: {mitre_count} CVEs")
    
    return enriched 