from typing import List, Dict
from pathlib import Path
from datetime import datetime
import json
import logging
from config import Config

def save_processed_data(
    enhanced_docs: List[Dict],
    processed_dir: Path,
    all_cves: List[Dict],
    kev_data: List[Dict],
    cwe_capec_mitre_mapping: Dict,
    logger: logging.Logger
) -> None:
    """Save processed data, enhanced documents, and summary statistics."""
    config = Config()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Save enhanced documents with timestamp
    docs_file = processed_dir / f"enhanced_documents_{timestamp}.json"
    with open(docs_file, 'w') as f:
        json.dump(enhanced_docs, f, indent=2)
    # Also save with the expected filename for CPE extraction in processed_dir
    expected_filename = processed_dir / "enhanced_documents_cve_2024.json"
    with open(expected_filename, 'w') as f:
        json.dump(enhanced_docs, f, indent=2)
    # Always save to the canonical knowledge_base_dir path
    knowledge_base_path = config.enhanced_documents_path
    knowledge_base_path.parent.mkdir(parents=True, exist_ok=True)
    with open(knowledge_base_path, 'w') as f:
        json.dump(enhanced_docs, f, indent=2)
    # Calculate correlation statistics
    kev_count = sum(1 for cve in all_cves if cve.get('is_in_kev'))
    csaf_correlations = sum(len(cve.get('csaf_correlations', [])) for cve in all_cves)
    exploitdb_correlations = sum(len(cve.get('exploitdb_correlations', [])) for cve in all_cves)
    cwe_with_mapping = sum(1 for cve in all_cves if any(cwe in cwe_capec_mitre_mapping for cwe in cve.get('cwe_ids', [])))
    # Save summary
    summary = {
        'timestamp': timestamp,
        'total_cves_processed': len(all_cves),
        'total_kev_entries': len(kev_data),
        'total_enhanced_documents': len(enhanced_docs),
        'cve_documents': len([d for d in enhanced_docs if d['document_type'] == 'CVE']),
        'kev_documents': len([d for d in enhanced_docs if d['document_type'] == 'KEV']),
        'correlation_statistics': {
            'cves_in_kev': kev_count,
            'total_csaf_correlations': csaf_correlations,
            'total_exploitdb_correlations': exploitdb_correlations,
            'cves_with_cwe_mapping': cwe_with_mapping,
            'cwe_capec_mitre_mappings_loaded': len(cwe_capec_mitre_mapping)
        },
        'files': {
            'enhanced_documents': str(docs_file),
            'enhanced_documents_cve_2024': str(expected_filename),
            'knowledge_base_enhanced_documents': str(knowledge_base_path)
        }
    }
    summary_file = processed_dir / f"processing_summary_{timestamp}.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Processed data saved to {processed_dir} and {knowledge_base_path}")
    logger.info(f"Summary: {len(all_cves)} CVEs, {len(kev_data)} KEV entries, {len(enhanced_docs)} enhanced documents")
    logger.info(f"Correlations: {kev_count} CVEs in KEV, {csaf_correlations} CSAF correlations, {exploitdb_correlations} ExploitDB correlations") 