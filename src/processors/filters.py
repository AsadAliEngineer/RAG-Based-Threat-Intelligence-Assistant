from typing import List, Dict
import logging

def filter_rejected_cves(cves: List[Dict], logger: logging.Logger) -> List[Dict]:
    """Filter out rejected CVEs based on description content."""
    logger.info("Filtering out rejected CVEs...")
    original_count = len(cves)
    filtered_cves = []
    rejected_count = 0
    rejection_indicators = [
        'rejected reason',
        'rejected:',
        'rejection reason',
        'this cve has been rejected',
        'cve rejected',
        'rejected cve',
        'not a vulnerability',
        'duplicate of',
        'duplicate cve',
        'withdrawn',
        'withdrawal reason'
    ]
    for cve in cves:
        description = cve.get('description', '').lower()
        is_rejected = any(indicator in description for indicator in rejection_indicators)
        if is_rejected:
            rejected_count += 1
            logger.debug(f"Rejected CVE: {cve.get('cve_id', 'Unknown')} - {description[:100]}...")
        else:
            filtered_cves.append(cve)
    logger.info(f"Filtered out {rejected_count} rejected CVEs ({original_count - rejected_count} remaining)")
    return filtered_cves 