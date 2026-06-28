#!/usr/bin/env python3

import json
import logging
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.mapper.mapper_config import MapperConfig
from src.mapper.cve_ttp_mapper import CVEtoTTPMapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_cve_ttp_mapping():
    """Run CVE-to-TTP mapping on processed CVE data."""
    
    config = MapperConfig()
    mapper = CVEtoTTPMapper(config)
    
    # Check if CWE mappings exist
    if not config.cwe_capec_mitre_mapping_path.exists():
        logger.error(f"CWE-CAPEC-MITRE mapping not found at {config.cwe_capec_mitre_mapping_path}")
        logger.error("Please run 'python -m src.collectors.main_collector' first to generate mappings")
        return
    
    # Look for CVE data files
    cve_data_dir = config.cti_data_dir / "cve_docs"
    if not cve_data_dir.exists():
        logger.warning(f"CVE docs directory not found at {cve_data_dir}")
        logger.info("Looking for alternative CVE data sources...")
        
        # Try to find CVE data in other locations
        possible_paths = [
            config.cti_data_dir / "nvd_cves",
            config.cti_data_dir / "cve_data",
            config.data_dir / "cve",
            config.data_dir / "nvd"
        ]
        
        for path in possible_paths:
            if path.exists():
                cve_data_dir = path
                logger.info(f"Found CVE data at {cve_data_dir}")
                break
        else:
            logger.error("No CVE data found. Please download CVE data first.")
            return
    
    # Process all CVE files
    cve_files = list(cve_data_dir.glob("*.json"))
    logger.info(f"Found {len(cve_files)} CVE files to process")
    
    all_mappings = []
    stats = {
        "total_cves": 0,
        "cves_with_ttps": 0,
        "unique_ttps": set(),
        "methods_used": {}
    }
    
    for cve_file in cve_files[:10]:  # Process first 10 files as a test
        logger.info(f"Processing {cve_file.name}")
        
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Handle single CVE or list of CVEs
            if isinstance(cve_data, list):
                cve_list = cve_data
            elif "vulnerabilities" in cve_data:  # NVD API v2 format
                cve_list = [item["cve"] for item in cve_data["vulnerabilities"]]
            elif "CVE_Items" in cve_data:  # NVD v1 format
                cve_list = cve_data["CVE_Items"]
            else:
                cve_list = [cve_data]
            
            for cve_item in cve_list:
                mapping = mapper.map_cve_to_ttps(cve_item)
                all_mappings.append(mapping)
                
                # Update statistics
                stats["total_cves"] += 1
                if mapping["ttps"]:
                    stats["cves_with_ttps"] += 1
                    stats["unique_ttps"].update(mapping["ttps"])
                
                for method in mapping["methods_used"]:
                    stats["methods_used"][method] = stats["methods_used"].get(method, 0) + 1
                
        except Exception as e:
            logger.error(f"Error processing {cve_file}: {e}")
            continue
    
    # Save results
    output_path = config.cve_ttp_mappings_path
    mapper.save_mappings(all_mappings, output_path)
    
    # Print statistics
    logger.info("\n=== CVE-to-TTP Mapping Statistics ===")
    logger.info(f"Total CVEs processed: {stats['total_cves']}")
    logger.info(f"CVEs with TTPs: {stats['cves_with_ttps']} ({stats['cves_with_ttps']/stats['total_cves']*100:.1f}%)")
    logger.info(f"Unique TTPs found: {len(stats['unique_ttps'])}")
    logger.info(f"Methods used: {stats['methods_used']}")
    
    # Show sample mappings
    logger.info("\n=== Sample Mappings ===")
    for mapping in all_mappings[:5]:
        if mapping["ttps"]:
            logger.info(f"{mapping['cve_id']}: {', '.join(mapping['ttps'][:5])}")


if __name__ == "__main__":
    run_cve_ttp_mapping()