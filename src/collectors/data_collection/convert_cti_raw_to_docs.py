#!/usr/bin/env python3
"""
Convert raw CTI data to processed documents using the converters.
"""

import sys
import os
import logging
from pathlib import Path

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from config import Config
from src.collectors.data_collection.cti_converters.kev_converter import KEVConverter
from src.collectors.data_collection.cti_converters.csaf_converter import CSAFConverter
from src.collectors.data_collection.cti_converters.capec_converter import CAPECConverter
from src.collectors.data_collection.cti_converters.attack_converter import AttackConverter

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function to convert all raw CTI data to documents"""
    logger.info("=== Starting CTI Raw to Docs Conversion ===")
    
    # Initialize config
    config = Config()
    raw_dir = config.cti_data_dir
    docs_dir = config.cti_docs_dir
    
    logger.info(f"Raw data directory: {raw_dir}")
    logger.info(f"Documents directory: {docs_dir}")
    
    # Ensure directories exist
    raw_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    total_converted = 0
    
    try:
        # Convert KEV data
        logger.info("=== Converting KEV Data ===")
        kev_converter = KEVConverter(raw_dir, docs_dir, logger)
        kev_count = kev_converter.convert()
        total_converted += kev_count
        logger.info(f"KEV conversion complete: {kev_count} documents")
        
        # Convert CSAF data
        logger.info("=== Converting CSAF Data ===")
        csaf_converter = CSAFConverter(raw_dir, docs_dir, logger)
        csaf_count = csaf_converter.convert()
        total_converted += csaf_count
        logger.info(f"CSAF conversion complete: {csaf_count} documents")
        
        # Convert CAPEC data (if available)
        logger.info("=== Converting CAPEC Data ===")
        try:
            capec_converter = CAPECConverter(raw_dir, docs_dir, logger)
            capec_count = capec_converter.convert()
            total_converted += capec_count
            logger.info(f"CAPEC conversion complete: {capec_count} documents")
        except Exception as e:
            logger.warning(f"CAPEC conversion failed: {e}")
        
        # Convert MITRE ATT&CK data (if available)
        logger.info("=== Converting MITRE ATT&CK Data ===")
        try:
            attack_converter = AttackConverter(raw_dir, docs_dir, logger)
            attack_count = attack_converter.convert()
            total_converted += attack_count
            logger.info(f"MITRE ATT&CK conversion complete: {attack_count} documents")
        except Exception as e:
            logger.warning(f"MITRE ATT&CK conversion failed: {e}")
        
        # Summary
        logger.info("=== Conversion Summary ===")
        logger.info(f"Total documents converted: {total_converted}")
        logger.info(f"Documents directory: {docs_dir}")
        
        # List created directories
        for subdir in docs_dir.iterdir():
            if subdir.is_dir():
                file_count = len(list(subdir.glob("*.json")))
                logger.info(f"  {subdir.name}: {file_count} documents")
        
        logger.info("=== CTI Conversion Complete ===")
        return True
        
    except Exception as e:
        logger.error(f"Error during CTI conversion: {e}")
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        logger.error("CTI conversion failed!")
        sys.exit(1)
    else:
        logger.info("CTI conversion completed successfully!") 