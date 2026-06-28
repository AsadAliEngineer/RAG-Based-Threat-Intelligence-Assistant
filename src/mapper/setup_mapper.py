#!/usr/bin/env python3
"""
Setup script for CVE-to-TTP Mapper

This script downloads required data files that are too large for Git repositories.
"""

import logging
import requests
from pathlib import Path
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def download_file(url: str, output_path: Path, description: str) -> bool:
    """Download a file from URL to output path.
    
    Args:
        url: URL to download from
        output_path: Local path to save file
        description: Description for logging
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Downloading {description}...")
        logger.info(f"URL: {url}")
        logger.info(f"Destination: {output_path}")
        
        # Create parent directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download with progress indication
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        print(f"\rProgress: {progress:.1f}%", end='', flush=True)
        
        print()  # New line after progress
        logger.info(f"Successfully downloaded {description}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to download {description}: {e}")
        return False


def check_file_exists(file_path: Path, description: str) -> bool:
    """Check if a file exists and log the result."""
    if file_path.exists():
        size_mb = file_path.stat().st_size / (1024 * 1024)
        logger.info(f"✓ {description} already exists ({size_mb:.1f} MB)")
        return True
    else:
        logger.info(f"✗ {description} not found")
        return False


def setup_mapper_data():
    """Download required data files for the mapper."""
    
    logger.info("Setting up CVE-to-TTP Mapper data files...")
    logger.info("=" * 50)
    
    # Get the mapper directory
    mapper_dir = Path(__file__).parent
    tie_models_dir = mapper_dir / "tie_models"
    
    # Files to check/download
    files_to_check = [
        {
            "path": tie_models_dir / "app.trained.model.zip",
            "description": "TIE trained model",
            "required": False,
            "note": "Should be included in repository"
        },
        {
            "path": tie_models_dir / "app.enrichment.json", 
            "description": "TIE enrichment data",
            "required": False,
            "note": "Should be included in repository"
        },
        {
            "path": tie_models_dir / "enterprise-attack.json",
            "description": "MITRE ATT&CK STIX data",
            "required": True,
            "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
            "note": "Large file, downloaded separately"
        }
    ]
    
    logger.info("\nChecking existing files:")
    logger.info("-" * 30)
    
    all_files_present = True
    files_to_download = []
    
    for file_info in files_to_check:
        exists = check_file_exists(file_info["path"], file_info["description"])
        
        if not exists:
            if file_info["required"]:
                files_to_download.append(file_info)
            else:
                logger.warning(f"Optional file missing: {file_info['description']}")
                logger.warning(f"Note: {file_info['note']}")
            all_files_present = False
    
    if all_files_present:
        logger.info("\n✓ All required files are present!")
        logger.info("The mapper is ready to use.")
        return True
    
    # Download missing required files
    if files_to_download:
        logger.info(f"\nDownloading {len(files_to_download)} missing files:")
        logger.info("-" * 40)
        
        success = True
        for file_info in files_to_download:
            download_success = download_file(
                file_info["url"], 
                file_info["path"], 
                file_info["description"]
            )
            if not download_success:
                success = False
        
        if success:
            logger.info("\n✓ All files downloaded successfully!")
            logger.info("The mapper is now ready to use.")
        else:
            logger.error("\n✗ Some downloads failed. Check the logs above.")
            return False
    
    return True


def verify_setup():
    """Verify that the mapper can be imported and initialized."""
    logger.info("\nVerifying mapper setup...")
    
    try:
        # Try to import the mapper components
        sys.path.append(str(Path(__file__).parent.parent.parent))
        
        from src.mapper.mapper_config import MapperConfig
        from src.mapper.cve_cwe_mapper import CVEtoCWEtoTTPMapper
        from src.mapper.simple_tie_inference import SimpleTIEInference
        
        config = MapperConfig()
        
        # Check CWE mapping
        if config.cwe_capec_mitre_mapping_path.exists():
            cwe_mapper = CVEtoCWEtoTTPMapper(config.cwe_capec_mitre_mapping_path)
            logger.info("✓ CWE mapper initialized successfully")
        else:
            logger.warning("✗ CWE mapping data not found. Run data collection first.")
        
        # Check TIE inference
        if config.tie_model_path.exists():
            try:
                import numpy as np
                tie_inference = SimpleTIEInference(
                    model_path=config.tie_model_path,
                    enrichment_path=config.tie_enrichment_path
                )
                if tie_inference.model_loaded:
                    logger.info("✓ TIE inference initialized successfully")
                else:
                    logger.warning("✗ TIE model failed to load")
            except ImportError:
                logger.warning("✗ NumPy not available. Install with: pip install numpy")
        else:
            logger.warning("✗ TIE model not found")
        
        logger.info("\nSetup verification complete!")
        return True
        
    except Exception as e:
        logger.error(f"Setup verification failed: {e}")
        return False


def main():
    """Main setup function."""
    print("CVE-to-TTP Mapper Setup")
    print("=" * 50)
    
    # Download required data
    setup_success = setup_mapper_data()
    
    if setup_success:
        # Verify the setup
        verify_setup()
        
        print("\n" + "=" * 50)
        print("Setup complete! You can now use the mapper:")
        print("  python src/mapper/test_simple_mapper.py")
    else:
        print("\n" + "=" * 50)
        print("Setup failed. Please check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()