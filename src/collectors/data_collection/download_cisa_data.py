import sys
import os
import time
import logging
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from config import Config
import requests

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure requests with timeout
TIMEOUT = 30  # 30 seconds timeout

def download_with_progress(url, description, timeout=TIMEOUT):
    """Download with progress logging and timeout"""
    logger.info(f"Starting download: {description}")
    logger.info(f"URL: {url}")
    
    start_time = time.time()
    try:
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()
        
        # Get content length for progress tracking
        content_length = response.headers.get('content-length')
        if content_length:
            content_length = int(content_length)
            logger.info(f"File size: {content_length:,} bytes")
        
        # Read content
        content = response.content
        download_time = time.time() - start_time
        
        logger.info(f"Download completed in {download_time:.2f} seconds")
        if content_length:
            speed = content_length / download_time if download_time > 0 else 0
            logger.info(f"Download speed: {speed/1024:.1f} KB/s")
        
        return content
        
    except requests.exceptions.Timeout:
        logger.error(f"Timeout error downloading {description} after {timeout} seconds")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error downloading {description}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error downloading {description}: {e}")
        raise

def main():
    logger.info("=== Starting CISA Data Download ===")
    
    config = Config()
    CSAF_OUT_DIR = config.csaf_dir
    KEV_CSV_PATH = config.known_exploited_vuln_csv
    
    logger.info(f"Output directory: {CSAF_OUT_DIR}")
    logger.info(f"KEV CSV path: {KEV_CSV_PATH}")
    
    # Create output directory
    CSAF_OUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Created/verified output directory: {CSAF_OUT_DIR}")
    
    # Step 1: Download KEV CSV
    logger.info("=== Step 1: Downloading KEV CSV ===")
    KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    
    try:
        kev_content = download_with_progress(KEV_URL, "KEV CSV file")
        KEV_CSV_PATH.write_bytes(kev_content)
        logger.info(f"KEV CSV saved to: {KEV_CSV_PATH}")
        logger.info(f"KEV CSV size: {len(kev_content):,} bytes")
    except Exception as e:
        logger.error(f"Failed to download KEV CSV: {e}")
        return False
    
    # Step 2: Download CSAF Advisories
    logger.info("=== Step 2: Downloading CSAF Advisories ===")
    API_ROOT = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white"
    
    try:
        logger.info(f"Fetching CSAF directory listing from: {API_ROOT}")
        resp = requests.get(API_ROOT, timeout=TIMEOUT)
        resp.raise_for_status()
        
        entries = resp.json()
        logger.info(f"Found {len(entries)} entries in CSAF repository")
        
        year_folders = [entry for entry in entries if entry["type"] == "dir"]
        logger.info(f"Found {len(year_folders)} year folders")
        
        total_files_downloaded = 0
        total_files_skipped = 0
        
        for i, entry in enumerate(year_folders, 1):
            year = entry["name"]
            logger.info(f"Processing year folder {i}/{len(year_folders)}: {year}")
            
            try:
                year_resp = requests.get(entry["url"], timeout=TIMEOUT)
                year_resp.raise_for_status()
                
                year_files = year_resp.json()
                json_files = [f for f in year_files if f["name"].endswith(".json")]
                
                logger.info(f"  Found {len(json_files)} JSON files in year {year}")
                
                for j, fileinfo in enumerate(json_files, 1):
                    download_url = fileinfo["download_url"]
                    out_path = CSAF_OUT_DIR / fileinfo["name"]
                    
                    if out_path.exists():
                        logger.debug(f"    Skipping {fileinfo['name']} (already exists)")
                        total_files_skipped += 1
                        continue
                    
                    logger.info(f"    Downloading {j}/{len(json_files)}: {fileinfo['name']}")
                    
                    try:
                        file_content = download_with_progress(download_url, f"CSAF file {fileinfo['name']}")
                        out_path.write_bytes(file_content)
                        total_files_downloaded += 1
                        logger.info(f"    Successfully downloaded: {fileinfo['name']} ({len(file_content):,} bytes)")
                        
                    except Exception as e:
                        logger.error(f"    Failed to download {fileinfo['name']}: {e}")
                        continue
                
            except Exception as e:
                logger.error(f"Failed to process year folder {year}: {e}")
                continue
        
        logger.info(f"CSAF download summary:")
        logger.info(f"  - Files downloaded: {total_files_downloaded}")
        logger.info(f"  - Files skipped (already exist): {total_files_skipped}")
        
    except Exception as e:
        logger.error(f"Failed to download CSAF advisories: {e}")
        return False
    
    # Final summary
    logger.info("=== Download Summary ===")
    logger.info(f"KEV CSV: {KEV_CSV_PATH}")
    logger.info(f"CSAF Directory: {CSAF_OUT_DIR}")
    
    # Check file sizes
    if KEV_CSV_PATH.exists():
        kev_size = KEV_CSV_PATH.stat().st_size
        logger.info(f"KEV CSV size: {kev_size:,} bytes")
    
    csaf_files = list(CSAF_OUT_DIR.glob("*.json"))
    logger.info(f"CSAF files count: {len(csaf_files)}")
    
    logger.info("=== CISA Data Download Complete ===")
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        logger.error("CISA data download failed!")
        sys.exit(1)
    else:
        logger.info("CISA data download completed successfully!")
