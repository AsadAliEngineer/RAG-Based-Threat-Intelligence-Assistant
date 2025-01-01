#!/usr/bin/env python3
"""
Download all available CVE data from NVD
"""

import os
import requests
import zipfile
from pathlib import Path
from tqdm import tqdm

def download_cve_data():
    """Download all available CVE data from NVD"""
    
    # Get the directory of this script
    script_dir = Path(__file__).resolve().parent
    target_dir = script_dir.parent / "data" / "CVE" / "zip"
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # NVD CVE base URL
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
    
    # Get current year
    import datetime
    current_year = datetime.datetime.now().year
    
    print(f"[INFO] Downloading CVE data from 2002 to {current_year}...")
    
    # Download CVE data for each year
    for year in range(2002, current_year + 1):
        filename = f"nvdcve-1.1-{year}.json.zip"
        url = f"{base_url}/{filename}"
        target_file = target_dir / filename
        
        if target_file.exists():
            print(f"[INFO] {filename} already exists, skipping...")
            continue
            
        try:
            print(f"[INFO] Downloading {filename}...")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Get file size for progress bar
            total_size = int(response.headers.get('content-length', 0))
            
            with open(target_file, 'wb') as f:
                with tqdm(total=total_size, unit='B', unit_scale=True, desc=filename) as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print(f"[INFO] Successfully downloaded: {target_file}")
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to download {filename}: {e}")
            continue
    
    # Also download the modified CVE feed (contains recent updates)
    modified_filename = "nvdcve-1.1-modified.json.zip"
    modified_url = f"{base_url}/{modified_filename}"
    modified_target_file = target_dir / modified_filename
    
    if not modified_target_file.exists():
        try:
            print(f"[INFO] Downloading {modified_filename}...")
            response = requests.get(modified_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(modified_target_file, 'wb') as f:
                with tqdm(total=total_size, unit='B', unit_scale=True, desc=modified_filename) as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print(f"[INFO] Successfully downloaded: {modified_target_file}")
            
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to download {modified_filename}: {e}")
    
    print(f"[INFO] Download complete! Files saved to: {target_dir}")

if __name__ == "__main__":
    download_cve_data() 