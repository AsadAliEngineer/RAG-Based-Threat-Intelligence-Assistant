#!/usr/bin/env python3

import argparse
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Helper to run a script and print output/errors

def run_script(script_path):
    logger.info(f"Running {script_path} ...")
    result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        raise RuntimeError(f"Script {script_path} failed.")


def main():
    base_dir = Path(__file__).parent / "data_collection"
    steps = [
        ("Download KEV and CSAF", base_dir / "download_cisa_data.py", "download"),
        ("Download CWE, CAPEC, ExploitDB", base_dir / "get_data.py", "download"),
        ("Convert raw CTI to docs", base_dir / "convert_cti_raw_to_docs.py", "convert"),
    ]

    parser = argparse.ArgumentParser(description="Orchestrate threat intelligence data collection and preparation.")
    parser.add_argument('--download', action='store_true', help='Download all raw data only')
    parser.add_argument('--convert', action='store_true', help='Convert raw data to docs only')
    args = parser.parse_args()

    # Determine which steps to run
    selected_steps = []
    if args.download:
        selected_steps = [s for s in steps if s[2] == "download"]
    elif args.convert:
        selected_steps = [s for s in steps if s[2] == "convert"]
    else:
        selected_steps = steps  # Run all

    for desc, script, _ in selected_steps:
        print(f"\n=== {desc} ===")
        try:
            run_script(str(script))
        except Exception as e:
            logger.error(f"Error in step '{desc}': {e}")
            break

if __name__ == "__main__":
    main()
