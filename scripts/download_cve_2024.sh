#!/bin/bash
set -e

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Set target directory relative to project root
TARGET_DIR="$SCRIPT_DIR/../data/CVE/zip"
mkdir -p "$TARGET_DIR"

# NVD CVE 2024 URL (official source)
CVE_URL="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip"

echo "[INFO] Downloading 2024 CVE data from NVD..."
curl -L "$CVE_URL" -o "$TARGET_DIR/nvdcve-1.1-2024.json.zip"

echo "[INFO] Download complete: $TARGET_DIR/nvdcve-1.1-2024.json.zip" 