#!/usr/bin/env python3
"""
Check individual year files for Log4j and CVE-2021-44228
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path

def check_year_files():
    """Check individual year files for Log4j CVEs"""
    print("=== CHECKING INDIVIDUAL YEAR FILES ===")
    
    # Check the knowledge_base directory for year files
    kb_dir = Path("data/knowledge_base")
    
    # Look for enhanced_documents_cve_*.json files
    year_files = list(kb_dir.glob("enhanced_documents_cve_*.json"))
    print(f"Found {len(year_files)} year files:")
    
    for file in year_files:
        print(f"  - {file.name}")
    
    # Check specific years for Log4j
    log4j_years = ['2021', '2022', '2023', '2024']  # Log4Shell was 2021, but related CVEs might be in later years
    
    for year in log4j_years:
        file_path = kb_dir / f"enhanced_documents_cve_{year}.json"
        if file_path.exists():
            print(f"\n🔍 Checking {year} file...")
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                print(f"  📊 Documents in {year}: {len(data)}")
                
                # Check for Log4j CVEs
                log4j_docs = []
                cve_2021_44228_docs = []
                
                for doc in data:
                    content = doc.get('content', '').lower()
                    cve_id = doc.get('id', '')
                    
                    # Check for Log4j
                    if 'log4j' in content:
                        log4j_docs.append({
                            'id': doc.get('id'),
                            'title': doc.get('title'),
                            'content_preview': doc.get('content', '')[:200] + "..."
                        })
                    
                    # Check for CVE-2021-44228
                    if 'CVE-2021-44228' in doc.get('content', ''):
                        cve_2021_44228_docs.append({
                            'id': doc.get('id'),
                            'title': doc.get('title'),
                            'content_preview': doc.get('content', '')[:200] + "..."
                        })
                
                print(f"  🔍 Log4j CVEs in {year}: {len(log4j_docs)}")
                for doc in log4j_docs[:2]:  # Show first 2
                    print(f"    - {doc['id']}: {doc['content_preview']}")
                
                print(f"  🔍 CVE-2021-44228 in {year}: {len(cve_2021_44228_docs)}")
                for doc in cve_2021_44228_docs:
                    print(f"    - {doc['id']}: {doc['content_preview']}")
                
                # Check document structure
                if data:
                    sample_doc = data[0]
                    print(f"  📋 Sample document structure:")
                    print(f"    Keys: {list(sample_doc.keys())}")
                    print(f"    ID: {sample_doc.get('id')}")
                    print(f"    Content length: {len(sample_doc.get('content', ''))}")
                
            except Exception as e:
                print(f"  ❌ Error reading {year} file: {e}")
        else:
            print(f"\n❌ {year} file not found: {file_path}")

if __name__ == "__main__":
    check_year_files() 