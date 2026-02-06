#!/usr/bin/env python3
"""
Analyze year-based CVE files for RAG suitability
"""

import json
import sys
from pathlib import Path

def analyze_year_file(file_path: Path):
    """Analyze a single year file"""
    print(f"\n🔍 Analyzing {file_path.name}...")
    
    try:
        # Try different encodings
        for encoding in ['utf-8', 'utf-8-sig', 'latin-1']:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    data = json.load(f)
                print(f"  ✅ Successfully loaded with {encoding} encoding")
                break
            except UnicodeDecodeError:
                continue
            except json.JSONDecodeError as e:
                print(f"  ❌ JSON decode error with {encoding}: {e}")
                continue
        else:
            print(f"  ❌ Failed to load with any encoding")
            return None
        
        if not data:
            print(f"  ❌ Empty data")
            return None
        
        # Analyze structure
        sample_doc = data[0]
        print(f"  📊 Total documents: {len(data)}")
        print(f"  🔑 Document keys: {list(sample_doc.keys())}")
        
        # Check RAG suitability
        content = sample_doc.get('content', '')
        print(f"  📝 Content length: {len(content)} characters")
        print(f"  📝 Content preview: {content[:100]}...")
        
        # Check for required RAG fields
        rag_fields = ['id', 'content', 'title']
        missing_fields = [field for field in rag_fields if field not in sample_doc]
        if missing_fields:
            print(f"  ⚠️  Missing RAG fields: {missing_fields}")
        else:
            print(f"  ✅ All required RAG fields present")
        
        # Check content quality
        if len(content) < 50:
            print(f"  ⚠️  Content seems too short for RAG")
        elif len(content) > 5000:
            print(f"  ⚠️  Content might be too long for RAG")
        else:
            print(f"  ✅ Content length suitable for RAG")
        
        # Check for specific CVEs
        log4j_count = sum(1 for doc in data if 'log4j' in doc.get('content', '').lower())
        cve_44228_count = sum(1 for doc in data if 'CVE-2021-44228' in doc.get('content', ''))
        
        print(f"  🔍 Log4j mentions: {log4j_count}")
        print(f"  🔍 CVE-2021-44228 mentions: {cve_44228_count}")
        
        return data
        
    except Exception as e:
        print(f"  ❌ Error analyzing file: {e}")
        return None

def main():
    """Main function"""
    print("=== ANALYZING YEAR-BASED FILES FOR RAG SUITABILITY ===")
    
    # Check knowledge_base directory
    kb_dir = Path("data/knowledge_base")
    if not kb_dir.exists():
        print("❌ Knowledge base directory not found")
        return
    
    # Find year files
    year_files = list(kb_dir.glob("enhanced_documents_cve_*.json"))
    year_files.sort()
    
    print(f"Found {len(year_files)} year files:")
    for file in year_files:
        print(f"  - {file.name}")
    
    # Analyze recent years (2021-2024) for RAG suitability
    recent_years = ['2021', '2022', '2023', '2024']
    
    for year in recent_years:
        file_path = kb_dir / f"enhanced_documents_cve_{year}.json"
        if file_path.exists():
            data = analyze_year_file(file_path)
            if data:
                # Check if we can use this data directly for RAG
                print(f"  🎯 RAG Suitability Assessment for {year}:")
                
                # Check if content is meaningful
                sample_docs = data[:5]  # Check first 5 documents
                meaningful_content = 0
                for doc in sample_docs:
                    content = doc.get('content', '')
                    if len(content) > 100 and not content.isspace():
                        meaningful_content += 1
                
                if meaningful_content >= 4:
                    print(f"    ✅ Content quality: Good ({meaningful_content}/5 docs have meaningful content)")
                else:
                    print(f"    ⚠️  Content quality: Poor ({meaningful_content}/5 docs have meaningful content)")
                
                # Check structure consistency
                consistent_structure = all(
                    'id' in doc and 'content' in doc and 'title' in doc 
                    for doc in sample_docs
                )
                if consistent_structure:
                    print(f"    ✅ Structure consistency: Good")
                else:
                    print(f"    ⚠️  Structure consistency: Poor")
                
                print(f"    💡 Recommendation: {'Use directly for RAG' if meaningful_content >= 4 and consistent_structure else 'Needs processing for RAG'}")

if __name__ == "__main__":
    main() 