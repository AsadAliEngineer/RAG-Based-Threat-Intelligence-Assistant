#!/usr/bin/env python3
"""
Test CVE search functionality
"""

import requests
import json

def test_cve_search():
    """Test CVE-2021-44228 search"""
    print("🔍 Testing CVE-2021-44228 search...")
    
    try:
        response = requests.post(
            'http://localhost:8000/api/v1/search', 
            json={'query': 'CVE-2021-44228', 'n_results': 3}
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            print(f"Found {len(results)} results:")
            
            for i, result in enumerate(results[:3], 1):
                cve_id = result['id']
                severity = result['metadata']['severity']
                cvss_score = result['metadata']['cvss_score']
                year = result['metadata']['year']
                
                print(f"  {i}. {cve_id}: {severity} (CVSS {cvss_score}) - Year: {year}")
                
                # Check if this is the actual CVE-2021-44228
                if cve_id == 'CVE-2021-44228':
                    print(f"     ✅ Found the actual Log4Shell vulnerability!")
                    print(f"     📝 Description preview: {result['text'][:100]}...")
                else:
                    print(f"     📝 Related CVE mentioning CVE-2021-44228")
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_cve_search() 