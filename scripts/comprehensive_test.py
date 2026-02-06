#!/usr/bin/env python3
"""
Comprehensive test script for CVE RAG System
Tests both API functionality and identifies potential UI issues
"""

import requests
import json
import time
from typing import Dict, List, Any

def test_api_health():
    """Test API health endpoint"""
    print("🔍 Testing API Health...")
    try:
        response = requests.get("http://localhost:8000/api/v1/health", timeout=10)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Health: {data.get('status', 'unknown')}")
            print(f"   GPU: {data.get('gpu_name', 'N/A')}")
            print(f"   Documents: {data.get('vector_db_documents', 0)}")
            print(f"   Model Loaded: {data.get('model_loaded', 'unknown')}")
            return True
        else:
            print(f"❌ Health check failed: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_search_endpoint():
    """Test search endpoint specifically for CVE-2021-44228"""
    print("\n🔍 Testing Search Endpoint...")
    try:
        payload = {
            "query": "CVE-2021-44228",
            "top_k": 5
        }
        
        response = requests.post(
            "http://localhost:8000/api/v1/search",
            json=payload,
            timeout=30
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Found {len(results)} results")
            
            # Check if we found the actual Log4Shell CVE
            found_log4shell = False
            for i, result in enumerate(results, 1):
                cve_id = result.get('id', 'Unknown')
                metadata = result.get('metadata', {})
                severity = metadata.get('severity', 'Unknown')
                cvss_score = metadata.get('cvss_score', 'Unknown')
                year = metadata.get('year', 'Unknown')
                
                print(f"  {i}. {cve_id}: {severity} (CVSS {cvss_score}) - Year: {year}")
                
                if cve_id == 'CVE-2021-44228':
                    found_log4shell = True
                    print(f"     ✅ Found the actual Log4Shell vulnerability!")
                    print(f"     📝 Description: {result.get('text', '')[:200]}...")
            
            if not found_log4shell:
                print("     ⚠️  Actual CVE-2021-44228 not found in top results")
            
            return True
        else:
            print(f"❌ Search failed: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Search error: {e}")
        return False

def test_query_endpoint():
    """Test full query endpoint with LLM generation"""
    print("\n🔍 Testing Full Query Endpoint...")
    try:
        payload = {
            "query": "What is CVE-2021-44228 and why is it dangerous?",
            "top_k": 5,
            "max_context_docs": 3,
            "use_large_model": False
        }
        
        response = requests.post(
            "http://localhost:8000/api/v1/query",
            json=payload,
            timeout=60
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Query successful")
            print(f"   Model Used: {data.get('model_used', 'unknown')}")
            print(f"   Processing Time: {data.get('processing_time', 0):.2f}s")
            print(f"   Results Count: {len(data.get('search_results', []))}")
            print(f"   Response Length: {len(data.get('response', ''))}")
            
            # Show response preview
            response_text = data.get('response', '')
            if response_text:
                print(f"   📝 Response Preview: {response_text[:300]}...")
            
            return True
        else:
            print(f"❌ Query failed: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Query error: {e}")
        return False

def test_summary_endpoint():
    """Test summary endpoint"""
    print("\n🔍 Testing Summary Endpoint...")
    try:
        payload = {
            "query": "Log4Shell vulnerabilities",
            "max_results": 20
        }
        
        response = requests.post(
            "http://localhost:8000/api/v1/summary",
            json=payload,
            timeout=30
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Summary successful")
            print(f"   Total Results: {data.get('total_results', 0)}")
            print(f"   Severity Distribution: {data.get('severity_distribution', {})}")
            print(f"   Top Vendors: {data.get('top_vendors', [])[:3]}")
            print(f"   Top Products: {data.get('top_products', [])[:3]}")
            
            return True
        else:
            print(f"❌ Summary failed: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Summary error: {e}")
        return False

def test_ui_compatibility():
    """Test endpoints that the Gradio UI uses"""
    print("\n🔍 Testing UI Compatibility...")
    
    # Test the exact endpoints the UI calls
    ui_tests = [
        {
            "name": "UI Search API",
            "url": "http://localhost:8000/api/v1/search",
            "method": "POST",
            "payload": {"query": "CVE-2021-44228", "top_k": 10}
        },
        {
            "name": "UI Query API", 
            "url": "http://localhost:8000/api/v1/query",
            "method": "POST",
            "payload": {
                "query": "What is CVE-2021-44228?",
                "top_k": 10,
                "max_context_docs": 5,
                "use_large_model": False
            }
        },
        {
            "name": "UI Summary API",
            "url": "http://localhost:8000/api/v1/summary", 
            "method": "POST",
            "payload": {"query": "Log4Shell", "max_results": 50}
        },
        {
            "name": "UI Health API",
            "url": "http://localhost:8000/api/v1/health",
            "method": "GET",
            "payload": None
        }
    ]
    
    all_passed = True
    
    for test in ui_tests:
        try:
            print(f"  Testing {test['name']}...")
            
            if test['method'] == 'GET':
                response = requests.get(test['url'], timeout=10)
            else:
                response = requests.post(test['url'], json=test['payload'], timeout=30)
            
            if response.status_code == 200:
                print(f"    ✅ {test['name']} - OK")
            else:
                print(f"    ❌ {test['name']} - Failed ({response.status_code})")
                all_passed = False
                
        except Exception as e:
            print(f"    ❌ {test['name']} - Error: {e}")
            all_passed = False
    
    return all_passed

def main():
    """Run comprehensive tests"""
    print("🚀 CVE RAG System - Comprehensive Test Suite")
    print("=" * 50)
    
    # Test API health first
    if not test_api_health():
        print("\n❌ API server is not healthy. Please check if it's running.")
        return
    
    # Test all endpoints
    tests = [
        ("Search Endpoint", test_search_endpoint),
        ("Query Endpoint", test_query_endpoint), 
        ("Summary Endpoint", test_summary_endpoint),
        ("UI Compatibility", test_ui_compatibility)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The system is working correctly.")
        print("💡 You can now start the Gradio UI with: python src/ui/gradio_app.py")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
        print("💡 The API server may need to be restarted or there may be configuration issues.")

if __name__ == "__main__":
    main() 