#!/usr/bin/env python3
"""
Test script for the simplified RAG API
Run this to test if your API is working correctly
"""

import requests
import json
import time
import sys

API_BASE_URL = "http://localhost:8000/api/v1"


def test_health():
    """Test the health endpoint"""
    print("🏥 Testing health endpoint...")
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed")
            print(f"   Status: {data.get('status')}")
            print(f"   Documents: {data.get('vector_db_documents', 0):,}")
            print(f"   GPU: {data.get('gpu_available', False)}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False


def test_search():
    """Test the search endpoint"""
    print("\n🔍 Testing search endpoint...")

    test_queries = [
        "SQL injection",
        "remote code execution",
        "buffer overflow"
    ]

    for query in test_queries:
        try:
            print(f"   Searching for: '{query}'")
            start_time = time.time()

            payload = {
                "query": query,
                "top_k": 3
            }

            response = requests.post(
                f"{API_BASE_URL}/search",
                json=payload,
                timeout=15
            )

            elapsed = time.time() - start_time

            if response.status_code == 200:
                results = response.json()
                print(f"   ✅ Found {len(results)} results in {elapsed:.2f}s")
                if results:
                    first_result = results[0]
                    print(f"      First result ID: {first_result.get('id', 'N/A')}")
                    print(f"      Score: {first_result.get('score', 0):.3f}")
            else:
                print(f"   ❌ Search failed: {response.status_code}")
                print(f"      Error: {response.text}")
                return False

        except requests.exceptions.Timeout:
            print(f"   ⏰ Search timed out for: {query}")
            return False
        except Exception as e:
            print(f"   ❌ Search error for '{query}': {e}")
            return False

    return True


def test_query():
    """Test the query endpoint (with LLM response)"""
    print("\n💬 Testing query endpoint...")

    try:
        payload = {
            "query": "What are the most critical SQL injection vulnerabilities?",
            "top_k": 2,
            "max_context_docs": 2
        }

        print(f"   Query: {payload['query']}")
        start_time = time.time()

        response = requests.post(
            f"{API_BASE_URL}/query",
            json=payload,
            timeout=20
        )

        elapsed = time.time() - start_time

        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Query completed in {elapsed:.2f}s")
            print(f"      Response length: {len(data.get('response', ''))}")
            print(f"      Search results: {len(data.get('search_results', []))}")
            print(f"      Processing time: {data.get('processing_time', 0):.2f}s")

            # Show first bit of response
            response_text = data.get('response', '')
            if len(response_text) > 100:
                print(f"      Response preview: {response_text[:100]}...")
            else:
                print(f"      Response: {response_text}")

            return True
        else:
            print(f"   ❌ Query failed: {response.status_code}")
            print(f"      Error: {response.text}")
            return False

    except requests.exceptions.Timeout:
        print(f"   ⏰ Query timed out")
        return False
    except Exception as e:
        print(f"   ❌ Query error: {e}")
        return False


def test_summary():
    """Test the summary endpoint"""
    print("\n📊 Testing summary endpoint...")

    try:
        payload = {
            "query": "web application vulnerabilities",
            "max_results": 20
        }

        print(f"   Summary query: {payload['query']}")
        start_time = time.time()

        response = requests.post(
            f"{API_BASE_URL}/summary",
            json=payload,
            timeout=20
        )

        elapsed = time.time() - start_time

        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Summary completed in {elapsed:.2f}s")
            print(f"      Total results: {data.get('total_results', 0)}")
            print(f"      Severities: {data.get('severity_distribution', {})}")
            print(f"      Top vendors: {data.get('top_vendors', [])[:3]}")
            return True
        else:
            print(f"   ❌ Summary failed: {response.status_code}")
            print(f"      Error: {response.text}")
            return False

    except requests.exceptions.Timeout:
        print(f"   ⏰ Summary timed out")
        return False
    except Exception as e:
        print(f"   ❌ Summary error: {e}")
        return False


def test_stats():
    """Test the stats endpoint"""
    print("\n📈 Testing stats endpoint...")
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Stats retrieved")
            print(f"   Status: {data.get('status')}")
            print(f"   Documents: {data.get('total_documents', 0):,}")
            print(f"   Version: {data.get('api_version')}")
            return True
        else:
            print(f"❌ Stats failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Stats error: {e}")
        return False


def main():
    """Run all tests"""
    print("🚀 Testing Simplified CVE RAG API")
    print("=" * 50)

    # Check if API is running
    try:
        requests.get(f"{API_BASE_URL}/health", timeout=5)
    except requests.exceptions.ConnectionError:
        print("❌ API is not running!")
        print("   Start it with: python -m src.api.main")
        sys.exit(1)
    except:
        pass  # Other errors will be caught by individual tests

    tests = [
        ("Health Check", test_health),
        ("Search", test_search),
        ("Query", test_query),
        ("Summary", test_summary),
        ("Stats", test_stats)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n{'=' * 20} {test_name} {'=' * 20}")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} test failed")

    print("\n" + "=" * 50)
    print(f"🎯 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Your API is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the error messages above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)