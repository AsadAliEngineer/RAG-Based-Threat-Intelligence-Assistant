# scripts/test_hybrid_system.py
"""
Test script for the Hybrid RAG System
"""

import requests
import json
import time
from typing import List, Dict


class HybridSystemTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.test_results = []

    def test_health(self):
        """Test health endpoint"""
        print("\n=== Testing Health Endpoint ===")
        start = time.time()

        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            elapsed = time.time() - start

            print(f"Status: {response.status_code}")
            print(f"Response time: {elapsed:.3f}s")

            if response.status_code == 200:
                data = response.json()
                print(f"System status: {data.get('status')}")
                print(f"Components: {json.dumps(data.get('stats', {}), indent=2)}")

                if elapsed < 1.0:
                    print("PASS: Health check is fast")
                    return True
                else:
                    print("WARNING: Health check is slow")
                    return True
            else:
                print("FAIL: Health check failed")
                return False

        except Exception as e:
            print(f"FAIL: {e}")
            return False

    def test_exact_cve(self, cve_id: str):
        """Test exact CVE lookup"""
        print(f"\n=== Testing Exact CVE: {cve_id} ===")
        start = time.time()

        try:
            # Test via search endpoint
            response = requests.post(
                f"{self.base_url}/search",
                json={"query": cve_id, "top_k": 1},
                timeout=10
            )
            elapsed = time.time() - start

            if response.status_code == 200:
                data = response.json()
                print(f"Search time: {elapsed:.3f}s")
                print(f"Results found: {len(data) if isinstance(data, list) else 0}")

                if isinstance(data, list) and data:
                    result = data[0]
                    if result.get('id', '').upper() == cve_id.upper():
                        print(f"PASS: Found exact match with score {result.get('score', 0)}")
                        return True
                    else:
                        print(f"FAIL: Found {result.get('id')} instead of {cve_id}")
                        return False
                else:
                    print("FAIL: No results found")
                    return False
            else:
                print(f"FAIL: Search returned status {response.status_code}")
                return False

        except Exception as e:
            print(f"FAIL: {e}")
            return False

    def test_technology_search(self, query: str):
        """Test technology-related searches"""
        print(f"\n=== Testing Technology Search: '{query}' ===")

        try:
            response = requests.post(
                f"{self.base_url}/search",
                json={"query": query, "top_k": 10},
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                print(f"Search time: {time.time():.3f}s")
                print(f"Results found: {len(data) if isinstance(data, list) else 0}")

                if isinstance(data, list) and data:
                    print("\nTop 3 results:")
                    for i, result in enumerate(data[:3]):
                        print(f"\n{i + 1}. {result.get('id')}")
                        print(f"   Score: {result.get('score', 0):.2f}")
                        metadata = result.get('metadata', {})
                        print(f"   Severity: {metadata.get('severity', 'Unknown')}")
                        print(f"   Description: {result.get('text', '')[:100]}...")

                    print(f"\nPASS: Found {len(data)} results")
                    return True
                else:
                    print("WARNING: No results found")
                    return True
            else:
                print(f"FAIL: Search returned status {response.status_code}")
                return False

        except Exception as e:
            print(f"FAIL: {e}")
            return False

    def test_performance(self):
        """Test system performance with multiple queries"""
        print("\n=== Testing Performance ===")

        test_queries = [
            ("CVE-2021-44228", "exact"),
            ("CVE-2022-30190", "exact"),
            ("log4j vulnerabilities", "technology"),
            ("5G related vulnerabilities", "technology"),
            ("remote code execution 2024", "complex"),
            ("Microsoft Exchange vulnerabilities", "product")
        ]

        times = []

        for query, query_type in test_queries:
            try:
                start = time.time()
                response = requests.post(
                    f"{self.base_url}/search",
                    json={"query": query, "top_k": 5},
                    timeout=15
                )
                elapsed = time.time() - start
                times.append(elapsed)

                if response.status_code == 200:
                    data = response.json()
                    result_count = len(data) if isinstance(data, list) else 0
                    print(f"{query_type.capitalize()} query '{query}': {elapsed:.3f}s ({result_count} results)")
                else:
                    print(f"Failed: {query}")

            except Exception as e:
                print(f"Error with '{query}': {e}")

        if times:
            avg_time = sum(times) / len(times)
            print(f"\nAverage response time: {avg_time * 1000:.2f}ms")

            if avg_time < 2.0:
                print("PASS: Performance is good")
                return True
            else:
                print("WARNING: Performance could be improved")
                return True

        return False

    def run_all_tests(self):
        """Run all tests"""
        print("Hybrid CVE RAG System Test Suite")
        print("=" * 50)

        # Test health
        health_ok = self.test_health()

        if not health_ok:
            print("\nHealth check failed. Is the API running?")
            print("Start it with: python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000")
            return

        # Test exact CVE lookups
        self.test_exact_cve("CVE-2021-44228")  # Log4Shell
        self.test_exact_cve("CVE-2022-30190")  # Follina

        # Test technology searches
        self.test_technology_search("log4j vulnerabilities")
        self.test_technology_search("5G related vulnerabilities")
        self.test_technology_search("remote code execution 2024")

        # Test performance
        self.test_performance()

        print("\n" + "=" * 50)
        print("Test suite completed")


if __name__ == "__main__":
    tester = HybridSystemTester()
    tester.run_all_tests()