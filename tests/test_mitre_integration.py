# scripts/test_mitre_integration.py
"""
Test MITRE ATT&CK integration in the enhanced system
"""

import requests
import json

API_URL = "http://localhost:8000"


def test_mitre_search():
    """Test MITRE-specific searches"""
    print("Testing MITRE ATT&CK Integration")
    print("=" * 50)

    # Test 1: Search by tactic
    print("\n1. Testing MITRE Tactic Search (Persistence):")
    response = requests.get(f"{API_URL}/search/mitre?tactic=persistence&top_k=5")
    if response.status_code == 200:
        data = response.json()
        print(f"   Found {data['count']} CVEs related to Persistence tactic")
        if data['results']:
            for i, result in enumerate(data['results'][:3]):
                print(f"   {i + 1}. {result['id']} - Tactics: {result.get('mitre_tactics', [])}")

    # Test 2: Search by technique
    print("\n2. Testing MITRE Technique Search:")
    response = requests.get(f"{API_URL}/search/mitre?technique=T1055&top_k=5")
    if response.status_code == 200:
        data = response.json()
        print(f"   Found {data['count']} CVEs related to technique T1055")

    # Test 3: General MITRE query
    print("\n3. Testing General MITRE Query:")
    response = requests.post(
        f"{API_URL}/search",
        json={"query": "mitre attack privilege escalation", "top_k": 5}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"   Found {data['count']} results")
        for i, result in enumerate(data['results'][:3]):
            print(f"   {i + 1}. {result['id']}")
            if result.get('mitre_tactics'):
                print(f"      Tactics: {', '.join(result['mitre_tactics'][:3])}")
            if result.get('mitre_techniques'):
                print(f"      Techniques: {', '.join(result['mitre_techniques'][:3])}")


def test_enhanced_cve_lookup():
    """Test enhanced CVE lookup with all relationships"""
    print("\n\n4. Testing Enhanced CVE Lookup:")

    # Look up a specific CVE
    response = requests.get(f"{API_URL}/cve/CVE-2021-44228")
    if response.status_code == 200:
        cve = response.json()
        print(f"   CVE: {cve['id']}")
        print(f"   Severity: {cve.get('severity', 'N/A')}")
        print(f"   CVSS Score: {cve.get('cvss_score', 'N/A')}")

        if cve.get('cwe_ids'):
            print(f"   CWEs: {', '.join(map(str, cve['cwe_ids']))}")

        if cve.get('capec_ids'):
            print(f"   CAPECs: {', '.join(map(str, cve['capec_ids']))}")

        if cve.get('mitre_tactics'):
            print(f"   MITRE Tactics: {', '.join(cve['mitre_tactics'])}")

        if cve.get('mitre_techniques'):
            print(f"   MITRE Techniques: {', '.join(cve['mitre_techniques'])}")


def test_performance_comparison():
    """Compare performance with enhanced features"""
    import time

    print("\n\n5. Performance Comparison:")

    queries = [
        ("CVE-2021-44228", "Exact CVE"),
        ("log4j vulnerabilities", "Technology search"),
        ("mitre tactic lateral movement", "MITRE search"),
        ("remote code execution critical 2024", "Complex search")
    ]

    for query, query_type in queries:
        start = time.time()
        response = requests.post(
            f"{API_URL}/search",
            json={"query": query, "top_k": 10}
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            print(f"\n   {query_type}: '{query}'")
            print(f"   Response time: {elapsed:.0f}ms (API: {data.get('search_time_ms', 0):.0f}ms)")
            print(f"   Results: {data['count']}")


if __name__ == "__main__":
    test_mitre_search()
    test_enhanced_cve_lookup()
    test_performance_comparison()