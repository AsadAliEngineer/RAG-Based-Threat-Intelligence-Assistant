#!/usr/bin/env python3
"""
Test script for LLM integration with existing RAG system
Run this to test the LLM components step by step
"""

import os
import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_step_1_imports():
    """Test 1: Check if all imports work"""
    print("🧪 Step 1: Testing imports...")

    try:
        # Test RAG system import
        from src.generators.rag_system import CVERAGSystem
        print("✅ RAG System import successful")

        # Test LLM client import
        from src.generation.llm_client import LLMClient, TechnologyDetector, EnhancedQueryProcessor
        print("✅ LLM Client imports successful")

        return True

    except ImportError as e:
        print(f"❌ Import failed: {e}")
        print("💡 Make sure you saved the llm_client.py file in src/generation/")
        return False


def test_step_2_rag_system():
    """Test 2: Check if RAG system works"""
    print("\n🧪 Step 2: Testing RAG System...")

    try:
        from src.generators.rag_system import CVERAGSystem

        # Initialize RAG system
        rag_system = CVERAGSystem()
        print("✅ RAG System initialized")

        # Test basic search
        results = rag_system.search_cves("SQL injection", n_results=3)
        print(f"✅ Basic search works: Found {len(results)} results")

        if results:
            sample = results[0]
            print(f"   Sample result: {sample['metadata'].get('cve_id', 'Unknown')} - Score: {sample['score']:.3f}")

        return rag_system

    except Exception as e:
        print(f"❌ RAG System test failed: {e}")
        return None


def test_step_3_technology_detection():
    """Test 3: Check technology detection"""
    print("\n🧪 Step 3: Testing Technology Detection...")

    try:
        from src.generation.llm_client import TechnologyDetector

        test_queries = [
            "log4j vulnerabilities",
            "apache web server RCE",
            "SQL injection in MySQL",
            "Java deserialization attacks"
        ]

        for query in test_queries:
            analysis = TechnologyDetector.detect_technologies(query)
            print(f"✅ Query: '{query}'")
            print(f"   Technologies: {analysis['technologies']}")
            print(f"   Critical years: {analysis['critical_years']}")
            print(f"   Priority: {analysis['priority_level']}")

        return True

    except Exception as e:
        print(f"❌ Technology detection failed: {e}")
        return False


def test_step_4_llm_client():
    """Test 4: Check LLM client (without requiring Ollama)"""
    print("\n🧪 Step 4: Testing LLM Client...")

    try:
        from src.generation.llm_client import LLMClient

        # Initialize LLM client (should work even without Ollama)
        llm_client = LLMClient()
        print(f"✅ LLM Client initialized (Available: {llm_client.available})")

        if llm_client.available:
            print("🎉 Ollama service detected and working!")
        else:
            print("⚠️  Ollama not available - will use fallback mode")

        # Test query expansion (works without LLM)
        test_query = "SQL injection vulnerabilities"
        expanded = llm_client.expand_query(test_query)
        print(f"✅ Query expansion works: {len(expanded)} variations")
        for i, exp in enumerate(expanded[:3], 1):
            print(f"   {i}. {exp}")

        # Test fallback response generation
        mock_context = [
            {
                'metadata': {'cve_id': 'CVE-2021-34527', 'severity': 'Critical'},
                'text': 'Windows Print Spooler Remote Code Execution Vulnerability',
                'score': 0.95
            }
        ]

        response = llm_client._generate_fallback_response("windows print spooler", mock_context)
        print("✅ Fallback response generation works:")
        print(f"   {response[:100]}...")

        return llm_client

    except Exception as e:
        print(f"❌ LLM Client test failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_step_5_integration():
    """Test 5: Full integration test"""
    print("\n🧪 Step 5: Testing Full Integration...")

    try:
        from src.generators.rag_system import CVERAGSystem
        from src.generation.llm_client import LLMClient, EnhancedQueryProcessor

        # Initialize components
        rag_system = CVERAGSystem()
        llm_client = LLMClient()
        processor = EnhancedQueryProcessor(rag_system, llm_client)

        print("✅ All components initialized")

        # Test enhanced query processing
        test_queries = [
            "log4j vulnerability",
            "CVE-2021-44228",
            "apache remote code execution"
        ]

        for query in test_queries:
            print(f"\n📝 Testing query: '{query}'")

            try:
                result = processor.process_query(query, top_k=5, use_llm=True)

                print(f"✅ Processing successful")
                print(f"   Results found: {len(result['search_results'])}")
                print(f"   Processing time: {result['metadata'].get('processing_time', 0):.2f}s")
                print(f"   LLM used: {result['metadata'].get('llm_used', False)}")

                if result.get('llm_response'):
                    print(f"   LLM response: {result['llm_response'][:150]}...")

                # Show top result
                if result['search_results']:
                    top_result = result['search_results'][0]
                    cve_id = top_result['metadata'].get('cve_id', 'Unknown')
                    score = top_result.get('score', 0)
                    print(f"   Top result: {cve_id} (Score: {score:.3f})")

            except Exception as e:
                print(f"❌ Query processing failed: {e}")

        return True

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_step_6_ollama_setup():
    """Test 6: Guide for Ollama setup"""
    print("\n🧪 Step 6: Ollama Setup Guide...")

    try:
        import requests

        # Test Ollama connection
        response = requests.get("http://localhost:11434/api/tags", timeout=5)

        if response.status_code == 200:
            models = response.json()
            print("🎉 Ollama is running!")
            print(f"   Available models: {len(models.get('models', []))}")

            # Check for Llama 3
            llama_models = [m for m in models.get('models', []) if 'llama3' in m.get('name', '')]
            if llama_models:
                print(f"✅ Llama 3 models found: {[m['name'] for m in llama_models]}")
                return True
            else:
                print("⚠️  Llama 3 not found. Run: ollama pull llama3:8b")
                return False

        else:
            print("❌ Ollama not responding correctly")
            return False

    except Exception as e:
        print("⚠️  Ollama not running or not accessible")
        print("\n📋 To install and run Ollama:")
        print("1. Install: curl -fsSL https://ollama.com/install.sh | sh")
        print("2. Start: ollama serve")
        print("3. Pull model: ollama pull llama3:8b")
        print("4. Re-run this test")
        return False


def main():
    """Run all tests"""
    print("🚀 Testing LLM Integration with RAG System")
    print("=" * 50)

    # Create src/generation directory if it doesn't exist
    generation_dir = Path("src/generation")
    generation_dir.mkdir(parents=True, exist_ok=True)

    # Create __init__.py if it doesn't exist
    init_file = generation_dir / "__init__.py"
    if not init_file.exists():
        init_file.touch()
        print("📁 Created src/generation directory structure")

    # Run tests step by step
    tests = [
        test_step_1_imports,
        test_step_2_rag_system,
        test_step_3_technology_detection,
        test_step_4_llm_client,
        test_step_5_integration,
        test_step_6_ollama_setup
    ]

    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"❌ Test {test_func.__name__} crashed: {e}")
            results.append(False)
            import traceback
            traceback.print_exc()

    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")

    test_names = [
        "Imports",
        "RAG System",
        "Technology Detection",
        "LLM Client",
        "Full Integration",
        "Ollama Setup"
    ]

    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {i + 1}. {name}: {status}")

    passed_tests = sum(1 for r in results if r)
    total_tests = len(results)

    print(f"\n🎯 Overall: {passed_tests}/{total_tests} tests passed")

    if passed_tests >= 4:  # Basic functionality works
        print("\n🎉 LLM integration is working! You can now:")
        print("   - Use enhanced query processing")
        print("   - Get technology-aware search results")
        print("   - Benefit from query expansion and reranking")
        if results[5]:  # Ollama working
            print("   - Generate intelligent LLM responses")
        else:
            print("   - Install Ollama for full LLM responses")
    else:
        print("\n⚠️  Some issues need to be resolved before using LLM integration")


if __name__ == "__main__":
    main()