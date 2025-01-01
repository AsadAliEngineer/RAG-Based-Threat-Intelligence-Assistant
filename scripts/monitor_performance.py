#!/usr/bin/env python3
"""
Performance monitoring script for the CVE RAG System
"""

import time
import asyncio
import aiohttp
import json
import logging
from typing import Dict, List
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Monitor API performance and response times"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        
    async def _get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def test_query_performance(self, query: str, use_large_model: bool = False) -> Dict:
        """Test query performance and return metrics"""
        start_time = time.time()
        
        try:
            session = await self._get_session()
            
            payload = {
                "query": query,
                "top_k": 10,
                "max_context_docs": 5,
                "use_large_model": use_large_model
            }
            
            async with session.post(f"{self.api_url}/api/v1/query", json=payload) as response:
                end_time = time.time()
                response_time = end_time - start_time
                
                if response.status == 200:
                    data = await response.json()
                    return {
                        "status": "success",
                        "response_time": response_time,
                        "query": query,
                        "model_used": data.get('model_used', 'unknown'),
                        "processing_time": data.get('processing_time', 0),
                        "results_count": len(data.get('search_results', [])),
                        "response_length": len(data.get('response', ''))
                    }
                else:
                    error_text = await response.text()
                    return {
                        "status": "error",
                        "response_time": response_time,
                        "query": query,
                        "error": f"{response.status}: {error_text}"
                    }
                    
        except Exception as e:
            end_time = time.time()
            return {
                "status": "error",
                "response_time": end_time - start_time,
                "query": query,
                "error": str(e)
            }
    
    async def test_search_performance(self, query: str) -> Dict:
        """Test search-only performance"""
        start_time = time.time()
        
        try:
            session = await self._get_session()
            
            payload = {
                "query": query,
                "top_k": 10
            }
            
            async with session.post(f"{self.api_url}/api/v1/search", json=payload) as response:
                end_time = time.time()
                response_time = end_time - start_time
                
                if response.status == 200:
                    data = await response.json()
                    return {
                        "status": "success",
                        "response_time": response_time,
                        "query": query,
                        "results_count": len(data)
                    }
                else:
                    error_text = await response.text()
                    return {
                        "status": "error",
                        "response_time": response_time,
                        "query": query,
                        "error": f"{response.status}: {error_text}"
                    }
                    
        except Exception as e:
            end_time = time.time()
            return {
                "status": "error",
                "response_time": end_time - start_time,
                "query": query,
                "error": str(e)
            }
    
    async def test_health_check(self) -> Dict:
        """Test health check endpoint"""
        start_time = time.time()
        
        try:
            session = await self._get_session()
            
            async with session.get(f"{self.api_url}/api/v1/health") as response:
                end_time = time.time()
                response_time = end_time - start_time
                
                if response.status == 200:
                    data = await response.json()
                    return {
                        "status": "success",
                        "response_time": response_time,
                        "health_status": data.get('status'),
                        "gpu_available": data.get('gpu_available'),
                        "vector_db_documents": data.get('vector_db_documents'),
                        "model_loaded": data.get('model_loaded')
                    }
                else:
                    error_text = await response.text()
                    return {
                        "status": "error",
                        "response_time": response_time,
                        "error": f"{response.status}: {error_text}"
                    }
                    
        except Exception as e:
            end_time = time.time()
            return {
                "status": "error",
                "response_time": end_time - start_time,
                "error": str(e)
            }
    
    async def run_performance_tests(self) -> Dict:
        """Run comprehensive performance tests"""
        logger.info("Starting performance tests...")
        
        # Test queries
        test_queries = [
            "What is CVE-2021-44228?",
            "Show me Microsoft vulnerabilities",
            "Find SQL injection vulnerabilities",
            "What are critical vulnerabilities from 2024?",
            "Summarize 5G related vulnerabilities"
        ]
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "health_check": await self.test_health_check(),
            "search_tests": [],
            "query_tests": []
        }
        
        # Test search performance
        logger.info("Testing search performance...")
        for query in test_queries:
            result = await self.test_search_performance(query)
            results["search_tests"].append(result)
            await asyncio.sleep(1)  # Rate limiting
        
        # Test full query performance
        logger.info("Testing full query performance...")
        for query in test_queries:
            result = await self.test_query_performance(query, use_large_model=False)
            results["query_tests"].append(result)
            await asyncio.sleep(2)  # Rate limiting
        
        # Calculate statistics
        search_times = [r["response_time"] for r in results["search_tests"] if r["status"] == "success"]
        query_times = [r["response_time"] for r in results["query_tests"] if r["status"] == "success"]
        
        if search_times:
            results["search_stats"] = {
                "avg_response_time": sum(search_times) / len(search_times),
                "min_response_time": min(search_times),
                "max_response_time": max(search_times),
                "success_rate": len(search_times) / len(results["search_tests"])
            }
        
        if query_times:
            results["query_stats"] = {
                "avg_response_time": sum(query_times) / len(query_times),
                "min_response_time": min(query_times),
                "max_response_time": max(query_times),
                "success_rate": len(query_times) / len(results["query_tests"])
            }
        
        return results
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()

def main():
    """Main function"""
    async def run_tests():
        monitor = PerformanceMonitor()
        try:
            results = await monitor.run_performance_tests()
            
            # Print results
            print("\n" + "="*60)
            print("CVE RAG SYSTEM PERFORMANCE REPORT")
            print("="*60)
            print(f"Timestamp: {results['timestamp']}")
            
            # Health check
            health = results["health_check"]
            print(f"\nHealth Check: {health['status']}")
            if health['status'] == 'success':
                print(f"  Response Time: {health['response_time']:.2f}s")
                print(f"  System Status: {health['health_status']}")
                print(f"  GPU Available: {health['gpu_available']}")
                print(f"  Vector DB Documents: {health['vector_db_documents']}")
                print(f"  Model Loaded: {health['model_loaded']}")
            
            # Search performance
            if "search_stats" in results:
                stats = results["search_stats"]
                print(f"\nSearch Performance:")
                print(f"  Average Response Time: {stats['avg_response_time']:.2f}s")
                print(f"  Min Response Time: {stats['min_response_time']:.2f}s")
                print(f"  Max Response Time: {stats['max_response_time']:.2f}s")
                print(f"  Success Rate: {stats['success_rate']:.1%}")
            
            # Query performance
            if "query_stats" in results:
                stats = results["query_stats"]
                print(f"\nFull Query Performance:")
                print(f"  Average Response Time: {stats['avg_response_time']:.2f}s")
                print(f"  Min Response Time: {stats['min_response_time']:.2f}s")
                print(f"  Max Response Time: {stats['max_response_time']:.2f}s")
                print(f"  Success Rate: {stats['success_rate']:.1%}")
            
            # Detailed results
            print(f"\nDetailed Results:")
            for i, result in enumerate(results["query_tests"]):
                status = "SUCCESS" if result["status"] == "success" else "ERROR"
                print(f"  [{status}] {result['query']}: {result['response_time']:.2f}s")
                if result["status"] == "error":
                    print(f"    Error: {result['error']}")
            
            # Save results to file
            with open("performance_report.json", "w") as f:
                json.dump(results, f, indent=2)
            print(f"\nDetailed report saved to: performance_report.json")
            
        finally:
            await monitor.close()
    
    asyncio.run(run_tests())

if __name__ == "__main__":
    main() 