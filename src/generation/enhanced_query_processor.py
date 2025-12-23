# src/generation/enhanced_query_processor.py


import logging
from typing import Dict, List, Any, Optional
import re
import time

logger = logging.getLogger(__name__)


class EnhancedQueryProcessor:
    """Query processor that integrates LLM with RAG system using correct method names"""

    def __init__(self, rag_system, llm_client=None):
        self.rag_system = rag_system
        self.llm_client = llm_client

        # Import TechnologyDetector from the fixed LLM client
        from src.generation.llm_client import TechnologyDetector
        self.tech_detector = TechnologyDetector()

        logger.info(
            f"Enhanced Query Processor initialized (LLM: {'available' if llm_client and llm_client.available else 'disabled'})")

    def process_query(
            self,
            query: str,
            top_k: int = 10,
            years: Optional[List[str]] = None,
            use_llm: bool = True
    ) -> Dict[str, Any]:
        """Process query with LLM integration using correct RAG methods"""

        start_time = time.time()

        try:
            # 1. Detect technologies and analyze query
            tech_analysis = self.tech_detector.detect_technologies(query)
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', query, re.IGNORECASE)

            # 2. Determine search strategy
            if cve_ids:
                search_method = "cve_lookup"
                search_years = None
            elif tech_analysis['critical_years'] and not years:
                search_method = "year_based"
                search_years = [str(y) for y in tech_analysis['critical_years'][-3:]]  # Last 3 years
            else:
                search_method = "general"
                search_years = years

            # 3. Execute search using correct method names
            search_results = self._execute_search_with_correct_methods(
                query, search_method, search_years, top_k, tech_analysis
            )

            # 4. Rerank results if LLM available
            if self.llm_client and self.llm_client.available and search_results:
                search_results = self.llm_client.rerank_results(query, search_results, top_k)

            # 5. Generate LLM response if available
            llm_response = None
            if self.llm_client and self.llm_client.available and use_llm:
                query_type = self._determine_query_type(query, cve_ids, tech_analysis)
                llm_response = self.llm_client.generate_response(query, search_results, query_type)
            elif search_results:
                llm_response = self._generate_simple_summary(query, search_results)
            else:
                llm_response = f"No relevant results found for: {query}"

            processing_time = time.time() - start_time

            return {
                'query': query,
                'search_results': search_results,
                'llm_response': llm_response,
                'metadata': {
                    'processing_time': processing_time,
                    'search_method': search_method,
                    'results_count': len(search_results),
                    'llm_used': self.llm_client and self.llm_client.available and use_llm,
                    'technologies_detected': tech_analysis['technologies'],
                    'critical_years': tech_analysis['critical_years']
                }
            }

        except Exception as e:
            logger.error(f"Query processing failed: {e}")

            # Fallback to basic search using correct method
            try:
                fallback_results = self.rag_system.search_cves(query, top_k)
                processing_time = time.time() - start_time

                return {
                    'query': query,
                    'search_results': fallback_results,
                    'llm_response': f"Basic search completed. Enhanced processing failed: {str(e)}",
                    'metadata': {
                        'processing_time': processing_time,
                        'fallback_used': True,
                        'error': str(e)
                    }
                }
            except Exception as fallback_error:
                processing_time = time.time() - start_time
                logger.error(f"Fallback search also failed: {fallback_error}")

                return {
                    'query': query,
                    'search_results': [],
                    'llm_response': f"Search failed: {str(e)}",
                    'metadata': {
                        'processing_time': processing_time,
                        'error': True,
                        'error_details': str(e)
                    }
                }

    def _execute_search_with_correct_methods(
            self,
            query: str,
            search_method: str,
            search_years: Optional[List[str]],
            top_k: int,
            tech_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute search using the correct CVERAGSystem method names"""

        try:
            if search_method == "cve_lookup":
                # Direct CVE lookup - use basic search
                logger.info(f"Using direct CVE lookup for: {query}")
                results = self.rag_system.search_cves(query, top_k)

            elif search_method == "year_based" and search_years:
                # Year-based search if method exists
                logger.info(f"Using year-based search for years: {search_years}")
                if hasattr(self.rag_system, 'search_cves_by_year'):
                    results = self.rag_system.search_cves_by_year(query, search_years, top_k)
                else:
                    # Fallback to regular search if year-based method doesn't exist
                    logger.warning("search_cves_by_year not available, falling back to regular search")
                    results = self.rag_system.search_cves(query, top_k)

            else:
                # General search
                logger.info(f"Using general search for: {query}")
                results = self.rag_system.search_cves(query, top_k)

            logger.info(f"Search completed: found {len(results)} results")
            return results

        except Exception as e:
            logger.error(f"Search execution failed: {e}")
            return []

    def _determine_query_type(
            self,
            query: str,
            cve_ids: List[str],
            tech_analysis: Dict[str, Any]
    ) -> str:
        """Determine query type for LLM prompt selection"""

        query_lower = query.lower()

        if cve_ids:
            return "cve_analysis"
        elif any(word in query_lower for word in ['explain', 'how', 'what', 'why', 'describe']):
            return "technical"
        elif tech_analysis['technologies']:
            return "technology_analysis"
        else:
            return "general"

    def _generate_simple_summary(self, query: str, results: List[Dict]) -> str:
        """Generate simple summary when LLM is not available"""
        if not results:
            return f"No results found for: {query}"

        cve_count = len(results)

        # Extract CVE IDs and severities
        cve_ids = []
        severities = []

        for result in results[:3]:  # Top 3 results
            metadata = result.get('metadata', {})
            cve_id = metadata.get('cve_id', 'Unknown')
            severity = metadata.get('severity', 'Unknown')

            cve_ids.append(cve_id)
            severities.append(severity)

        # Generate summary
        summary_lines = [
            f"Found {cve_count} vulnerabilities for: {query}",
            f"Top CVEs: {', '.join(cve_ids)}",
            f"Severity levels: {', '.join(set(s for s in severities if s != 'Unknown'))}",
            "",
            "Use LLM integration for detailed analysis and recommendations."
        ]

        return "\n".join(summary_lines)


# Simple test function for the processor
def test_enhanced_processor():
    """Test the enhanced query processor"""
    try:
        from src.generators.rag_system import CVERAGSystem
        from src.generation.llm_client_fixed import LLMClient

        # Initialize components
        print("Initializing RAG system...")
        rag_system = CVERAGSystem()

        print("Initializing LLM client...")
        llm_client = LLMClient()

        print("Initializing enhanced processor...")
        processor = EnhancedQueryProcessor(rag_system, llm_client)

        # Test with different query types
        test_queries = [
            "SQL injection vulnerabilities",
            "log4j vulnerability",
            "CVE-2021-44228"
        ]

        for query in test_queries:
            print(f"\n{'=' * 50}")
            print(f"Testing: {query}")
            print(f"{'=' * 50}")

            result = processor.process_query(query, top_k=3)

            print(f"Results: {len(result['search_results'])}")
            print(f"Time: {result['metadata']['processing_time']:.2f}s")
            print(f"Method: {result['metadata']['search_method']}")
            print(f"LLM used: {result['metadata']['llm_used']}")

            if result['llm_response']:
                print(f"Response: {result['llm_response'][:150]}...")

            if result['search_results']:
                top_result = result['search_results'][0]
                cve_id = top_result['metadata'].get('cve_id', 'Unknown')
                score = top_result.get('score', 0)
                print(f"Top result: {cve_id} (Score: {score:.3f})")

        return processor

    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    test_enhanced_processor()