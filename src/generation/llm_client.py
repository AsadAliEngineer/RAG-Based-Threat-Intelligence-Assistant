# src/generation/llm_client.py
"""
LLM Client for local Ollama integration with Llama 3 8B
Phase 3 implementation - Core LLM functionality without API dependencies
"""

import json
import logging
import requests
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)


class ModelType(Enum):
    LLAMA3_8B = "llama3:8b"
    LLAMA3_8B_INSTRUCT = "llama3:8b-instruct"


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    base_url: str = "http://localhost:11434"
    model: str = "llama3:8b"
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 60
    stream: bool = False


class PromptTemplate:
    """Template manager for different query types"""

    CVE_ANALYSIS = """You are a cybersecurity expert analyzing CVE vulnerabilities. 

Context Information:
{context}

User Question: {query}

Please provide a comprehensive analysis including:
1. Summary of the vulnerability
2. Technical details and affected systems
3. Risk assessment and CVSS score interpretation
4. Remediation steps and patches
5. Related vulnerabilities or attack patterns

Response should be technical but accessible. Focus on actionable information."""

    GENERAL_SEARCH = """You are a cybersecurity assistant helping with vulnerability research.

Search Results:
{context}

User Query: {query}

Based on the search results above, provide a helpful response that:
1. Directly answers the user's question
2. Synthesizes information from multiple sources
3. Highlights the most relevant findings
4. Suggests related areas to investigate

Keep the response concise but informative."""

    TECHNICAL_EXPLANATION = """You are explaining cybersecurity concepts to help users understand vulnerabilities.

Relevant Information:
{context}

Question: {query}

Provide a clear explanation that:
1. Explains technical concepts in accessible terms
2. Uses examples from the provided context
3. Connects to broader security implications
4. Suggests best practices

Aim for educational value while being precise."""


class QueryExpander:
    """Intelligent query expansion for better search results"""

    @staticmethod
    def expand_cve_query(query: str) -> List[str]:
        """Expand CVE-related queries with synonyms and related terms"""
        base_query = query.lower()
        expanded_queries = [query]

        # CVE-specific expansions
        cve_expansions = {
            'rce': ['remote code execution', 'arbitrary code execution'],
            'xss': ['cross-site scripting', 'script injection'],
            'sqli': ['sql injection', 'database injection'],
            'csrf': ['cross-site request forgery', 'session riding'],
            'lfi': ['local file inclusion', 'directory traversal'],
            'rfi': ['remote file inclusion', 'file inclusion'],
            'dos': ['denial of service', 'service disruption'],
            'privilege escalation': ['elevation of privilege', 'privesc'],
            'buffer overflow': ['buffer overrun', 'memory corruption'],
            'authentication bypass': ['auth bypass', 'access control']
        }

        for term, synonyms in cve_expansions.items():
            if term in base_query:
                expanded_queries.extend([f"{query} {syn}" for syn in synonyms])

        return expanded_queries[:3]  # Limit to avoid overexpansion

    @staticmethod
    def expand_technology_query(query: str, technologies: List[str]) -> List[str]:
        """Expand queries based on detected technologies"""
        expanded = [query]

        tech_contexts = {
            'apache': ['httpd', 'web server', 'mod_'],
            'nginx': ['web server', 'reverse proxy'],
            'wordpress': ['cms', 'plugin', 'theme'],
            'mysql': ['database', 'mariadb', 'sql'],
            'postgresql': ['database', 'postgres', 'sql'],
            'java': ['jvm', 'spring', 'log4j'],
            'python': ['django', 'flask', 'pip'],
            'node.js': ['nodejs', 'npm', 'express'],
            'docker': ['container', 'containerization'],
            'kubernetes': ['k8s', 'orchestration', 'cluster']
        }

        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in tech_contexts:
                contexts = tech_contexts[tech_lower]
                expanded.extend([f"{query} {ctx}" for ctx in contexts[:2]])

        return expanded[:5]


class ResultReranker:
    """Rerank search results based on relevance and LLM scoring"""

    def __init__(self, llm_client):
        self.llm_client = llm_client

    def rerank_results(self, query: str, results: List[Dict], top_k: int = 10) -> List[Dict]:
        """Rerank results using LLM-based relevance scoring"""
        if not results or len(results) <= top_k:
            return results

        try:
            # Batch scoring for efficiency
            scored_results = []

            for result in results:
                content = result.get('text', result.get('content', ''))[:500]  # Limit for scoring
                score = self._score_relevance(query, content)

                result_copy = result.copy()
                result_copy['llm_score'] = score
                result_copy['combined_score'] = (
                        result.get('score', 0.0) * 0.7 + score * 0.3
                )
                scored_results.append(result_copy)

            # Sort by combined score
            scored_results.sort(key=lambda x: x['combined_score'], reverse=True)
            return scored_results[:top_k]

        except Exception as e:
            logger.warning(f"Reranking failed: {e}, returning original results")
            return results[:top_k]

    def _score_relevance(self, query: str, content: str) -> float:
        """Score relevance using simple heuristics (fallback for when LLM is unavailable)"""
        try:
            # Simple keyword-based scoring as fallback
            query_words = set(query.lower().split())
            content_words = set(content.lower().split())

            overlap = len(query_words.intersection(content_words))
            total_query_words = len(query_words)

            if total_query_words == 0:
                return 0.0

            return overlap / total_query_words

        except Exception:
            return 0.0


class LLMClient:
    """Main LLM client for local Ollama integration"""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.query_expander = QueryExpander()
        self.reranker = ResultReranker(self)

        # Test connection
        self.available = self._test_connection()
        if not self.available:
            logger.warning("LLM service not available, running in search-only mode")

    def _test_connection(self) -> bool:
        """Test if Ollama service is available"""
        try:
            response = requests.get(
                f"{self.config.base_url}/api/tags",
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.info(f"LLM service test failed: {e}")
            return False

    def generate_response(
            self,
            query: str,
            context: List[Dict[str, Any]],
            query_type: str = "general"
    ) -> str:
        """Generate response using LLM with context"""

        if not self.available:
            return self._generate_fallback_response(query, context)

        try:
            # Prepare context
            context_text = self._format_context(context)

            # Select appropriate prompt template
            if query_type == "cve_analysis":
                prompt = PromptTemplate.CVE_ANALYSIS.format(
                    context=context_text,
                    query=query
                )
            elif query_type == "technical":
                prompt = PromptTemplate.TECHNICAL_EXPLANATION.format(
                    context=context_text,
                    query=query
                )
            else:
                prompt = PromptTemplate.GENERAL_SEARCH.format(
                    context=context_text,
                    query=query
                )

            # Call LLM
            response = self._call_ollama(prompt)
            return response

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._generate_fallback_response(query, context)

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API"""
        try:
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens
                }
            }

            response = requests.post(
                f"{self.config.base_url}/api/generate",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'No response generated')
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return "Error generating response"

        except requests.exceptions.Timeout:
            logger.error("LLM request timeout")
            return "Response generation timed out"
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            return "Error calling LLM service"

    def _format_context(self, context: List[Dict[str, Any]]) -> str:
        """Format search results into context for LLM"""
        if not context:
            return "No relevant context found."

        formatted_parts = []
        for i, item in enumerate(context[:5], 1):  # Limit context to top 5 results
            text = item.get('text', item.get('content', ''))
            metadata = item.get('metadata', {})

            # Extract key metadata
            cve_id = metadata.get('cve_id', 'Unknown')
            severity = metadata.get('severity', 'Unknown')
            score = item.get('score', 0.0)

            formatted_parts.append(
                f"[Result {i}] CVE: {cve_id} | Severity: {severity} | Relevance: {score:.3f}\n"
                f"{text[:800]}{'...' if len(text) > 800 else ''}\n"
            )

        return "\n".join(formatted_parts)

    def _generate_fallback_response(self, query: str, context: List[Dict]) -> str:
        """Generate a structured response when LLM is not available"""
        if not context:
            return f"No relevant information found for query: {query}"

        # Analyze context to provide structured summary
        cve_ids = []
        severities = []
        technologies = []

        for item in context[:3]:  # Top 3 results
            metadata = item.get('metadata', {})
            cve_ids.append(metadata.get('cve_id', 'Unknown'))
            severities.append(metadata.get('severity', 'Unknown'))

            text = item.get('text', '')
            # Simple technology extraction
            tech_patterns = ['apache', 'nginx', 'mysql', 'java', 'python', 'wordpress']
            for tech in tech_patterns:
                if tech.lower() in text.lower():
                    technologies.append(tech)

        # Generate structured summary
        summary_parts = [
            f"Search Results Summary for: {query}",
            f"Found {len(context)} relevant vulnerabilities",
            f"Top CVEs: {', '.join(cve_ids[:3])}",
            f"Severity levels: {', '.join(set(severities))}",
        ]

        if technologies:
            summary_parts.append(f"Affected technologies: {', '.join(set(technologies))}")

        summary_parts.append("\nFor detailed analysis, please refer to the individual search results below.")

        return "\n".join(summary_parts)

    def expand_query(self, query: str, technologies: List[str] = None) -> List[str]:
        """Expand query for better search results"""
        try:
            if technologies:
                return self.query_expander.expand_technology_query(query, technologies)
            else:
                return self.query_expander.expand_cve_query(query)
        except Exception as e:
            logger.warning(f"Query expansion failed: {e}")
            return [query]

    def rerank_results(self, query: str, results: List[Dict], top_k: int = 10) -> List[Dict]:
        """Rerank search results using LLM"""
        return self.reranker.rerank_results(query, results, top_k)


# src/generation/enhanced_query_processor.py
"""
Enhanced Query Processor - Integrates LLM with RAG system
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import re
import time

logger = logging.getLogger(__name__)


@dataclass
class ProcessedQuery:
    """Container for processed query information"""
    original_query: str
    expanded_queries: List[str]
    detected_entities: Dict[str, Any]
    query_type: str
    suggested_years: List[str]
    confidence: float


class TechnologyDetector:
    """Detect technologies and suggest relevant time periods"""

    TECHNOLOGY_PATTERNS = {
        'log4j': {'years': [2021, 2022, 2023], 'priority': 5, 'aliases': ['log4shell']},
        'apache': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['httpd']},
        'nginx': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 3, 'aliases': []},
        'wordpress': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['wp']},
        'drupal': {'years': [2018, 2019, 2020, 2021, 2022], 'priority': 3, 'aliases': []},
        'mysql': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 3, 'aliases': ['mariadb']},
        'postgresql': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 3, 'aliases': ['postgres']},
        'java': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['jvm', 'openjdk']},
        'python': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 3, 'aliases': ['django', 'flask']},
        'node.js': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 3, 'aliases': ['nodejs', 'npm']},
        'docker': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 4, 'aliases': ['container']},
        'kubernetes': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['k8s']},
        'windows': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['microsoft']},
        'linux': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 3, 'aliases': ['ubuntu', 'debian']},
        'openssl': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4, 'aliases': []},
        'spring': {'years': [2021, 2022, 2023, 2024], 'priority': 4, 'aliases': ['springboot']},
        'jenkins': {'years': [2020, 2021, 2022, 2023], 'priority': 3, 'aliases': []},
        'elasticsearch': {'years': [2020, 2021, 2022, 2023], 'priority': 3, 'aliases': ['elastic']},
    }

    @classmethod
    def detect_technologies(cls, query: str) -> Dict[str, Any]:
        """Detect technologies and return relevant information"""
        query_lower = query.lower()
        detected_technologies = []
        critical_years = set()
        max_priority = 0

        for tech, info in cls.TECHNOLOGY_PATTERNS.items():
            # Check main technology name
            if tech in query_lower:
                detected_technologies.append(tech)
                critical_years.update(info['years'])
                max_priority = max(max_priority, info['priority'])
                continue

            # Check aliases
            for alias in info['aliases']:
                if alias in query_lower:
                    detected_technologies.append(tech)
                    critical_years.update(info['years'])
                    max_priority = max(max_priority, info['priority'])
                    break

        return {
            'technologies': detected_technologies,
            'critical_years': sorted(list(critical_years)),
            'priority_level': max_priority,
            'search_strategy': cls._determine_search_strategy(detected_technologies, max_priority)
        }

    @classmethod
    def _determine_search_strategy(cls, technologies: List[str], priority: int) -> Dict[str, Any]:
        """Determine optimal search strategy based on detected technologies"""
        if priority >= 4:  # High priority technologies
            return {
                'strategy': 'focused_tech',
                'result_limit': 20,
                'year_focus': True,
                'expand_query': True
            }
        elif priority >= 3:  # Medium priority
            return {
                'strategy': 'balanced',
                'result_limit': 15,
                'year_focus': True,
                'expand_query': False
            }
        else:  # General search
            return {
                'strategy': 'general',
                'result_limit': 10,
                'year_focus': False,
                'expand_query': False
            }


class EnhancedQueryProcessor:
    """Main query processor that coordinates LLM and RAG system"""

    def __init__(self, rag_system, llm_client=None):
        self.rag_system = rag_system
        self.llm_client = llm_client
        self.tech_detector = TechnologyDetector()

        logger.info(f"Enhanced Query Processor initialized (LLM: {'available' if llm_client else 'disabled'})")

    def process_query(
            self,
            query: str,
            top_k: int = 10,
            years: Optional[List[str]] = None,
            use_llm: bool = True
    ) -> Dict[str, Any]:
        """Process query with full LLM integration"""

        start_time = time.time()

        try:
            # 1. Analyze and expand query
            processed_query = self._analyze_query(query)

            # 2. Determine search parameters
            search_params = self._determine_search_params(
                processed_query, top_k, years
            )

            # 3. Execute search with expanded queries
            search_results = self._execute_enhanced_search(
                processed_query, search_params
            )

            # 4. Rerank results using LLM if available
            if self.llm_client and use_llm and search_results:
                search_results = self.llm_client.rerank_results(
                    query, search_results, top_k
                )

            # 5. Generate LLM response if available
            llm_response = None
            if self.llm_client and use_llm:
                query_type = self._determine_query_type(processed_query)
                llm_response = self.llm_client.generate_response(
                    query, search_results, query_type
                )

            processing_time = time.time() - start_time

            return {
                'query': query,
                'processed_query': processed_query,
                'search_results': search_results,
                'llm_response': llm_response,
                'metadata': {
                    'processing_time': processing_time,
                    'search_strategy': search_params.get('strategy'),
                    'results_count': len(search_results),
                    'llm_used': llm_response is not None
                }
            }

        except Exception as e:
            logger.error(f"Query processing failed: {e}")
            # Fallback to basic search
            try:
                basic_results = self.rag_system.search(query, top_k)
                return {
                    'query': query,
                    'search_results': basic_results,
                    'llm_response': f"Basic search completed. Advanced processing failed: {str(e)}",
                    'metadata': {'fallback_used': True}
                }
            except Exception as fallback_error:
                logger.error(f"Fallback search also failed: {fallback_error}")
                return {
                    'query': query,
                    'search_results': [],
                    'llm_response': f"Search failed: {str(e)}",
                    'metadata': {'error': True}
                }

    def _analyze_query(self, query: str) -> ProcessedQuery:
        """Analyze query to extract entities and expand"""

        # Detect technologies
        tech_analysis = self.tech_detector.detect_technologies(query)

        # Extract CVE IDs
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', query, re.IGNORECASE)

        # Extract years
        year_matches = re.findall(r'\b(20\d{2})\b', query)

        # Expand query if LLM is available
        expanded_queries = [query]
        if self.llm_client:
            try:
                expanded_queries = self.llm_client.expand_query(
                    query, tech_analysis['technologies']
                )
            except Exception as e:
                logger.warning(f"Query expansion failed: {e}")

        # Determine query type
        query_type = 'general'
        if cve_ids:
            query_type = 'cve_lookup'
        elif any(term in query.lower() for term in ['explain', 'how', 'what', 'why']):
            query_type = 'technical'
        elif tech_analysis['technologies']:
            query_type = 'technology_focused'

        return ProcessedQuery(
            original_query=query,
            expanded_queries=expanded_queries,
            detected_entities={
                'cve_ids': cve_ids,
                'technologies': tech_analysis['technologies'],
                'years': year_matches,
                'tech_analysis': tech_analysis
            },
            query_type=query_type,
            suggested_years=[str(y) for y in tech_analysis['critical_years']],
            confidence=0.8 if tech_analysis['technologies'] else 0.5
        )

    def _determine_search_params(
            self,
            processed_query: ProcessedQuery,
            top_k: int,
            years: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Determine optimal search parameters"""

        tech_analysis = processed_query.detected_entities['tech_analysis']
        strategy_info = tech_analysis['search_strategy']

        # Use provided years or suggested years
        search_years = years or processed_query.suggested_years

        # Limit years for performance
        if len(search_years) > 5:
            search_years = search_years[-5:]  # Most recent 5 years

        return {
            'strategy': strategy_info['strategy'],
            'top_k': min(top_k, strategy_info['result_limit']),
            'years': search_years,
            'expand_query': strategy_info['expand_query'],
            'technologies': processed_query.detected_entities['technologies']
        }

    def _execute_enhanced_search(
            self,
            processed_query: ProcessedQuery,
            search_params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute search with enhancements"""

        all_results = []

        # Primary search with original query
        try:
            if search_params['years'] and hasattr(self.rag_system, 'search_cves_by_year'):
                primary_results = self.rag_system.search_cves_by_year(
                    processed_query.original_query,
                    search_params['years'],
                    search_params['top_k']
                )
            else:
                primary_results = self.rag_system.search(
                    processed_query.original_query,
                    search_params['top_k']
                )

            all_results.extend(primary_results)

        except Exception as e:
            logger.warning(f"Primary search failed: {e}")

        # Expanded query search if enabled and we have fewer results
        if (search_params['expand_query'] and
                len(all_results) < search_params['top_k'] and
                len(processed_query.expanded_queries) > 1):

            for expanded_query in processed_query.expanded_queries[1:2]:  # Try 1 expansion
                try:
                    expanded_results = self.rag_system.search(
                        expanded_query,
                        max(5, search_params['top_k'] - len(all_results))
                    )
                    all_results.extend(expanded_results)

                    if len(all_results) >= search_params['top_k']:
                        break

                except Exception as e:
                    logger.warning(f"Expanded search failed for '{expanded_query}': {e}")

        # Remove duplicates and return top results
        unique_results = self._deduplicate_results(all_results)
        return unique_results[:search_params['top_k']]

    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate results based on CVE ID or content similarity"""
        seen_ids = set()
        unique_results = []

        for result in results:
            # Try to get CVE ID from metadata or text
            cve_id = None
            metadata = result.get('metadata', {})
            if 'cve_id' in metadata:
                cve_id = metadata['cve_id']
            else:
                # Try to extract from text
                text = result.get('text', result.get('content', ''))
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', text)
                if cve_match:
                    cve_id = cve_match.group()

            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique_results.append(result)
            elif not cve_id:  # If no CVE ID found, include it
                unique_results.append(result)

        return unique_results

    def _determine_query_type(self, processed_query: ProcessedQuery) -> str:
        """Determine the type of query for LLM prompt selection"""
        query_lower = processed_query.original_query.lower()

        if processed_query.detected_entities['cve_ids']:
            return 'cve_analysis'
        elif any(word in query_lower for word in ['explain', 'how', 'what', 'why', 'describe']):
            return 'technical'
        elif processed_query.detected_entities['technologies']:
            return 'technology_analysis'
        else:
            return 'general'


# Example usage function for testing
def test_llm_integration():
    """Test function to demonstrate LLM integration"""

    # This would be called from your main application
    try:
        from src.generators.rag_system import CVERAGSystem

        # Initialize components
        rag_system = CVERAGSystem()

        # Try to initialize LLM (will gracefully fall back if not available)
        try:
            llm_client = LLMClient()
            print(f"LLM Client status: {'Available' if llm_client.available else 'Unavailable'}")
        except Exception as e:
            print(f"LLM initialization failed: {e}")
            llm_client = None

        # Create enhanced processor
        processor = EnhancedQueryProcessor(rag_system, llm_client)

        # Test queries
        test_queries = [
            "log4j vulnerabilities 2021",
            "CVE-2021-44228",
            "apache web server remote code execution",
            "explain SQL injection attacks"
        ]

        for query in test_queries:
            print(f"\n{'=' * 50}")
            print(f"Testing query: {query}")
            print(f"{'=' * 50}")

            result = processor.process_query(query, top_k=5)

            print(f"Results found: {len(result['search_results'])}")
            print(f"Processing time: {result['metadata'].get('processing_time', 0):.2f}s")

            if result.get('llm_response'):
                print(f"LLM Response: {result['llm_response'][:200]}...")

            print("Top search results:")
            for i, res in enumerate(result['search_results'][:3], 1):
                metadata = res.get('metadata', {})
                print(f"  {i}. {metadata.get('cve_id', 'Unknown')} - Score: {res.get('score', 0):.3f}")

        return processor

    except Exception as e:
        print(f"Test failed: {e}")
        return None


if __name__ == "__main__":
    # Run test if script is executed directly
    test_llm_integration()