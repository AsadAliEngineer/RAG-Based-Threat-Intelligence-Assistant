# src/generators/rag_system_hybrid.py
"""
Hybrid RAG System that uses intelligent query routing for optimal performance
"""

import json
import re
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import chromadb
from chromadb.config import Settings
from concurrent.futures import ThreadPoolExecutor
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SearchStrategy(Enum):
    EXACT_ID = "exact_id"
    YEAR_BASED = "year_based"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


@dataclass
class SearchContext:
    query: str
    strategy: SearchStrategy
    year: Optional[int] = None
    is_cve_id: bool = False


class HybridRAGSystem:
    """
    Optimized RAG system using hybrid search strategies
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_path = config.get('base_path', 'data/knowledge_base')
        self.vector_db_path = os.path.join(self.base_path, 'vector_db')

        # Lazy loading for vector DB
        self._vector_client = None
        self._vector_collection = None
        self._vector_loaded = False
        self._vector_lock = threading.Lock()

        # Cache for year-based data
        self._year_cache = {}
        self._cache_lock = threading.Lock()
        self.max_cache_size = config.get('max_cache_years', 2)

        # Fast CVE ID index for exact matches
        self._cve_index = {}
        self._index_loaded = False
        self._index_lock = threading.Lock()

        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=4)

        # Build fast CVE index
        self._build_cve_index()

        logger.info("HybridRAGSystem initialized")

    def _build_cve_index(self):
        """Build fast CVE ID index for exact matches"""
        if self._index_loaded:
            return

        with self._index_lock:
            if self._index_loaded:  # Double-check
                return

            logger.info("Building fast CVE ID index...")
            
            for year in [2021, 2022, 2023, 2024]:
                file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')
                if not os.path.exists(file_path):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    # Index CVE IDs for fast lookup
                    for doc in data:
                        cve_id = doc.get('id', '') or doc.get('cve_id', '')
                        if cve_id:
                            self._cve_index[cve_id.upper()] = {
                                'doc': doc,
                                'year': year,
                                'file_path': file_path
                            }

                    logger.info(f"Indexed {len(data)} CVEs from year {year}")

                except Exception as e:
                    logger.error(f"Error indexing year {year}: {e}")

            self._index_loaded = True
            logger.info(f"Fast CVE index built with {len(self._cve_index)} entries")

    def search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Main search method with intelligent routing
        """
        if not query:
            return []

        logger.info(f"Searching for: {query}")

        # Analyze query to determine search strategy
        context = self._analyze_query(query)
        logger.info(f"Search strategy: {context.strategy}")

        # Route to appropriate search method
        if context.strategy == SearchStrategy.EXACT_ID:
            results = self._search_exact_cve_id(context, top_k)
        elif context.strategy == SearchStrategy.YEAR_BASED:
            results = self._search_year_based(context, top_k)
        elif context.strategy == SearchStrategy.SEMANTIC:
            results = self._search_semantic(context, top_k)
        else:  # HYBRID
            results = self._search_hybrid(context, top_k)

        logger.info(f"Found {len(results)} results")
        return results

    def _analyze_query(self, query: str) -> SearchContext:
        """
        Analyze query to determine optimal search strategy
        """
        query_lower = query.lower()

        # Check if it's a CVE ID
        cve_pattern = re.compile(r'^cve-(\d{4})-\d{4,}$', re.IGNORECASE)
        cve_match = cve_pattern.match(query)

        if cve_match:
            # Extract year from CVE ID
            year = int(cve_match.group(1))
            return SearchContext(
                query=query,
                strategy=SearchStrategy.EXACT_ID,
                year=year,
                is_cve_id=True
            )

        # Keywords that indicate complex/semantic search needed
        semantic_indicators = [
            'related', 'vulnerabilities', 'similar', 'about',
            'regarding', 'concerning', 'associated', 'affecting'
        ]

        # Technology/product keywords that benefit from semantic search
        tech_keywords = [
            '5g', 'log4j', 'log4shell', 'windows', 'linux', 'apache', 'microsoft',
            'oracle', 'java', 'python', 'docker', 'kubernetes', 'cloud',
            'remote code', 'rce', 'sql injection', 'xss', 'csrf'
        ]

        # Check if query needs semantic understanding
        needs_semantic = False

        # Check for semantic indicators
        for indicator in semantic_indicators:
            if indicator in query_lower:
                needs_semantic = True
                break

        # Check for technology keywords with context
        for tech in tech_keywords:
            if tech in query_lower:
                needs_semantic = True
                break

        # Check if query contains year
        year_match = re.search(r'\b(202[1-4])\b', query)
        if year_match:
            return SearchContext(
                query=query,
                strategy=SearchStrategy.HYBRID if needs_semantic else SearchStrategy.YEAR_BASED,
                year=int(year_match.group(1))
            )

        # Decide strategy
        if needs_semantic:
            return SearchContext(
                query=query,
                strategy=SearchStrategy.HYBRID
            )

        # Default to year-based for simple queries
        return SearchContext(
            query=query,
            strategy=SearchStrategy.YEAR_BASED
        )

    def _search_exact_cve_id(self, context: SearchContext, top_k: int) -> List[Dict[str, Any]]:
        """
        Fast exact CVE ID search using pre-built index
        """
        query_upper = context.query.upper()
        
        # Check fast index first
        if query_upper in self._cve_index:
            index_entry = self._cve_index[query_upper]
            doc = index_entry['doc']
            year = index_entry['year']
            
            return [{
                'id': query_upper,
                'content': doc.get('content', ''),
                'description': doc.get('description', ''),
                'score': 10.0,
                'year': year,
                'match_type': 'exact_id',
                'severity': doc.get('severity', 'unknown'),
                'cvss_score': doc.get('cvss_score', 0.0)
            }]

        # Fallback to year-based search if not in index
        logger.warning(f"Exact match not found for {context.query}, falling back to year-based search")
        return self._search_year_based(context, top_k)

    def _search_year_based(self, context: SearchContext, top_k: int) -> List[Dict[str, Any]]:
        """
        Search within year-based JSON files
        """
        results = []
        query_lower = context.query.lower()

        # Determine which years to search
        if context.year:
            years = [context.year]
        else:
            # Search all years, newest first
            years = [2024, 2023, 2022, 2021]

        for year in years:
            year_data = self._load_year_data(year)
            if not year_data:
                continue

            year_results = self._search_in_documents(
                documents=year_data,
                query=query_lower,
                year=year,
                top_k=top_k * 2  # Get more results per year, filter later
            )

            results.extend(year_results)

            # Early termination if we have enough high-quality results
            if len(results) >= top_k * 2 and any(r['score'] > 5.0 for r in results[:top_k]):
                break

        # Sort by score and return top_k
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def _search_semantic(self, context: SearchContext, top_k: int) -> List[Dict[str, Any]]:
        """
        Semantic search using vector database (lazy loaded)
        """
        # For now, fallback to year-based search
        # This is where vector search would go if enabled
        logger.info("Semantic search requested, using enhanced year-based search")
        return self._search_year_based(context, top_k)

    def _search_hybrid(self, context: SearchContext, top_k: int) -> List[Dict[str, Any]]:
        """
        Hybrid search combining year-based and enhanced matching
        """
        # For now, use enhanced year-based search
        # This provides good results without vector DB complexity
        return self._search_technology_vulnerabilities(context.query, top_k)

    def _search_technology_vulnerabilities(self, query: str, top_k: int = 20) -> List[Dict[str, Any]]:
        """
        Specialized search for technology-related vulnerabilities
        """
        results = []
        query_lower = query.lower()

        # Extract key terms from query
        tech_terms = []
        vuln_types = []

        # Common vulnerability types
        vuln_patterns = {
            'rce': ['remote code execution', 'remote command execution'],
            'sqli': ['sql injection', 'sqli'],
            'xss': ['cross-site scripting', 'xss'],
            'xxe': ['xml external entity', 'xxe'],
            'lfi': ['local file inclusion', 'lfi'],
            'rfi': ['remote file inclusion', 'rfi']
        }

        # Extract technology terms (remove common words)
        common_words = {'what', 'are', 'the', 'related', 'vulnerabilities', 'cve', 'for', 'in', 'of'}
        words = query_lower.split()
        tech_terms = [w for w in words if w not in common_words and len(w) > 2]

        # Check for vulnerability type patterns
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in query_lower:
                    vuln_types.append(vuln_type)
                    break

        # Search all years
        for year in [2024, 2023, 2022, 2021]:
            year_data = self._load_year_data(year)
            if not year_data:
                continue

            year_results = []

            for doc in year_data:
                score = 0.0

                # Get all searchable fields
                cve_id = doc.get('id', '') or doc.get('cve_id', '')
                description = (doc.get('description', '') or '').lower()
                content = (doc.get('content', '') or '').lower()
                affected_products = doc.get('affected_products', [])

                # Score based on technology terms
                for term in tech_terms:
                    # Check affected products (highest priority)
                    if affected_products:
                        affected_str = ' '.join(str(p).lower() for p in affected_products)
                        if term in affected_str:
                            score += 5.0

                    # Check in description
                    if term in description:
                        score += 3.0
                        # Boost if appears multiple times
                        score += min(description.count(term) * 0.5, 2.0)

                    # Check in content
                    if term in content:
                        score += 1.0
                        # Boost based on frequency
                        score += min(content.count(term) * 0.2, 1.0)

                # Score based on vulnerability types
                for vuln_type in vuln_types:
                    for pattern in vuln_patterns.get(vuln_type, []):
                        if pattern in description or pattern in content:
                            score += 2.0
                            break

                # Additional scoring factors
                if score > 0:
                    # Boost recent vulnerabilities
                    if year >= 2023:
                        score *= 1.2

                    # Boost high severity
                    severity = (doc.get('severity', '') or '').lower()
                    if severity in ['critical', 'high']:
                        score *= 1.5
                    elif severity == 'medium':
                        score *= 1.1

                    # Add result
                    year_results.append({
                        'id': cve_id,
                        'content': content[:500],
                        'description': description[:300],
                        'score': score,
                        'year': year,
                        'severity': severity,
                        'cvss_score': doc.get('cvss_score', 0.0),
                        'affected_products': affected_products[:5] if affected_products else [],
                        'match_type': 'technology_search'
                    })

            # Sort year results by score
            year_results.sort(key=lambda x: x['score'], reverse=True)

            # Take top results from this year
            results.extend(year_results[:max(10, top_k // 4)])

        # Final sort and limit
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def _search_in_documents(self, documents: List[Dict], query: str, year: int, top_k: int) -> List[Dict]:
        """
        Search within a list of documents
        """
        results = []

        for doc in documents:
            score = 0.0

            # Get document fields
            doc_id = doc.get('id', '') or doc.get('cve_id', '')
            content = doc.get('content', '') or ''
            description = doc.get('description', '') or ''

            # Combine searchable text
            full_text = f"{doc_id} {content} {description}".lower()

            # Check if query appears in document
            if query not in full_text:
                continue

            # Calculate relevance score
            if query in doc_id.lower():
                score = 5.0  # High score for ID match
            else:
                # Calculate TF-IDF-like score
                count = full_text.count(query)
                doc_length = len(full_text.split())
                if doc_length > 0:
                    score = 1.0 + (count / doc_length * 100)

                # Boost if in description
                if query in description.lower():
                    score *= 1.5

                # Boost if query appears at the beginning
                if full_text[:200].count(query) > 0:
                    score *= 1.2

            if score > 0:
                results.append({
                    'id': doc_id,
                    'content': content[:500],  # Truncate for response
                    'description': description[:300],
                    'score': score,
                    'year': year,
                    'severity': doc.get('severity', 'unknown'),
                    'cvss_score': doc.get('cvss_score', 0.0),
                    'match_type': 'text_match'
                })

        return results

    def _load_year_data(self, year: int) -> List[Dict[str, Any]]:
        """
        Load year-based data with caching
        """
        # Check cache first
        with self._cache_lock:
            if year in self._year_cache:
                logger.info(f"Using cached data for year {year}")
                return self._year_cache[year]

        file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')

        try:
            logger.info(f"Loading data for year {year} from {file_path}")
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Cache the data
            with self._cache_lock:
                # Implement simple LRU by removing oldest if cache is full
                if len(self._year_cache) >= self.max_cache_size:
                    # Remove the oldest cached year
                    oldest_year = min(self._year_cache.keys())
                    del self._year_cache[oldest_year]
                    logger.info(f"Evicted year {oldest_year} from cache")

                self._year_cache[year] = data
                logger.info(f"Cached {len(data)} documents for year {year}")

            return data

        except Exception as e:
            logger.error(f"Error loading year {year} data: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """
        Get system statistics without loading vector DB
        """
        stats = {
            'year_cache_size': len(self._year_cache),
            'cached_years': list(self._year_cache.keys()),
            'vector_db_loaded': self._vector_loaded,
            'available_years': [],
            'total_documents_cached': sum(len(docs) for docs in self._year_cache.values())
        }

        # Check available year files
        for year in [2021, 2022, 2023, 2024]:
            file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')
            if os.path.exists(file_path):
                stats['available_years'].append(year)

        return stats

    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)