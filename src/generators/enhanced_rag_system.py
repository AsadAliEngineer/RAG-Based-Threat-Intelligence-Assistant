# src/generators/enhanced_rag_system.py
"""
Enhanced RAG System with indexing, caching, and MITRE ATT&CK integration
Optimized for large dataset (2002-2025)
"""

import json
import pickle
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum
import hashlib
import os
import re
import threading
import time
from datetime import datetime, timedelta
import logging

# For embeddings (optional - will gracefully degrade if not available)
try:
    from sentence_transformers import SentenceTransformer
    import faiss

    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("Warning: sentence-transformers or faiss not available. Semantic search disabled.")

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


@dataclass
class IndexedDocument:
    """Lightweight document representation for fast retrieval"""
    cve_id: str
    year: int
    severity: str
    cvss_score: float
    keywords: List[str]
    cwe_ids: List[str]
    capec_ids: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    embedding_id: Optional[int] = None


class EnhancedRAGSystem:
    """
    Enhanced RAG system with support for large multi-year dataset (2002-2025)
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_path = config.get('base_path', 'data/knowledge_base')

        # Dynamic year range
        self.start_year = config.get('start_year', 2002)
        self.end_year = config.get('end_year', 2025)
        self.available_years = []

        # Initialize lightweight embedding model if available
        self.use_embeddings = config.get('use_embeddings', False) and EMBEDDINGS_AVAILABLE
        if self.use_embeddings:
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.embedding_dim = 384
                logger.info("Embeddings enabled with all-MiniLM-L6-v2")
            except Exception as e:
                logger.warning(f"Failed to load embedding model: {e}")
                self.use_embeddings = False

        # Indexes for fast lookup
        self.cve_index = {}  # cve_id -> full document
        self.keyword_index = defaultdict(set)  # keyword -> set of cve_ids
        self.year_index = defaultdict(set)  # year -> set of cve_ids
        self.severity_index = defaultdict(set)  # severity -> set of cve_ids
        self.cwe_index = defaultdict(set)  # cwe_id -> set of cve_ids
        self.capec_index = defaultdict(set)  # capec_id -> set of cve_ids
        self.mitre_tactic_index = defaultdict(set)  # tactic -> set of cve_ids
        self.mitre_technique_index = defaultdict(set)  # technique -> set of cve_ids

        # CVE to year mapping for lazy loading
        self.cve_to_year = {}

        # FAISS indexes for each year (if embeddings enabled)
        self.faiss_indexes = {}

        # Query cache with TTL
        self.query_cache = {}
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour default
        self.cache_lock = threading.Lock()

        # Year data cache (from original hybrid system)
        self._year_cache = {}
        self._year_loaded = set()  # Track which years are fully loaded
        self._cache_lock = threading.Lock()
        self.max_cache_size = config.get('max_cache_years', 3)

        # Initialize indexes
        self._build_indexes()

    def search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Main search method - drop-in replacement for hybrid system
        """
        if not query:
            return []

        # Check cache first
        cache_key = self._get_cache_key(query, top_k)
        cached_result = self._get_cached_result(cache_key)
        if cached_result is not None:
            logger.info(f"Cache hit for query: {query}")
            return cached_result

        logger.info(f"Searching for: {query}")

        # Check if it's a CVE ID
        if self._is_cve_id(query):
            results = self._search_exact_cve(query)
            if results:
                self._cache_result(cache_key, results)
                return results

        # Check if it's a MITRE technique/tactic query
        if self._is_mitre_query(query):
            results = self._search_mitre(query, top_k)
            if results:
                self._cache_result(cache_key, results)
                return results

        # Perform multi-strategy search
        results = self._multi_strategy_search(query, top_k)

        # Cache and return results
        self._cache_result(cache_key, results)
        return results

    def _build_indexes(self):
        """Build all indexes for fast retrieval"""
        logger.info("Building enhanced indexes...")

        # First, try to load pre-built indexes
        master_index_paths = [
            os.path.join(self.base_path, 'master_index_full.pkl'),  # From build_indexes.py
            os.path.join(self.base_path, 'master_index.pkl')  # Legacy
        ]

        for index_path in master_index_paths:
            if os.path.exists(index_path):
                logger.info(f"Loading pre-built indexes from {index_path}...")
                if self._load_indexes(index_path):
                    return

        # If no pre-built index, detect available years
        self.available_years = self._detect_available_years()

        if not self.available_years:
            logger.warning("No CVE data files found!")
            return

        logger.info(
            f"Found {len(self.available_years)} years of data: {min(self.available_years)}-{max(self.available_years)}")

        # For initial startup without pre-built index, only index recent years
        if len(self.available_years) > 10:
            logger.warning("Large dataset detected. For faster startup, run 'python scripts/build_indexes.py' first!")
            logger.info("Loading only recent 5 years for now...")

            recent_years = sorted(self.available_years)[-5:]  # Last 5 years
            for year in recent_years:
                self._build_year_index(year)
        else:
            # Small dataset, index everything
            for year in sorted(self.available_years, reverse=True):
                self._build_year_index(year)

        logger.info(f"Indexes built: {len(self.cve_index)} CVEs indexed")

    def _detect_available_years(self) -> List[int]:
        """Dynamically detect available years from data files"""
        years = []

        for year in range(self.start_year, self.end_year + 1):
            file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')
            if os.path.exists(file_path):
                years.append(year)

        return sorted(years)

    def _build_year_index(self, year: int):
        """Build indexes for a specific year"""
        file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')

        if not os.path.exists(file_path):
            logger.warning(f"Data file not found for year {year}")
            return

        logger.info(f"Indexing year {year}...")

        with open(file_path, 'r', encoding='utf-8') as f:
            documents = json.load(f)

        # Initialize FAISS index for this year if embeddings enabled
        if self.use_embeddings and year >= 2020:  # Only recent years for embeddings
            self.faiss_indexes[year] = faiss.IndexFlatIP(self.embedding_dim)
            year_embeddings = []
            year_cve_ids = []

        for doc in documents:
            cve_id = doc.get('id', '') or doc.get('cve_id', '')
            if not cve_id:
                continue

            # Store full document
            self.cve_index[cve_id] = doc
            self.cve_to_year[cve_id] = year

            # Extract all metadata
            keywords = self._extract_keywords(doc)
            cwe_ids = doc.get('cwe_ids', []) or []
            capec_ids = doc.get('capec_ids', []) or []
            mitre_tactics = doc.get('mitre_tactics', []) or []
            mitre_techniques = doc.get('mitre_techniques', []) or []

            # Create indexed document
            indexed_doc = IndexedDocument(
                cve_id=cve_id,
                year=year,
                severity=(doc.get('severity', 'unknown') or 'unknown').lower(),
                cvss_score=float(doc.get('cvss_score', 0.0) or 0.0),
                keywords=keywords,
                cwe_ids=cwe_ids,
                capec_ids=capec_ids,
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques
            )

            # Update all indexes
            self.year_index[year].add(cve_id)
            self.severity_index[indexed_doc.severity].add(cve_id)

            for keyword in keywords:
                self.keyword_index[keyword.lower()].add(cve_id)

            for cwe_id in cwe_ids:
                self.cwe_index[str(cwe_id)].add(cve_id)

            for capec_id in capec_ids:
                self.capec_index[str(capec_id)].add(cve_id)

            for tactic in mitre_tactics:
                self.mitre_tactic_index[tactic.lower()].add(cve_id)

            for technique in mitre_techniques:
                self.mitre_technique_index[technique.lower()].add(cve_id)

            # Generate embedding if enabled and year is recent
            if self.use_embeddings and year >= 2020:
                embedding_text = self._create_embedding_text(doc, keywords)
                try:
                    embedding = self.embedding_model.encode(embedding_text, show_progress_bar=False)
                    year_embeddings.append(embedding)
                    year_cve_ids.append(cve_id)
                except Exception as e:
                    logger.warning(f"Failed to generate embedding for {cve_id}: {e}")

        # Add embeddings to FAISS if available
        if self.use_embeddings and year >= 2020 and year_embeddings:
            try:
                embeddings_array = np.array(year_embeddings).astype('float32')
                faiss.normalize_L2(embeddings_array)
                self.faiss_indexes[year].add(embeddings_array)
                self.faiss_indexes[f"{year}_ids"] = year_cve_ids
                logger.info(f"Added {len(year_embeddings)} embeddings for year {year}")
            except Exception as e:
                logger.warning(f"Failed to build FAISS index for year {year}: {e}")

        # Mark year as loaded
        self._year_loaded.add(year)
        logger.info(f"Indexed {len(documents)} CVEs for year {year}")

    def _load_indexes(self, path: str) -> bool:
        """Load indexes from disk with support for new format"""
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)

            # Check if it's the new format from build_indexes.py
            if 'metadata' in data and 'indexes' in data:
                # New format
                metadata = data['metadata']
                logger.info(f"Loading indexes built on {metadata.get('build_date', 'unknown')}")
                logger.info(f"Index contains {metadata.get('total_cves', 0):,} CVEs")
                logger.info(f"Years available: {metadata.get('years_available', [])}")

                # Load indexes
                indexes = data['indexes']
                self.keyword_index = defaultdict(set, {k: set(v) for k, v in indexes.get('keyword_index', {}).items()})
                self.year_index = defaultdict(set, {int(k): set(v) for k, v in indexes.get('year_index', {}).items()})
                self.severity_index = defaultdict(set,
                                                  {k: set(v) for k, v in indexes.get('severity_index', {}).items()})
                self.cwe_index = defaultdict(set, {k: set(v) for k, v in indexes.get('cwe_index', {}).items()})
                self.capec_index = defaultdict(set, {k: set(v) for k, v in indexes.get('capec_index', {}).items()})
                self.mitre_tactic_index = defaultdict(set, {k: set(v) for k, v in
                                                            indexes.get('mitre_tactic_index', {}).items()})
                self.mitre_technique_index = defaultdict(set, {k: set(v) for k, v in
                                                               indexes.get('mitre_technique_index', {}).items()})

                # Store available years
                self.available_years = metadata.get('years_available', [])

                # Setup CVE to year mapping for lazy loading
                self._setup_lazy_loading(data.get('cve_ids', []))

                logger.info(f"Successfully loaded indexes for {len(self.available_years)} years")
                return True
            else:
                # Legacy format - try to load
                logger.info("Loading legacy index format...")
                return self._load_legacy_indexes(data)

        except Exception as e:
            logger.error(f"Failed to load indexes from {path}: {e}")
            return False

    def _load_legacy_indexes(self, data: Dict) -> bool:
        """Load legacy index format"""
        try:
            # Legacy format has direct index data
            self.keyword_index = defaultdict(set, data.get('keyword_index', {}))
            self.year_index = defaultdict(set, data.get('year_index', {}))
            self.severity_index = defaultdict(set, data.get('severity_index', {}))
            self.cwe_index = defaultdict(set, data.get('cwe_index', {}))
            self.capec_index = defaultdict(set, data.get('capec_index', {}))
            self.mitre_tactic_index = defaultdict(set, data.get('mitre_tactic_index', {}))
            self.mitre_technique_index = defaultdict(set, data.get('mitre_technique_index', {}))

            # Detect available years from year_index
            self.available_years = sorted(self.year_index.keys())

            logger.info(f"Loaded legacy indexes with {len(self.available_years)} years")
            return True
        except Exception as e:
            logger.error(f"Failed to load legacy indexes: {e}")
            return False

    def _setup_lazy_loading(self, cve_ids: List[str]):
        """Setup lazy loading for CVE documents"""
        # Create a mapping of CVE ID to year for efficient loading
        for cve_id in cve_ids:
            # Extract year from CVE ID
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                self.cve_to_year[cve_id] = year

    def _extract_keywords(self, doc: Dict) -> List[str]:
        """Extract keywords from document for indexing"""
        keywords = set()

        # Extract from description and content
        description = (doc.get('description', '') or '').lower()
        content = (doc.get('content', '') or '').lower()

        # Technology keywords
        tech_patterns = [
            'apache', 'nginx', 'iis', 'tomcat', 'docker', 'kubernetes', 'k8s',
            'windows', 'linux', 'ubuntu', 'debian', 'redhat', 'centos', 'macos', 'android', 'ios',
            'chrome', 'firefox', 'edge', 'safari', 'internet explorer',
            'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'oracle',
            'java', 'python', 'php', 'ruby', 'node.js', 'nodejs', 'javascript', 'golang', 'rust',
            'wordpress', 'drupal', 'joomla', 'magento',
            'aws', 'azure', 'gcp', 'google cloud', 'vmware', 'openstack',
            'log4j', 'log4shell', 'spring', 'struts', 'jenkins', 'gitlab', 'github',
            '5g', '4g', 'lte', 'wifi', 'bluetooth', 'zigbee',
            'cisco', 'microsoft', 'adobe', 'apple', 'google', 'oracle', 'ibm', 'sap'
        ]

        for pattern in tech_patterns:
            if pattern in description or pattern in content:
                keywords.add(pattern)

        # Vulnerability types
        vuln_patterns = {
            'rce': ['remote code execution', 'remote command execution', 'arbitrary code'],
            'sqli': ['sql injection', 'sqli'],
            'xss': ['cross-site scripting', 'xss'],
            'xxe': ['xml external entity', 'xxe'],
            'dos': ['denial of service', 'dos', 'ddos'],
            'lfi': ['local file inclusion', 'lfi'],
            'rfi': ['remote file inclusion', 'rfi'],
            'privesc': ['privilege escalation', 'elevation of privilege', 'privesc'],
            'auth_bypass': ['authentication bypass', 'auth bypass'],
            'buffer_overflow': ['buffer overflow', 'stack overflow', 'heap overflow'],
            'path_traversal': ['path traversal', 'directory traversal', '../'],
            'ssrf': ['server-side request forgery', 'ssrf'],
            'csrf': ['cross-site request forgery', 'csrf'],
            'idor': ['insecure direct object reference', 'idor'],
            'deserialization': ['deserialization', 'unserialize', 'pickle']
        }

        for key, patterns in vuln_patterns.items():
            for pattern in patterns:
                if pattern in description or pattern in content:
                    keywords.add(key)

        # Extract from affected products
        affected_products = doc.get('affected_products', [])
        if affected_products:
            for product in affected_products[:10]:  # Limit to prevent explosion
                if product:
                    product_str = str(product).lower()
                    # Extract product name (first significant word)
                    words = product_str.split()
                    for word in words:
                        if len(word) > 2 and word not in ['the', 'and', 'for']:
                            keywords.add(word)
                            break

        return list(keywords)

    def _create_embedding_text(self, doc: Dict, keywords: List[str]) -> str:
        """Create text for embedding generation"""
        parts = [
            doc.get('id', ''),
            doc.get('description', '')[:500],  # Limit length
            ' '.join(keywords[:20]),  # Top keywords
            ' '.join(doc.get('mitre_tactics', [])[:5]),
            ' '.join(doc.get('mitre_techniques', [])[:5])
        ]
        return ' '.join(filter(None, parts))

    def _is_cve_id(self, query: str) -> bool:
        """Check if query is a CVE ID"""
        return bool(re.match(r'^cve-\d{4}-\d{4,}$', query.lower()))

    def _is_mitre_query(self, query: str) -> bool:
        """Check if query is about MITRE ATT&CK"""
        query_lower = query.lower()
        mitre_keywords = ['mitre', 'att&ck', 'attack', 'tactic', 'technique', 't1', 'ta']
        return any(keyword in query_lower for keyword in mitre_keywords)

    def _search_exact_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Fast exact CVE lookup"""
        cve_id_upper = cve_id.upper()

        # Check if CVE is in index
        if cve_id_upper in self.cve_to_year:
            # Load the document if not already loaded
            doc = self._load_cve_document(cve_id_upper)
            if doc:
                return [{
                    'id': cve_id_upper,
                    'content': doc.get('content', ''),
                    'description': doc.get('description', ''),
                    'score': 10.0,
                    'year': doc.get('year', self.cve_to_year.get(cve_id_upper, 0)),
                    'severity': doc.get('severity', 'unknown'),
                    'cvss_score': doc.get('cvss_score', 0.0),
                    'cwe_ids': doc.get('cwe_ids', []),
                    'capec_ids': doc.get('capec_ids', []),
                    'mitre_tactics': doc.get('mitre_tactics', []),
                    'mitre_techniques': doc.get('mitre_techniques', []),
                    'affected_products': doc.get('affected_products', [])[:5],
                    'match_type': 'exact_id'
                }]

        return []

    def _load_cve_document(self, cve_id: str) -> Optional[Dict]:
        """Lazy load a specific CVE document"""
        if cve_id in self.cve_index:
            return self.cve_index[cve_id]

        # Find the year
        year = self.cve_to_year.get(cve_id)
        if not year:
            # Try to extract from CVE ID
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))

        if year and year in self.available_years:
            # Ensure year is loaded
            if year not in self._year_loaded:
                self._ensure_year_loaded(year)

            return self.cve_index.get(cve_id)

        return None

    def _ensure_year_loaded(self, year: int):
        """Ensure year data is loaded"""
        if year in self._year_loaded:
            return

        file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    documents = json.load(f)

                # Load documents into cve_index
                for doc in documents:
                    cve_id = doc.get('id', '') or doc.get('cve_id', '')
                    if cve_id:
                        self.cve_index[cve_id] = doc

                self._year_loaded.add(year)
                logger.info(f"Lazy loaded {len(documents)} CVEs for year {year}")

                # Manage cache size
                with self._cache_lock:
                    if len(self._year_loaded) > self.max_cache_size:
                        # Remove oldest loaded year
                        oldest_year = min(self._year_loaded)
                        # Remove CVEs from that year from memory
                        for cve_id in list(self.year_index.get(oldest_year, [])):
                            if cve_id in self.cve_index:
                                del self.cve_index[cve_id]
                        self._year_loaded.remove(oldest_year)
                        logger.info(f"Evicted year {oldest_year} from memory")

            except Exception as e:
                logger.error(f"Failed to load year {year}: {e}")

    def _search_mitre(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Search for MITRE ATT&CK related vulnerabilities"""
        query_lower = query.lower()
        matched_cves = set()

        # Search in tactics
        for tactic, cve_ids in self.mitre_tactic_index.items():
            if tactic in query_lower or query_lower in tactic:
                matched_cves.update(cve_ids)

        # Search in techniques
        for technique, cve_ids in self.mitre_technique_index.items():
            if technique in query_lower or query_lower in technique:
                matched_cves.update(cve_ids)

        # Score and format results
        results = []
        for cve_id in matched_cves:
            doc = self._load_cve_document(cve_id)
            if doc:
                score = self._calculate_mitre_relevance(doc, query_lower)
                results.append(self._format_result(doc, score, 'mitre_search'))

        # Sort by score and return top_k
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_k]

    def _multi_strategy_search(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """
        Multi-strategy search combining keyword, index, and optional semantic search
        """
        query_lower = query.lower()
        query_words = query_lower.split()

        # Strategy 1: Keyword index search
        keyword_results = self._search_by_keywords(query_words, top_k * 2)

        # Strategy 2: Full-text search in descriptions
        text_results = self._search_in_text(query_lower, top_k * 2)

        # Strategy 3: Semantic search (if available and query is complex)
        semantic_results = []
        if self.use_embeddings and len(query_words) > 2:
            semantic_results = self._search_semantic(query, top_k)

        # Merge and deduplicate results
        all_results = self._merge_search_results(
            keyword_results,
            text_results,
            semantic_results,
            top_k
        )

        return all_results

    def _search_by_keywords(self, query_words: List[str], limit: int) -> List[Tuple[str, float]]:
        """Fast keyword-based search using inverted index"""
        cve_scores = defaultdict(float)

        for word in query_words:
            word_lower = word.lower()

            # Direct keyword match
            if word_lower in self.keyword_index:
                for cve_id in self.keyword_index[word_lower]:
                    cve_scores[cve_id] += 3.0

            # Partial matches (only for words longer than 3 chars)
            if len(word_lower) > 3:
                for keyword, cve_ids in self.keyword_index.items():
                    if word_lower in keyword or keyword in word_lower:
                        for cve_id in cve_ids:
                            cve_scores[cve_id] += 1.0

        # Convert to list and sort
        results = [(cve_id, score) for cve_id, score in cve_scores.items()]
        results.sort(key=lambda x: x[1], reverse=True)

        return results[:limit]

    def _search_in_text(self, query: str, limit: int) -> List[Tuple[str, float]]:
        """Search in CVE descriptions and content"""
        results = []

        # Use available years, search newest first
        search_years = sorted(self.available_years, reverse=True) if self.available_years else []

        # For performance with 23 years, limit initial search
        if len(search_years) > 10:
            # Search recent 10 years first
            search_years = search_years[:10]
            logger.debug(f"Searching in recent {len(search_years)} years for performance")

        for year in search_years:
            if year not in self.year_index:
                continue

            # For old years, only search if we have good keyword matches
            if year < 2015 and not any(word in self.keyword_index for word in query.split()):
                continue

            # Ensure year data is loaded
            if year not in self._year_loaded:
                self._ensure_year_loaded(year)

            for cve_id in self.year_index[year]:
                doc = self.cve_index.get(cve_id)
                if not doc:
                    continue

                description = (doc.get('description', '') or '').lower()
                content = (doc.get('content', '') or '').lower()

                score = 0.0

                # Check for query in text
                if query in description:
                    score += 5.0
                    score += description.count(query) * 0.5
                elif query in content:
                    score += 2.0
                    score += content.count(query) * 0.2

                if score > 0:
                    # Boost by severity and recency
                    if doc.get('severity', '').lower() in ['critical', 'high']:
                        score *= 1.3
                    if year >= 2020:
                        score *= 1.2

                    results.append((cve_id, score))

            # Early termination if we have enough good results
            if len(results) >= limit and any(score > 5.0 for _, score in results[:limit]):
                break

        # Sort and limit
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    def _search_semantic(self, query: str, top_k: int) -> List[Tuple[str, float]]:
        """Semantic search using FAISS (if available)"""
        if not self.use_embeddings:
            return []

        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode(query, show_progress_bar=False)
            query_embedding = query_embedding.reshape(1, -1).astype('float32')
            faiss.normalize_L2(query_embedding)

            all_results = []

            # Search only recent years with FAISS indexes
            recent_years = [y for y in sorted(self.faiss_indexes.keys(), reverse=True) if isinstance(y, int)]

            for year in recent_years[:5]:  # Limit to recent 5 years
                if f"{year}_ids" not in self.faiss_indexes:
                    continue

                index = self.faiss_indexes[year]
                cve_ids = self.faiss_indexes[f"{year}_ids"]

                if index.ntotal == 0:
                    continue

                # Search
                k_year = min(top_k, index.ntotal)
                distances, indices = index.search(query_embedding, k_year)

                # Convert to results
                for i, idx in enumerate(indices[0]):
                    if 0 <= idx < len(cve_ids):
                        cve_id = cve_ids[idx]
                        score = float(distances[0][i]) * 5.0  # Scale similarity score
                        all_results.append((cve_id, score))

            # Sort by score
            all_results.sort(key=lambda x: x[1], reverse=True)
            return all_results[:top_k]

        except Exception as e:
            logger.warning(f"Semantic search failed: {e}")
            return []

    def _merge_search_results(self,
                              keyword_results: List[Tuple[str, float]],
                              text_results: List[Tuple[str, float]],
                              semantic_results: List[Tuple[str, float]],
                              top_k: int) -> List[Dict[str, Any]]:
        """Merge results from different search strategies"""
        # Combine scores for same CVEs
        combined_scores = defaultdict(float)

        # Add keyword results (highest weight)
        for cve_id, score in keyword_results:
            combined_scores[cve_id] += score * 1.0

        # Add text search results
        for cve_id, score in text_results:
            combined_scores[cve_id] += score * 0.8

        # Add semantic results (if available)
        for cve_id, score in semantic_results:
            combined_scores[cve_id] += score * 0.6

        # Sort by combined score
        sorted_results = sorted(combined_scores.items(), key=lambda x: x[1], reverse=True)

        # Format top results
        final_results = []
        for cve_id, score in sorted_results[:top_k]:
            doc = self._load_cve_document(cve_id)
            if doc:
                final_results.append(self._format_result(doc, score, 'multi_strategy'))

        return final_results

    def _format_result(self, doc: Dict, score: float, match_type: str) -> Dict[str, Any]:
        """Format a document into a search result"""
        cve_id = doc.get('id', '') or doc.get('cve_id', '')

        return {
            'id': cve_id,
            'score': round(score, 2),
            'year': doc.get('year', self._extract_year_from_cve(cve_id)),
            'severity': doc.get('severity', 'unknown'),
            'cvss_score': doc.get('cvss_score', 0.0),
            'description': doc.get('description', '')[:300],
            'content': doc.get('content', '')[:500],
            'cwe_ids': doc.get('cwe_ids', []),
            'capec_ids': doc.get('capec_ids', []),
            'mitre_tactics': doc.get('mitre_tactics', []),
            'mitre_techniques': doc.get('mitre_techniques', []),
            'affected_products': doc.get('affected_products', [])[:5],
            'match_type': match_type
        }

    def _calculate_mitre_relevance(self, doc: Dict, query: str) -> float:
        """Calculate relevance score for MITRE queries"""
        score = 0.0

        # Check tactics
        for tactic in doc.get('mitre_tactics', []):
            if query in tactic.lower() or tactic.lower() in query:
                score += 3.0

        # Check techniques
        for technique in doc.get('mitre_techniques', []):
            if query in technique.lower() or technique.lower() in query:
                score += 5.0

        # Boost by severity
        severity = (doc.get('severity', '') or '').lower()
        if severity == 'critical':
            score *= 1.5
        elif severity == 'high':
            score *= 1.3

        return score

    def _extract_year_from_cve(self, cve_id: str) -> int:
        """Extract year from CVE ID"""
        match = re.search(r'CVE-(\d{4})-', cve_id)
        if match:
            return int(match.group(1))
        return 0

    # Cache management methods
    def _get_cache_key(self, query: str, top_k: int) -> str:
        """Generate cache key"""
        return f"{query}:{top_k}"

    def _get_cached_result(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get result from cache if valid"""
        with self.cache_lock:
            if cache_key in self.query_cache:
                cached_data = self.query_cache[cache_key]
                if time.time() - cached_data['timestamp'] < self.cache_ttl:
                    return cached_data['results']
                else:
                    del self.query_cache[cache_key]
        return None

    def _cache_result(self, cache_key: str, results: List[Dict[str, Any]]):
        """Cache search results"""
        with self.cache_lock:
            self.query_cache[cache_key] = {
                'results': results,
                'timestamp': time.time()
            }

            # Limit cache size
            if len(self.query_cache) > 1000:
                # Remove oldest entries
                sorted_keys = sorted(
                    self.query_cache.keys(),
                    key=lambda k: self.query_cache[k]['timestamp']
                )
                for key in sorted_keys[:100]:
                    del self.query_cache[key]

    def _is_index_fresh(self, index_path: str, max_age_days: int = 7) -> bool:
        """Check if index is recent enough"""
        if not os.path.exists(index_path):
            return False

        file_age = time.time() - os.path.getmtime(index_path)
        return file_age < (max_age_days * 24 * 3600)

    def _save_indexes(self, path: str):
        """Save indexes to disk"""
        try:
            index_data = {
                'keyword_index': dict(self.keyword_index),
                'year_index': dict(self.year_index),
                'severity_index': dict(self.severity_index),
                'cwe_index': dict(self.cwe_index),
                'capec_index': dict(self.capec_index),
                'mitre_tactic_index': dict(self.mitre_tactic_index),
                'mitre_technique_index': dict(self.mitre_technique_index),
                'cve_ids': list(self.cve_to_year.keys()),
                'timestamp': time.time()
            }

            with open(path, 'wb') as f:
                pickle.dump(index_data, f)

            logger.info(f"Saved indexes to {path}")
        except Exception as e:
            logger.error(f"Failed to save indexes: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        total_cves = len(set().union(*self.year_index.values())) if self.year_index else 0

        return {
            'total_cves_indexed': total_cves,
            'keywords_indexed': len(self.keyword_index),
            'cwe_relationships': len(self.cwe_index),
            'capec_relationships': len(self.capec_index),
            'mitre_tactics': len(self.mitre_tactic_index),
            'mitre_techniques': len(self.mitre_technique_index),
            'years_available': sorted(self.available_years) if self.available_years else [],
            'year_range': f"{min(self.available_years)}-{max(self.available_years)}" if self.available_years else "N/A",
            'cache_size': len(self.query_cache),
            'embeddings_enabled': self.use_embeddings,
            'index_loaded': bool(self.year_index),
            'cached_years': list(self._year_loaded),
            'available_years': self.available_years
        }

    # Backward compatibility methods
    def search_cves(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Alias for search() - backward compatibility"""
        return self.search(query, top_k)

    def _load_year_data(self, year: int) -> List[Dict[str, Any]]:
        """Load year data - backward compatibility with hybrid system"""
        self._ensure_year_loaded(year)

        # Return documents for the year
        docs = []
        for cve_id in self.year_index.get(year, []):
            if cve_id in self.cve_index:
                docs.append(self.cve_index[cve_id])

        return docs