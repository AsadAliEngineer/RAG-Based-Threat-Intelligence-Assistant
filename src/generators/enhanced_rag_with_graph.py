#!/usr/bin/env python3
"""
Enhanced RAG System with Knowledge Graph Features
Combines semantic search with graph-based scoring for improved retrieval performance.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import logging
import numpy as np
from datetime import datetime

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GraphEnhancedRAG:
    """RAG system enhanced with knowledge graph features"""

    def __init__(self):
        self.config = Config()
        self.knowledge_base_dir = self.config.knowledge_base_dir
        self.networkx_dir = self.knowledge_base_dir / 'networkx_graph'

        # Initialize components
        self.embedding_model = None
        self.chroma_client = None
        self.collection = None

        # Load graph features
        self.graph_features = self._load_graph_features()
        self.similarity_matrix = self._load_similarity_matrix()

        # Performance tracking
        self.query_stats = {
            'total_queries': 0,
            'avg_response_time': 0.0,
            'semantic_only_queries': 0,
            'graph_enhanced_queries': 0
        }

    def _load_graph_features(self) -> Dict[str, Any]:
        """Load graph features exported by NetworkX builder"""
        try:
            graph_features_file = self.networkx_dir / "graph_features.json"
            if graph_features_file.exists():
                with open(graph_features_file, 'r', encoding='utf-8') as f:
                    features = json.load(f)
                logger.info("✅ Loaded graph features")
                return features
            else:
                logger.warning("Graph features not found. Run networkx_graph_builder.py first.")
                return {}
        except Exception as e:
            logger.error(f"Error loading graph features: {e}")
            return {}

    def _load_similarity_matrix(self) -> Dict[str, Any]:
        """Load precomputed similarity matrix"""
        try:
            similarity_file = self.networkx_dir / "similarity_matrix.json"
            if similarity_file.exists():
                with open(similarity_file, 'r', encoding='utf-8') as f:
                    matrix = json.load(f)
                logger.info("✅ Loaded similarity matrix")
                return matrix
            else:
                logger.warning("Similarity matrix not found. Graph features will be limited.")
                return {}
        except Exception as e:
            logger.error(f"Error loading similarity matrix: {e}")
            return {}

    def initialize_components(self):
        """Initialize embedding model and vector database"""
        try:
            # Initialize embedding model
            from sentence_transformers import SentenceTransformer
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("✅ Embedding model loaded")

            # Initialize ChromaDB
            import chromadb
            db_path = self.knowledge_base_dir / "vector_db"
            self.chroma_client = chromadb.PersistentClient(path=str(db_path))

            try:
                self.collection = self.chroma_client.get_collection("cve_collection")
                logger.info("✅ Connected to existing vector database")
            except Exception:
                logger.warning("Vector database not found. Please run RAG system builder first.")
                self.collection = None

        except ImportError as e:
            logger.error(f"Required packages not installed: {e}")
            logger.error("Please install: pip install sentence-transformers chromadb")
            raise

    def hybrid_search(self,
                      query: str,
                      top_k: int = 10,
                      alpha: float = 0.7,
                      use_graph_features: bool = True) -> List[Dict[str, Any]]:
        """
        Perform hybrid search combining semantic search with graph-based scoring

        Args:
            query: Search query
            top_k: Number of results to return
            alpha: Weight for semantic score vs graph score (0.0 = all graph, 1.0 = all semantic)
            use_graph_features: Whether to use graph-based enhancement

        Returns:
            List of enhanced search results
        """
        start_time = datetime.now()

        if not self.collection:
            logger.error("Vector database not available")
            return []

        try:
            # 1. Standard semantic search with expanded candidate set
            candidate_multiplier = 3 if use_graph_features else 1
            semantic_results = self.collection.query(
                query_texts=[query],
                n_results=min(top_k * candidate_multiplier, 100),  # Get more candidates for reranking
                include=['documents', 'metadatas', 'distances']
            )

            if not semantic_results['ids'] or not semantic_results['ids'][0]:
                logger.warning("No semantic search results found")
                return []

            # 2. Process and enhance results
            enhanced_results = []

            for i, cve_id in enumerate(semantic_results['ids'][0]):
                # Get base semantic score (convert distance to similarity)
                semantic_distance = semantic_results['distances'][0][i]
                semantic_score = max(0.0, 1.0 - semantic_distance)  # Convert distance to similarity

                result = {
                    'cve_id': cve_id,
                    'document': semantic_results['documents'][0][i],
                    'metadata': semantic_results['metadatas'][0][i] if semantic_results['metadatas'] else {},
                    'semantic_score': semantic_score,
                    'semantic_distance': semantic_distance,
                    'final_score': semantic_score  # Default to semantic score
                }

                # 3. Apply graph-based enhancements
                if use_graph_features and self.graph_features:
                    graph_score = self._calculate_graph_score(cve_id, query)
                    similarity_boost = self._calculate_similarity_boost(cve_id)

                    # Combined score with weighted factors
                    final_score = (alpha * semantic_score +
                                   (1 - alpha) * graph_score +
                                   similarity_boost)

                    result.update({
                        'graph_score': graph_score,
                        'similarity_boost': similarity_boost,
                        'final_score': final_score,
                        'similar_cves': self._get_similar_cves(cve_id),
                        'importance_score': self.graph_features.get('node_importance', {}).get(cve_id, 0.0),
                        'cluster_info': self._get_cluster_info(cve_id)
                    })

                    self.query_stats['graph_enhanced_queries'] += 1
                else:
                    self.query_stats['semantic_only_queries'] += 1

                enhanced_results.append(result)

            # 4. Sort by final score and return top-k
            enhanced_results.sort(key=lambda x: x['final_score'], reverse=True)
            final_results = enhanced_results[:top_k]

            # 5. Update performance stats
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            self._update_query_stats(response_time)

            logger.info(f"Hybrid search completed in {response_time:.3f}s, returned {len(final_results)} results")
            return final_results

        except Exception as e:
            logger.error(f"Error in hybrid search: {e}")
            return []

    def _calculate_graph_score(self, cve_id: str, query: str) -> float:
        """Calculate graph-based score for a CVE"""
        if not self.graph_features:
            return 0.0

        score = 0.0

        # Importance score (PageRank)
        importance = self.graph_features.get('node_importance', {}).get(cve_id, 0.0)
        score += importance * 0.5

        # Centrality score (if available)
        if 'betweenness_centrality' in self.graph_features:
            centrality = self.graph_features['betweenness_centrality'].get(cve_id, 0.0)
            score += centrality * 0.3

        # Cluster relevance (boost if in a large cluster)
        cluster_info = self._get_cluster_info(cve_id)
        if cluster_info:
            cluster_boost = min(0.2, len(cluster_info) / 1000)  # Normalize cluster size
            score += cluster_boost

        return min(1.0, score)  # Normalize to [0, 1]

    def _calculate_similarity_boost(self, cve_id: str) -> float:
        """Calculate boost based on similarity to other important CVEs"""
        if not self.similarity_matrix or cve_id not in self.similarity_matrix:
            return 0.0

        similar_cves = self.similarity_matrix[cve_id].get('similar_cves', [])
        if not similar_cves:
            return 0.0

        # Boost based on number and quality of similar CVEs
        boost = 0.0
        for similar_cve, similarity_score in similar_cves[:5]:  # Top 5 similar
            if similarity_score > 0.3:  # Only consider reasonably similar CVEs
                boost += similarity_score * 0.02  # Small boost per similar CVE

        return min(0.1, boost)  # Cap the boost

    def _get_similar_cves(self, cve_id: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Get similar CVEs for a given CVE"""
        if not self.similarity_matrix or cve_id not in self.similarity_matrix:
            return []

        similar_cves = self.similarity_matrix[cve_id].get('similar_cves', [])
        return similar_cves[:top_k]

    def _get_cluster_info(self, cve_id: str) -> List[str]:
        """Get cluster information for a CVE"""
        if not self.graph_features or 'vulnerability_clusters' not in self.graph_features:
            return []

        clusters = self.graph_features['vulnerability_clusters']
        for cluster_name, cve_list in clusters.items():
            if cve_id in cve_list:
                return cve_list
        return []

    def _update_query_stats(self, response_time: float):
        """Update query performance statistics"""
        self.query_stats['total_queries'] += 1

        # Update rolling average response time
        total = self.query_stats['total_queries']
        current_avg = self.query_stats['avg_response_time']
        self.query_stats['avg_response_time'] = ((current_avg * (total - 1)) + response_time) / total

    def find_related_vulnerabilities(self, cve_id: str, relation_types: List[str] = None) -> Dict[str, List[str]]:
        """
        Find vulnerabilities related to a given CVE through various relationship types

        Args:
            cve_id: Target CVE ID
            relation_types: Types of relationships to consider ['similar', 'same_cwe', 'same_product']

        Returns:
            Dictionary of relationship types to lists of related CVEs
        """
        if relation_types is None:
            relation_types = ['similar', 'same_cluster']

        related = {}

        # Similar vulnerabilities
        if 'similar' in relation_types:
            similar_cves = self._get_similar_cves(cve_id, top_k=10)
            related['similar'] = [cve for cve, score in similar_cves if score > 0.3]

        # Same cluster vulnerabilities
        if 'same_cluster' in relation_types:
            cluster_cves = self._get_cluster_info(cve_id)
            related['same_cluster'] = [cve for cve in cluster_cves if cve != cve_id][:20]

        return related

    def get_vulnerability_trends(self, cve_list: List[str]) -> Dict[str, Any]:
        """Analyze trends in a list of vulnerabilities"""
        if not cve_list or not self.graph_features:
            return {}

        trends = {
            'total_cves': len(cve_list),
            'avg_importance': 0.0,
            'severity_distribution': {},
            'common_clusters': [],
            'temporal_distribution': {}
        }

        # Calculate average importance
        importance_scores = []
        for cve_id in cve_list:
            score = self.graph_features.get('node_importance', {}).get(cve_id, 0.0)
            importance_scores.append(score)

        if importance_scores:
            trends['avg_importance'] = np.mean(importance_scores)

        # Find common clusters
        cluster_counts = {}
        for cve_id in cve_list:
            cluster_info = self._get_cluster_info(cve_id)
            if cluster_info:
                for cluster_name in self.graph_features['vulnerability_clusters']:
                    if cve_id in self.graph_features['vulnerability_clusters'][cluster_name]:
                        cluster_counts[cluster_name] = cluster_counts.get(cluster_name, 0) + 1

        # Sort clusters by frequency
        sorted_clusters = sorted(cluster_counts.items(), key=lambda x: x[1], reverse=True)
        trends['common_clusters'] = sorted_clusters[:5]

        return trends

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get system performance statistics"""
        stats = self.query_stats.copy()

        if self.graph_features:
            stats['graph_features_available'] = True
            stats['total_nodes'] = self.graph_features.get('metadata', {}).get('nodes', 0)
            stats['total_edges'] = self.graph_features.get('metadata', {}).get('edges', 0)
        else:
            stats['graph_features_available'] = False

        stats['similarity_matrix_available'] = bool(self.similarity_matrix)

        return stats

    def benchmark_search_methods(self, test_queries: List[str], top_k: int = 10) -> Dict[str, Any]:
        """Benchmark different search methods"""
        logger.info("🧪 Benchmarking search methods...")

        results = {
            'semantic_only': [],
            'graph_enhanced': [],
            'query_times': {
                'semantic_only': [],
                'graph_enhanced': []
            }
        }

        for query in test_queries:
            logger.info(f"Testing query: {query}")

            # Semantic only
            start = datetime.now()
            semantic_results = self.hybrid_search(query, top_k=top_k, use_graph_features=False)
            semantic_time = (datetime.now() - start).total_seconds()

            # Graph enhanced
            start = datetime.now()
            graph_results = self.hybrid_search(query, top_k=top_k, use_graph_features=True)
            graph_time = (datetime.now() - start).total_seconds()

            results['semantic_only'].append(semantic_results)
            results['graph_enhanced'].append(graph_results)
            results['query_times']['semantic_only'].append(semantic_time)
            results['query_times']['graph_enhanced'].append(graph_time)

        # Calculate averages
        results['avg_times'] = {
            'semantic_only': np.mean(results['query_times']['semantic_only']),
            'graph_enhanced': np.mean(results['query_times']['graph_enhanced'])
        }

        logger.info(f"Benchmark complete:")
        logger.info(f"  Semantic only avg time: {results['avg_times']['semantic_only']:.3f}s")
        logger.info(f"  Graph enhanced avg time: {results['avg_times']['graph_enhanced']:.3f}s")

        return results


def main():
    """Main function for testing"""
    rag = GraphEnhancedRAG()

    try:
        # Initialize components
        rag.initialize_components()

        # Test queries
        test_queries = [
            "SQL injection vulnerabilities in web applications",
            "Remote code execution in Microsoft products",
            "Buffer overflow vulnerabilities",
            "Cross-site scripting XSS attacks",
            "Log4j vulnerability CVE-2021-44228"
        ]

        # Test individual search
        logger.info("🔍 Testing enhanced search...")
        for query in test_queries[:2]:  # Test first 2 queries
            logger.info(f"\nQuery: {query}")
            results = rag.hybrid_search(query, top_k=5, use_graph_features=True)

            for i, result in enumerate(results, 1):
                logger.info(f"  {i}. {result['cve_id']}")
                logger.info(f"     Final Score: {result['final_score']:.3f}")
                logger.info(f"     Semantic: {result['semantic_score']:.3f}")
                if 'graph_score' in result:
                    logger.info(f"     Graph: {result['graph_score']:.3f}")
                if 'similar_cves' in result and result['similar_cves']:
                    similar = [f"{cve}({score:.2f})" for cve, score in result['similar_cves'][:3]]
                    logger.info(f"     Similar: {', '.join(similar)}")

        # Performance stats
        logger.info("\n📊 Performance Statistics:")
        stats = rag.get_performance_stats()
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")

        # Test related vulnerabilities
        logger.info("\n🔗 Testing related vulnerability finding...")
        test_cve = "CVE-2021-44228"  # Log4j
        related = rag.find_related_vulnerabilities(test_cve)
        for rel_type, cve_list in related.items():
            logger.info(f"  {rel_type}: {len(cve_list)} CVEs")
            if cve_list:
                logger.info(f"    Examples: {', '.join(cve_list[:5])}")

        logger.info("\n✅ Enhanced RAG system test complete!")

    except Exception as e:
        logger.error(f"Error in enhanced RAG system: {e}")
        raise


if __name__ == "__main__":
    main()