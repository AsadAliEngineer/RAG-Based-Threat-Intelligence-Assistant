#!/usr/bin/env python3
"""
NetworkX Graph Builder for Enhanced Similarity Search
Builds NetworkX graph from JSON knowledge graph for advanced graph algorithms.
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Set, Any
from collections import defaultdict, Counter
import logging
import networkx as nx
import numpy as np
import pandas as pd

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkXGraphBuilder:
    """Build NetworkX graph for advanced graph algorithms and similarity search"""
    
    def __init__(self):
        self.config = Config()
        self.knowledge_base_dir = self.config.knowledge_base_dir
        self.kg_dir = self.knowledge_base_dir / 'knowledge_graph'
        self.output_dir = self.knowledge_base_dir / 'networkx_graph'
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize graph
        self.G = nx.MultiDiGraph()  # Support multiple relationships between nodes
        
        # Data storage
        self.cve_nodes = {}
        self.product_nodes = {}
        self.vendor_nodes = {}
        self.cwe_nodes = {}
        self.capec_nodes = {}
        self.mitre_technique_nodes = {}
        self.mitre_tactic_nodes = {}
        
        # Relationships
        self.relationships = {}
        
        # Cache for expensive operations
        self.similarity_cache = {}
        self.centrality_cache = {}
        
    def debug_relationship_structure(self):
        """Debug function to check relationship data structure"""
        logger.info("Debugging relationship structure...")
        
        for rel_type, rel_list in self.relationships.items():
            if rel_list:
                logger.info(f"{rel_type}: {len(rel_list)} relationships")
                # Show sample relationship structure
                sample = rel_list[0]
                logger.info(f"  Sample {rel_type}: {sample}")
            else:
                logger.warning(f"{rel_type}: No relationships found!")
    
    def debug_cve_connections(self, cve_id: str):
        """Debug function to check a specific CVE's connections"""
        if cve_id not in self.G:
            logger.warning(f"CVE {cve_id} not found in graph")
            return
            
        logger.info(f"Debugging connections for {cve_id}:")
        neighbors = list(self.G.neighbors(cve_id))
        logger.info(f"  Direct neighbors: {len(neighbors)}")
        
        by_type = defaultdict(list)
        for neighbor in neighbors:
            node_type = self.G.nodes[neighbor].get('node_type', 'UNKNOWN')
            by_type[node_type].append(neighbor)
        
        for node_type, nodes in by_type.items():
            logger.info(f"  {node_type}: {len(nodes)} connections")
            if len(nodes) <= 5:  # Show all if 5 or fewer
                logger.info(f"    {nodes}")
            else:  # Show first 5
                logger.info(f"    {nodes[:5]}... (and {len(nodes)-5} more)")
        
    def load_kg_data(self):
        """Load all knowledge graph data from JSON files"""
        logger.info("Loading knowledge graph data...")
        
        try:
            # Load nodes
            with open(self.kg_dir / "cves_nodes.json", 'r', encoding='utf-8') as f:
                self.cve_nodes = json.load(f)
            logger.info(f"Loaded {len(self.cve_nodes)} CVE nodes")
            
            with open(self.kg_dir / "products_nodes.json", 'r', encoding='utf-8') as f:
                self.product_nodes = json.load(f)
            logger.info(f"Loaded {len(self.product_nodes)} product nodes")
            
            with open(self.kg_dir / "vendors_nodes.json", 'r', encoding='utf-8') as f:
                self.vendor_nodes = json.load(f)
            logger.info(f"Loaded {len(self.vendor_nodes)} vendor nodes")
            
            with open(self.kg_dir / "cwes_nodes.json", 'r', encoding='utf-8') as f:
                self.cwe_nodes = json.load(f)
            logger.info(f"Loaded {len(self.cwe_nodes)} CWE nodes")
            
            with open(self.kg_dir / "capecs_nodes.json", 'r', encoding='utf-8') as f:
                self.capec_nodes = json.load(f)
            logger.info(f"Loaded {len(self.capec_nodes)} CAPEC nodes")
            
            # Load relationships
            with open(self.kg_dir / "cve_product_relationships.json", 'r', encoding='utf-8') as f:
                self.relationships['cve_product'] = json.load(f)
            
            with open(self.kg_dir / "cve_cwe_relationships.json", 'r', encoding='utf-8') as f:
                self.relationships['cve_cwe'] = json.load(f)
            
            with open(self.kg_dir / "cve_capec_relationships.json", 'r', encoding='utf-8') as f:
                self.relationships['cve_capec'] = json.load(f)
            
            with open(self.kg_dir / "product_vendor_relationships.json", 'r', encoding='utf-8') as f:
                self.relationships['product_vendor'] = json.load(f)
            
            logger.info("Successfully loaded all knowledge graph data")
            
        except Exception as e:
            logger.error(f"Error loading knowledge graph data: {e}")
            logger.error("Please run kg_builder_without_neo4j.py first to build the knowledge graph")
            raise

    def build_networkx_graph(self):
        """Build the NetworkX graph with all nodes and relationships"""
        import time
        logger.info("Building NetworkX graph...")
        start_total = time.time()

        # Add CVE nodes
        logger.info("Adding CVE nodes...")
        start = time.time()
        for i, (cve_id, cve_data) in enumerate(self.cve_nodes.items()):
            if i % 20000 == 0 and i > 0:
                logger.info(f"  Added {i:,} CVE nodes...")
            node_data = cve_data.copy()
            node_data['node_type'] = 'CVE'
            self.G.add_node(cve_id, **node_data)
        logger.info(f"Finished adding {len(self.cve_nodes):,} CVE nodes in {time.time() - start:.2f}s")

        # Add Product nodes
        logger.info("Adding Product nodes...")
        start = time.time()
        for i, (product_id, product_data) in enumerate(self.product_nodes.items()):
            if i % 20000 == 0 and i > 0:
                logger.info(f"  Added {i:,} Product nodes...")
            node_data = product_data.copy()
            node_data['node_type'] = 'PRODUCT'
            self.G.add_node(product_id, **node_data)
        logger.info(f"Finished adding {len(self.product_nodes):,} Product nodes in {time.time() - start:.2f}s")

        # Add Vendor nodes
        logger.info("Adding Vendor nodes...")
        start = time.time()
        for i, (vendor_id, vendor_data) in enumerate(self.vendor_nodes.items()):
            if i % 5000 == 0 and i > 0:
                logger.info(f"  Added {i:,} Vendor nodes...")
            node_data = vendor_data.copy()
            node_data['node_type'] = 'VENDOR'
            self.G.add_node(vendor_id, **node_data)
        logger.info(f"Finished adding {len(self.vendor_nodes):,} Vendor nodes in {time.time() - start:.2f}s")

        # Add CWE nodes
        logger.info("Adding CWE nodes...")
        start = time.time()
        for i, (cwe_id, cwe_data) in enumerate(self.cwe_nodes.items()):
            if i % 100 == 0 and i > 0:
                logger.info(f"  Added {i:,} CWE nodes...")
            node_data = cwe_data.copy()
            node_data['node_type'] = 'CWE'
            self.G.add_node(cwe_id, **node_data)
        logger.info(f"Finished adding {len(self.cwe_nodes):,} CWE nodes in {time.time() - start:.2f}s")

        # Add CAPEC nodes
        logger.info("Adding CAPEC nodes...")
        start = time.time()
        for i, (capec_id, capec_data) in enumerate(self.capec_nodes.items()):
            if i % 100 == 0 and i > 0:
                logger.info(f"  Added {i:,} CAPEC nodes...")
            node_data = capec_data.copy()
            node_data['node_type'] = 'CAPEC'
            self.G.add_node(capec_id, **node_data)
        logger.info(f"Finished adding {len(self.capec_nodes):,} CAPEC nodes in {time.time() - start:.2f}s")

        # Add relationships - FIXED CVE-Product mapping
        logger.info("Adding CVE-Product relationships...")
        start = time.time()
        cve_product_edges = 0
        for i, rel in enumerate(self.relationships.get('cve_product', [])):
            if i % 50000 == 0 and i > 0:
                logger.info(f"  Processed {i:,} CVE-Product relationships...")
            cve_id = rel.get('cve_id', '')
            product_name = rel.get('product_name', '')

            if cve_id and product_name and cve_id in self.cve_nodes:
                # Find matching product node by searching for product_name in product nodes
                matching_product = None
                for product_key, product_data in self.product_nodes.items():
                    if product_data.get('name', '') == product_name:
                        matching_product = product_key
                        break

                if matching_product:
                    self.G.add_edge(cve_id, matching_product,
                                    relationship_type='AFFECTS', weight=1.0)
                    cve_product_edges += 1
        logger.info(f"Finished adding CVE-Product relationships: {cve_product_edges:,} edges in {time.time() - start:.2f}s")

        # Add CWE relationships
        logger.info("Adding CVE-CWE relationships...")
        start = time.time()
        cve_cwe_edges = 0
        for i, rel in enumerate(self.relationships.get('cve_cwe', [])):
            if i % 20000 == 0 and i > 0:
                logger.info(f"  Processed {i:,} CVE-CWE relationships...")
            cve_id = rel.get('cve_id', '')
            cwe_id = rel.get('cwe_id', '')
            if cve_id and cwe_id and cve_id in self.cve_nodes and cwe_id in self.cwe_nodes:
                self.G.add_edge(cve_id, cwe_id,
                                relationship_type='HAS_WEAKNESS', weight=1.0)
                cve_cwe_edges += 1
        logger.info(f"Finished adding CVE-CWE relationships: {cve_cwe_edges:,} edges in {time.time() - start:.2f}s")

        # Add CAPEC relationships
        logger.info("Adding CVE-CAPEC relationships...")
        start = time.time()
        cve_capec_edges = 0
        for i, rel in enumerate(self.relationships.get('cve_capec', [])):
            if i % 20000 == 0 and i > 0:
                logger.info(f"  Processed {i:,} CVE-CAPEC relationships...")
            cve_id = rel.get('cve_id', '')
            capec_id = rel.get('capec_id', '')
            if cve_id and capec_id and cve_id in self.cve_nodes and capec_id in self.capec_nodes:
                self.G.add_edge(cve_id, capec_id,
                                relationship_type='HAS_ATTACK_PATTERN', weight=1.0)
                cve_capec_edges += 1
        logger.info(f"Finished adding CVE-CAPEC relationships: {cve_capec_edges:,} edges in {time.time() - start:.2f}s")

        # Add Product-Vendor relationships
        logger.info("Adding Product-Vendor relationships...")
        start = time.time()
        product_vendor_edges = 0
        for i, rel in enumerate(self.relationships.get('product_vendor', [])):
            if i % 10000 == 0 and i > 0:
                logger.info(f"  Processed {i:,} Product-Vendor relationships...")
            product_key = rel.get('product_key', '')
            vendor_name = rel.get('vendor_name', '')
            if product_key and vendor_name and product_key in self.product_nodes and vendor_name in self.vendor_nodes:
                self.G.add_edge(product_key, vendor_name,
                                relationship_type='MANUFACTURED_BY', weight=1.0)
                product_vendor_edges += 1
        logger.info(f"Finished adding Product-Vendor relationships: {product_vendor_edges:,} edges in {time.time() - start:.2f}s")

        logger.info(f"Graph built: {self.G.number_of_nodes():,} nodes, {self.G.number_of_edges():,} edges")
        logger.info(f"CVE-Product edges created: {cve_product_edges}")

        # Add debug information about relationships
        rel_counts = {}
        for rel_type, rel_list in self.relationships.items():
            rel_counts[rel_type] = len(rel_list)
        logger.info(f"Relationship data loaded: {rel_counts}")

        # Count actual edges by type
        edge_types = defaultdict(int)
        for _, _, data in self.G.edges(data=True):
            edge_types[data.get('relationship_type', 'UNKNOWN')] += 1
        logger.info(f"Edges created in graph: {dict(edge_types)}")
        logger.info(f"Total time to build NetworkX graph: {time.time() - start_total:.2f}s")
    
    def find_similar_vulnerabilities(self, cve_id: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Find similar vulnerabilities using graph-based algorithms"""
        if cve_id not in self.G:
            logger.warning(f"CVE {cve_id} not found in graph")
            return []
        
        # Use cache if available
        cache_key = f"{cve_id}_{top_k}"
        if cache_key in self.similarity_cache:
            return self.similarity_cache[cache_key]
        
        # Get 2-hop neighborhood (CVE -> CWE/Product -> other CVEs)
        neighbors = set()
        for neighbor in self.G.neighbors(cve_id):
            neighbors.add(neighbor)
            for second_hop in self.G.neighbors(neighbor):
                if self.G.nodes[second_hop].get('node_type') == 'CVE' and second_hop != cve_id:
                    neighbors.add(second_hop)
        
        # Calculate similarity scores
        similarities = []
        target_cwe = self._get_connected_nodes(cve_id, 'CWE')
        target_products = self._get_connected_nodes(cve_id, 'PRODUCT')
        target_capec = self._get_connected_nodes(cve_id, 'CAPEC')
        target_cvss = self.G.nodes[cve_id].get('cvss_v3', {}).get('base_score', 0)
        
        for candidate_cve in neighbors:
            if candidate_cve == cve_id or self.G.nodes[candidate_cve].get('node_type') != 'CVE':
                continue
                
            # CWE similarity (Jaccard coefficient)
            cand_cwe = self._get_connected_nodes(candidate_cve, 'CWE')
            cwe_sim = self._jaccard_similarity(target_cwe, cand_cwe)
            
            # Product similarity  
            cand_products = self._get_connected_nodes(candidate_cve, 'PRODUCT')
            prod_sim = self._jaccard_similarity(target_products, cand_products)
            
            # CAPEC similarity
            cand_capec = self._get_connected_nodes(candidate_cve, 'CAPEC')
            capec_sim = self._jaccard_similarity(target_capec, cand_capec)
            
            # CVSS similarity
            cand_cvss = self.G.nodes[candidate_cve].get('cvss_v3', {}).get('base_score', 0)
            cvss_sim = 1 - abs(target_cvss - cand_cvss) / 10.0 if target_cvss > 0 and cand_cvss > 0 else 0
            
            # Combined similarity score with weights
            similarity = (0.4 * cwe_sim + 
                         0.3 * prod_sim + 
                         0.2 * capec_sim + 
                         0.1 * cvss_sim)
            
            if similarity > 0:  # Only include similar CVEs
                similarities.append((candidate_cve, similarity))
        
        # Sort by similarity and return top-k
        similarities.sort(key=lambda x: x[1], reverse=True)
        result = similarities[:top_k]
        
        # Cache result
        self.similarity_cache[cache_key] = result
        return result
    
    def get_vulnerability_clusters(self, min_cluster_size: int = 5) -> Dict[str, List[str]]:
        """Find clusters of related vulnerabilities"""
        logger.info("Finding vulnerability clusters...")
        
        # Get CVE nodes only
        cve_nodes = [n for n, data in self.G.nodes(data=True) if data.get('node_type') == 'CVE']
        
        # Build CWE-based clusters
        cwe_clusters = defaultdict(list)
        for cve in cve_nodes:
            cwes = self._get_connected_nodes(cve, 'CWE')
            for cwe in cwes:
                cwe_clusters[cwe].append(cve)
        
        # Build Product-based clusters  
        product_clusters = defaultdict(list)
        for cve in cve_nodes:
            products = self._get_connected_nodes(cve, 'PRODUCT')
            for product in products:
                product_clusters[product].append(cve)
        
        # Combine clusters and filter by minimum size
        all_clusters = {}
        
        # Add CWE clusters
        for cwe, cves in cwe_clusters.items():
            if len(cves) >= min_cluster_size:
                all_clusters[f"CWE_{cwe}"] = cves
        
        # Add Product clusters (for major products)
        for product, cves in product_clusters.items():
            if len(cves) >= min_cluster_size * 2:  # Higher threshold for products
                all_clusters[f"PRODUCT_{product}"] = cves
        
        logger.info(f"Found {len(all_clusters)} vulnerability clusters")
        return all_clusters
    
    def calculate_node_importance(self) -> Dict[str, float]:
        """Calculate importance scores using PageRank"""
        logger.info("Calculating node importance scores...")
        
        if 'pagerank' in self.centrality_cache:
            return self.centrality_cache['pagerank']
        
        try:
            # Convert to undirected graph for PageRank (better for importance)
            G_undirected = self.G.to_undirected()
            pagerank_scores = nx.pagerank(G_undirected, weight='weight', max_iter=100)
            
            # Cache result
            self.centrality_cache['pagerank'] = pagerank_scores
            
            logger.info("PageRank calculation complete")
            return pagerank_scores
            
        except Exception as e:
            logger.error(f"Error calculating PageRank: {e}")
            return {}
    
    def calculate_betweenness_centrality(self) -> Dict[str, float]:
        """Calculate betweenness centrality for CVE nodes"""
        logger.info("Calculating betweenness centrality...")
        
        if 'betweenness' in self.centrality_cache:
            logger.info("Using cached betweenness centrality results")
            return self.centrality_cache['betweenness']
        
        try:
            # Calculate only for a small sample of high-importance nodes due to computational complexity
            logger.info("Step 1: Identifying CVE nodes...")
            cve_nodes = [n for n, data in self.G.nodes(data=True) if data.get('node_type') == 'CVE']
            logger.info(f"Found {len(cve_nodes):,} CVE nodes in the graph")
            
            # Get top CVEs by CVSS score to focus on important ones
            logger.info("Step 2: Filtering CVEs with CVSS scores...")
            cve_with_scores = []
            for i, cve_id in enumerate(cve_nodes):
                if i % 10000 == 0:  # Progress update every 10k CVEs
                    logger.info(f"  Processing CVE {i+1:,}/{len(cve_nodes):,} ({i/len(cve_nodes)*100:.1f}%)")
                cvss_score = self.G.nodes[cve_id].get('cvss_v3', {}).get('base_score', 0)
                if cvss_score > 0:  # Only include CVEs with CVSS scores
                    cve_with_scores.append((cve_id, cvss_score))
            
            logger.info(f"Found {len(cve_with_scores):,} CVEs with CVSS scores")
            
            # Sort by CVSS score and take top 100 for betweenness calculation
            logger.info("Step 3: Sorting CVEs by CVSS score...")
            cve_with_scores.sort(key=lambda x: x[1], reverse=True)
            sample_size = min(100, len(cve_with_scores))  # Reduced from 1000 to 100
            sampled_nodes = [cve_id for cve_id, _ in cve_with_scores[:sample_size]]
            
            logger.info(f"Selected top {len(sampled_nodes)} CVEs by CVSS score for betweenness calculation")
            logger.info(f"CVSS score range: {cve_with_scores[0][1]} (highest) to {cve_with_scores[sample_size-1][1]} (lowest in sample)")
            
            # Log some example CVEs being processed
            logger.info("Sample CVEs being processed:")
            for i, (cve_id, score) in enumerate(cve_with_scores[:5]):
                logger.info(f"  {i+1}. {cve_id} (CVSS: {score})")
            
            # Use approximate betweenness centrality with smaller sample
            logger.info("Step 4: Starting betweenness centrality calculation...")
            logger.info(f"Graph size: {self.G.number_of_nodes():,} nodes, {self.G.number_of_edges():,} edges")
            logger.info(f"Using k={len(sampled_nodes)} for approximate calculation")
            
            import time
            start_time = time.time()
            
            betweenness_scores = nx.betweenness_centrality(self.G, k=len(sampled_nodes), weight='weight')
            
            elapsed_time = time.time() - start_time
            logger.info(f"Betweenness centrality calculation completed in {elapsed_time:.2f} seconds")
            
            # Log some statistics about the results
            if betweenness_scores:
                scores_list = list(betweenness_scores.values())
                non_zero_scores = [s for s in scores_list if s > 0]
                logger.info(f"Betweenness scores calculated: {len(betweenness_scores)} total, {len(non_zero_scores)} non-zero")
                if non_zero_scores:
                    logger.info(f"Score range: {min(non_zero_scores):.6f} to {max(non_zero_scores):.6f}")
                    logger.info(f"Average non-zero score: {sum(non_zero_scores)/len(non_zero_scores):.6f}")
                
                # Show top 5 CVEs by betweenness centrality
                top_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:5]
                logger.info("Top 5 CVEs by betweenness centrality:")
                for i, (cve_id, score) in enumerate(top_betweenness):
                    cvss_score = self.G.nodes[cve_id].get('cvss_v3', {}).get('base_score', 0)
                    logger.info(f"  {i+1}. {cve_id} (Betweenness: {score:.6f}, CVSS: {cvss_score})")
            
            # Cache result
            self.centrality_cache['betweenness'] = betweenness_scores
            
            logger.info("Betweenness centrality calculation complete and cached")
            return betweenness_scores
            
        except Exception as e:
            logger.error(f"Error calculating betweenness centrality: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            logger.warning("Skipping betweenness centrality calculation due to error")
            return {}
    
    def export_graph_features(self):
        """Export graph-based features for enhanced RAG"""
        logger.info("💾 Exporting graph features...")
        overall_start_time = time.time()
        
        logger.info("Step 1: Building metadata and basic metrics...")
        features = {
            'metadata': {
                'build_timestamp': str(pd.Timestamp.now()),
                'nodes': self.G.number_of_nodes(),
                'edges': self.G.number_of_edges(),
                'density': nx.density(self.G)
            },
            'graph_metrics': {
                'nodes': self.G.number_of_nodes(),
                'edges': self.G.number_of_edges(),
                'density': nx.density(self.G),
                'avg_degree': sum(dict(self.G.degree()).values()) / self.G.number_of_nodes()
            }
        }
        
        logger.info("Step 2: Calculating node importance (PageRank)...")
        start_time = time.time()
        features['node_importance'] = self.calculate_node_importance()
        pagerank_time = time.time() - start_time
        logger.info(f"PageRank calculation completed in {pagerank_time:.2f} seconds")
        
        logger.info("Step 3: Finding vulnerability clusters...")
        start_time = time.time()
        features['vulnerability_clusters'] = self.get_vulnerability_clusters()
        clusters_time = time.time() - start_time
        logger.info(f"Vulnerability clustering completed in {clusters_time:.2f} seconds")
        
        # Add centrality measures (with timeout for Unix systems, direct calculation for Windows)
        try:
            import signal
            import platform
            import time
            
            if platform.system() != 'Windows':
                # Unix-like systems support SIGALRM
                def timeout_handler(signum, frame):
                    raise TimeoutError("Betweenness centrality calculation timed out")
                
                # Set timeout for betweenness calculation (2 minutes - reduced from 5)
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(120)  # 2 minutes timeout
                
                try:
                    features['betweenness_centrality'] = self.calculate_betweenness_centrality()
                    signal.alarm(0)  # Cancel timeout
                except TimeoutError:
                    logger.warning("Betweenness centrality calculation timed out, skipping...")
                    features['betweenness_centrality'] = {}
                except Exception as e:
                    logger.warning(f"Could not calculate betweenness centrality: {e}")
                    features['betweenness_centrality'] = {}
            else:
                # Windows doesn't support SIGALRM, use time-based timeout
                logger.info("Windows detected - calculating betweenness centrality with time limit...")
                start_time = time.time()
                timeout_seconds = 120  # 2 minutes timeout
                
                try:
                    features['betweenness_centrality'] = self.calculate_betweenness_centrality()
                    elapsed = time.time() - start_time
                    logger.info(f"Betweenness centrality completed in {elapsed:.1f} seconds")
                except Exception as e:
                    elapsed = time.time() - start_time
                    if elapsed > timeout_seconds:
                        logger.warning(f"Betweenness centrality calculation took too long ({elapsed:.1f}s), skipping...")
                    else:
                        logger.warning(f"Could not calculate betweenness centrality: {e}")
                    features['betweenness_centrality'] = {}
                
        except Exception as e:
            logger.warning(f"Could not calculate betweenness centrality: {e}")
            features['betweenness_centrality'] = {}
        
        # Save to file
        logger.info("Step 5: Saving graph features to file...")
        output_file = self.output_dir / "graph_features.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(features, f, indent=2, ensure_ascii=False)
        
        file_size = output_file.stat().st_size / (1024 * 1024)  # Size in MB
        logger.info(f"Graph features exported to {output_file} ({file_size:.2f} MB)")
        
        # Save similarity matrix for top CVEs
        logger.info("Step 6: Building and exporting similarity matrix...")
        self._export_similarity_matrix()
        
        overall_time = time.time() - overall_start_time
        logger.info(f"🎉 Complete graph feature export finished in {overall_time:.2f} seconds")
        
        return features
    
    def _export_similarity_matrix(self, max_cves: int = 1000):
        """Export similarity matrix for top CVEs"""
        logger.info("Building similarity matrix...")
        
        # Get top CVEs by importance or CVSS score
        logger.info("Step 1: Collecting CVE nodes...")
        cve_nodes = [(n, data) for n, data in self.G.nodes(data=True) if data.get('node_type') == 'CVE']
        logger.info(f"Found {len(cve_nodes):,} CVE nodes")
        
        # Sort by CVSS score and take top N
        logger.info("Step 2: Sorting CVEs by CVSS score...")
        cve_nodes.sort(key=lambda x: x[1].get('cvss_v3', {}).get('base_score', 0), reverse=True)
        top_cves = [cve_id for cve_id, _ in cve_nodes[:max_cves]]
        logger.info(f"Selected top {len(top_cves)} CVEs for similarity matrix")
        
        # Log CVSS score range
        if top_cves:
            first_cvss = cve_nodes[0][1].get('cvss_v3', {}).get('base_score', 0)
            last_cvss = cve_nodes[len(top_cves)-1][1].get('cvss_v3', {}).get('base_score', 0)
            logger.info(f"CVSS score range: {first_cvss} (highest) to {last_cvss} (lowest in matrix)")
        
        similarity_matrix = {}
        start_time = time.time()
        
        logger.info("Step 3: Calculating similarity scores...")
        for i, cve_id in enumerate(top_cves):
            if i % 25 == 0:  # More frequent progress updates
                elapsed = time.time() - start_time
                avg_time_per_cve = elapsed / (i + 1) if i > 0 else 0
                remaining_cves = len(top_cves) - i
                estimated_remaining = avg_time_per_cve * remaining_cves
                logger.info(f"Processing CVE {i+1:,}/{len(top_cves):,} ({i/len(top_cves)*100:.1f}%) - "
                           f"Elapsed: {elapsed:.1f}s, Est. remaining: {estimated_remaining:.1f}s")
            
            try:
                similar_cves = self.find_similar_vulnerabilities(cve_id, top_k=20)
                similarity_matrix[cve_id] = {
                    'similar_cves': similar_cves,
                    'cvss_score': self.G.nodes[cve_id].get('cvss_v3', {}).get('base_score', 0)
                }
                
                # Log some statistics for the first few CVEs
                if i < 5:
                    logger.info(f"  {cve_id}: Found {len(similar_cves)} similar CVEs")
                    if similar_cves:
                        top_similar = similar_cves[0]
                        logger.info(f"    Top similar: {top_similar[0]} (score: {top_similar[1]:.3f})")
                
            except Exception as e:
                logger.warning(f"Error processing similarity for {cve_id}: {e}")
                similarity_matrix[cve_id] = {
                    'similar_cves': [],
                    'cvss_score': self.G.nodes[cve_id].get('cvss_v3', {}).get('base_score', 0)
                }
        
        total_time = time.time() - start_time
        logger.info(f"Similarity matrix calculation completed in {total_time:.2f} seconds")
        logger.info(f"Average time per CVE: {total_time/len(top_cves):.3f} seconds")
        
        # Calculate some statistics about the similarity matrix
        total_similarities = sum(len(data['similar_cves']) for data in similarity_matrix.values())
        non_empty_similarities = sum(1 for data in similarity_matrix.values() if data['similar_cves'])
        logger.info(f"Similarity matrix statistics:")
        logger.info(f"  Total CVEs processed: {len(similarity_matrix)}")
        logger.info(f"  CVEs with similar CVEs: {non_empty_similarities}")
        logger.info(f"  Total similarity relationships: {total_similarities}")
        logger.info(f"  Average similarities per CVE: {total_similarities/len(similarity_matrix):.1f}")
        
        # Save similarity matrix
        logger.info("Step 4: Saving similarity matrix to file...")
        output_file = self.output_dir / "similarity_matrix.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(similarity_matrix, f, indent=2, ensure_ascii=False)
        
        file_size = output_file.stat().st_size / (1024 * 1024)  # Size in MB
        logger.info(f"Similarity matrix exported to {output_file} ({file_size:.2f} MB)")
    
    def _get_connected_nodes(self, node_id: str, node_type: str) -> Set[str]:
        """Get all connected nodes of a specific type"""
        connected = set()
        for neighbor in self.G.neighbors(node_id):
            if self.G.nodes[neighbor].get('node_type') == node_type:
                connected.add(neighbor)
        return connected
    
    def _jaccard_similarity(self, set1: Set[str], set2: Set[str]) -> float:
        """Calculate Jaccard similarity between two sets"""
        if not set1 and not set2:
            return 0.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0
    
    def print_graph_statistics(self):
        """Print comprehensive graph statistics"""
        logger.info("📊 Graph Statistics:")
        logger.info("=" * 50)
        
        # Basic stats
        logger.info(f"Nodes: {self.G.number_of_nodes():,}")
        logger.info(f"Edges: {self.G.number_of_edges():,}")
        logger.info(f"Density: {nx.density(self.G):.6f}")
        
        # Node type distribution
        node_types = defaultdict(int)
        for _, data in self.G.nodes(data=True):
            node_types[data.get('node_type', 'UNKNOWN')] += 1
        
        logger.info("\nNode Type Distribution:")
        for node_type, count in sorted(node_types.items()):
            logger.info(f"  {node_type}: {count:,}")
        
        # Relationship type distribution
        rel_types = defaultdict(int)
        for _, _, data in self.G.edges(data=True):
            rel_types[data.get('relationship_type', 'UNKNOWN')] += 1
        
        logger.info("\nRelationship Type Distribution:")
        for rel_type, count in sorted(rel_types.items()):
            logger.info(f"  {rel_type}: {count:,}")

def main():
    """Main function"""
    builder = NetworkXGraphBuilder()
    
    try:
        # Load data and build graph
        builder.load_kg_data()
        builder.debug_relationship_structure()  # Add debug info
        builder.build_networkx_graph()
        
        # Print statistics
        builder.print_graph_statistics()
        
        # Debug specific CVE connections
        test_cves = ["CVE-2021-44228", "CVE-2020-1472", "CVE-2019-0708"]
        for test_cve in test_cves:
            if test_cve in builder.G:
                builder.debug_cve_connections(test_cve)
                break  # Just debug one existing CVE
        
        # Export features for RAG enhancement
        features = builder.export_graph_features()
        
        # Test similarity search
        logger.info("\n🧪 Testing similarity search...")
        test_cves = ["CVE-2021-44228", "CVE-2020-1472", "CVE-2019-0708"]
        
        for test_cve in test_cves:
            logger.info(f"\nSimilar vulnerabilities to {test_cve}:")
            if test_cve in builder.G:
                similar = builder.find_similar_vulnerabilities(test_cve, top_k=5)
                if similar:
                    for cve, score in similar:
                        logger.info(f"  {cve}: {score:.3f}")
                else:
                    logger.info(f"  No similar vulnerabilities found for {test_cve}")
            else:
                logger.info(f"  CVE {test_cve} not found in graph")
                
        # Test with a CVE that should exist
        logger.info(f"\nTesting with a random CVE from the graph...")
        cve_nodes = [n for n, data in builder.G.nodes(data=True) if data.get('node_type') == 'CVE']
        if cve_nodes:
            test_cve = cve_nodes[0]
            logger.info(f"Testing similarity for {test_cve}:")
            similar = builder.find_similar_vulnerabilities(test_cve, top_k=3)
            if similar:
                for cve, score in similar:
                    logger.info(f"  {cve}: {score:.3f}")
            else:
                logger.info(f"  No similar vulnerabilities found for {test_cve}")
        
        logger.info("\n✅ NetworkX graph construction complete!")
        logger.info(f"📁 Output directory: {builder.output_dir}")
        
    except Exception as e:
        logger.error(f"Error in graph construction: {e}")
        raise

if __name__ == "__main__":
    main()
