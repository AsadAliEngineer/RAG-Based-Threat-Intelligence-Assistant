#!/usr/bin/env python3
"""
Knowledge Graph Builder Without Neo4j

This script builds a comprehensive knowledge graph from processed CVE data and CPE extraction results
without requiring Neo4j. It creates a structured representation that can be used for RAG systems
and other graph-based analysis.

Usage:
    python kg_builder_without_neo4j.py
"""

import json
import sys
from datetime import datetime
from typing import Dict, List, Any, Set
from pathlib import Path
from collections import defaultdict, Counter
import logging

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class KnowledgeGraphBuilder:
    def __init__(self):
        self.config = Config()
        self.knowledge_base_dir = self.config.knowledge_base_dir
        self.output_dir = self.knowledge_base_dir / 'knowledge_graph'
        self.output_dir.mkdir(exist_ok=True)
        
        # Graph structure
        self.nodes = {
            'cves': {},
            'products': {},
            'vendors': {},
            'cwes': {},
            'capecs': {},
            'mitre_techniques': {},
            'mitre_tactics': {}
        }
        
        self.relationships = {
            'cve_product': [],
            'cve_cwe': [],
            'cve_capec': [],
            'cve_mitre_technique': [],
            'cve_mitre_tactic': [],
            'product_vendor': [],
            'product_version': []
        }
        
        self.statistics = {}
    
    def load_all_cve_data(self) -> List[Dict[str, Any]]:
        """Load all CVE data from year-based files"""
        all_cves = []
        
        # Find all year-based CVE files
        cve_files = list(self.knowledge_base_dir.glob("enhanced_documents_cve_*.json"))
        cve_files.sort()
        
        logger.info(f"Found {len(cve_files)} year-based CVE files")
        
        for file in cve_files:
            logger.info(f"Loading CVEs from {file.name}...")
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Filter for CVE documents only
                cve_docs = [doc for doc in data if doc.get('document_type') == 'CVE']
                all_cves.extend(cve_docs)
                logger.info(f"  Loaded {len(cve_docs)} CVEs from {file.name}")
                
            except Exception as e:
                logger.error(f"Error loading {file.name}: {e}")
                continue
        
        logger.info(f"Total CVEs loaded: {len(all_cves)}")
        return all_cves
    
    def load_cpe_data(self) -> Dict[str, Any]:
        """Load CPE parsing results"""
        cpe_file = self.knowledge_base_dir / 'cpe_parsing_results_full.json'
        
        if not cpe_file.exists():
            logger.warning(f"CPE file not found: {cpe_file}")
            return {}
        
        try:
            with open(cpe_file, 'r', encoding='utf-8') as f:
                cpe_data = json.load(f)
            logger.info(f"Loaded CPE data for {len(cpe_data.get('products', {}))} products")
            return cpe_data
        except Exception as e:
            logger.error(f"Error loading CPE data: {e}")
            return {}
    
    def build_cve_nodes(self, cve_data: List[Dict[str, Any]]):
        """Build CVE nodes from CVE data"""
        logger.info("Building CVE nodes...")
        
        for cve in cve_data:
            cve_id = cve['id']
            
            # Create CVE node
            cve_node = {
                'id': cve_id,
                'title': cve.get('title', ''),
                'description': cve.get('content', ''),
                'source': cve.get('source', ''),
                'published_date': cve.get('published_date', ''),
                'last_modified_date': cve.get('last_modified_date', ''),
                'cvss_v3': cve.get('cvss_v3', {}),
                'cvss_v2': cve.get('cvss_v2', {}),
                'affected_products': cve.get('affected_products', []),
                'is_in_kev': cve.get('is_in_kev', False),
                'tags': cve.get('tags', []),
                'vulnerability_count': 1  # Each CVE represents one vulnerability
            }
            
            self.nodes['cves'][cve_id] = cve_node
            
            # Create relationships
            self._create_cve_relationships(cve_id, cve)
    
    def _create_cve_relationships(self, cve_id: str, cve: Dict[str, Any]):
        """Create relationships for a CVE"""
        # CVE -> Product relationships
        affected_products = cve.get('affected_products', [])
        for product_name in affected_products:
            self.relationships['cve_product'].append({
                'cve_id': cve_id,
                'product_name': product_name,
                'relationship_type': 'AFFECTS'
            })
        
        # CVE -> CWE relationships
        cwe_refs = cve.get('cwe_refs', [])
        for cwe_id in cwe_refs:
            self.relationships['cve_cwe'].append({
                'cve_id': cve_id,
                'cwe_id': cwe_id,
                'relationship_type': 'HAS_WEAKNESS'
            })
        
        # CVE -> CAPEC relationships
        capec_entries = cve.get('capec_entries', [])
        for capec_id in capec_entries:
            self.relationships['cve_capec'].append({
                'cve_id': cve_id,
                'capec_id': capec_id,
                'relationship_type': 'HAS_ATTACK_PATTERN'
            })
        
        # CVE -> MITRE Technique relationships
        mitre_techniques = cve.get('mitre_techniques', [])
        for technique_id in mitre_techniques:
            self.relationships['cve_mitre_technique'].append({
                'cve_id': cve_id,
                'technique_id': technique_id,
                'relationship_type': 'USES_TECHNIQUE'
            })
        
        # CVE -> MITRE Tactic relationships
        mitre_tactics = cve.get('mitre_tactics', [])
        for tactic_id in mitre_tactics:
            self.relationships['cve_mitre_tactic'].append({
                'cve_id': cve_id,
                'tactic_id': tactic_id,
                'relationship_type': 'BELONGS_TO_TACTIC'
            })
    
    def build_cwe_nodes(self):
        """Build CWE nodes from CVE relationships"""
        logger.info("Building CWE nodes...")
        
        cwe_counter = Counter()
        for rel in self.relationships['cve_cwe']:
            cwe_counter[rel['cwe_id']] += 1
        
        for cwe_id, count in cwe_counter.items():
            self.nodes['cwes'][cwe_id] = {
                'id': cwe_id,
                'name': f"Common Weakness Enumeration {cwe_id}",
                'vulnerability_count': count,
                'node_type': 'CWE'
            }
    
    def build_capec_nodes(self):
        """Build CAPEC nodes from CVE relationships"""
        logger.info("Building CAPEC nodes...")
        
        capec_counter = Counter()
        for rel in self.relationships['cve_capec']:
            capec_counter[rel['capec_id']] += 1
        
        for capec_id, count in capec_counter.items():
            self.nodes['capecs'][capec_id] = {
                'id': capec_id,
                'name': f"Common Attack Pattern {capec_id}",
                'vulnerability_count': count,
                'node_type': 'CAPEC'
            }
    
    def build_mitre_nodes(self):
        """Build MITRE ATT&CK nodes from CVE relationships"""
        logger.info("Building MITRE ATT&CK nodes...")
        
        # Techniques
        technique_counter = Counter()
        for rel in self.relationships['cve_mitre_technique']:
            technique_counter[rel['technique_id']] += 1
        
        for technique_id, count in technique_counter.items():
            self.nodes['mitre_techniques'][technique_id] = {
                'id': technique_id,
                'name': f"MITRE ATT&CK Technique {technique_id}",
                'vulnerability_count': count,
                'node_type': 'MITRE_TECHNIQUE'
            }
        
        # Tactics
        tactic_counter = Counter()
        for rel in self.relationships['cve_mitre_tactic']:
            tactic_counter[rel['tactic_id']] += 1
        
        for tactic_id, count in tactic_counter.items():
            self.nodes['mitre_tactics'][tactic_id] = {
                'id': tactic_id,
                'name': f"MITRE ATT&CK Tactic {tactic_id}",
                'vulnerability_count': count,
                'node_type': 'MITRE_TACTIC'
            }
    
    def build_product_vendor_nodes(self, cpe_data: Dict[str, Any]):
        """Build Product and Vendor nodes from CPE data"""
        logger.info("Building Product and Vendor nodes...")
        
        # Build vendor nodes first
        vendor_counter = Counter()
        for product_key, product_data in cpe_data.get('products', {}).items():
            vendor_name = product_data.get('vendor', '')
            if vendor_name:
                vendor_counter[vendor_name] += product_data.get('vulnerability_count', 0)
        
        for vendor_name, total_vulns in vendor_counter.items():
            self.nodes['vendors'][vendor_name] = {
                'name': vendor_name,
                'display_name': vendor_name.title(),
                'vulnerability_count': total_vulns,
                'product_count': 0,  # Will be updated below
                'node_type': 'VENDOR'
            }
        
        # Build product nodes
        for product_key, product_data in cpe_data.get('products', {}).items():
            vendor_name = product_data.get('vendor', '')
            
            # Create product node
            product_node = {
                'name': product_data.get('product', ''),
                'vendor': vendor_name,
                'display_name': product_data.get('display_name', ''),
                'category': product_data.get('category', ''),
                'family': product_data.get('family', ''),
                'criticality_score': product_data.get('criticality_score', 0.0),
                'aliases': product_data.get('aliases', []),
                'vulnerability_count': product_data.get('vulnerability_count', 0),
                'versions': list(product_data.get('versions', {}).keys()),
                'node_type': 'PRODUCT'
            }
            
            self.nodes['products'][product_key] = product_node
            
            # Create product-vendor relationship
            if vendor_name:
                self.relationships['product_vendor'].append({
                    'product_key': product_key,
                    'vendor_name': vendor_name,
                    'relationship_type': 'MANUFACTURED_BY'
                })
                
                # Update vendor product count
                if vendor_name in self.nodes['vendors']:
                    self.nodes['vendors'][vendor_name]['product_count'] += 1
    
    def calculate_statistics(self):
        """Calculate comprehensive statistics about the knowledge graph"""
        logger.info("Calculating knowledge graph statistics...")
        
        stats = {
            'build_timestamp': datetime.now().isoformat(),
            'node_counts': {
                'cves': len(self.nodes['cves']),
                'products': len(self.nodes['products']),
                'vendors': len(self.nodes['vendors']),
                'cwes': len(self.nodes['cwes']),
                'capecs': len(self.nodes['capecs']),
                'mitre_techniques': len(self.nodes['mitre_techniques']),
                'mitre_tactics': len(self.nodes['mitre_tactics'])
            },
            'relationship_counts': {
                'cve_product': len(self.relationships['cve_product']),
                'cve_cwe': len(self.relationships['cve_cwe']),
                'cve_capec': len(self.relationships['cve_capec']),
                'cve_mitre_technique': len(self.relationships['cve_mitre_technique']),
                'cve_mitre_tactic': len(self.relationships['cve_mitre_tactic']),
                'product_vendor': len(self.relationships['product_vendor'])
            },
            'cve_statistics': {
                'total_cves': len(self.nodes['cves']),
                'cves_in_kev': sum(1 for cve in self.nodes['cves'].values() if cve.get('is_in_kev', False)),
                'cves_with_cvss_v3': sum(1 for cve in self.nodes['cves'].values() if cve.get('cvss_v3', {}).get('base_score')),
                'cves_with_cvss_v2': sum(1 for cve in self.nodes['cves'].values() if cve.get('cvss_v2', {}).get('base_score'))
            },
            'severity_distribution': self._calculate_severity_distribution(),
            'top_vendors': self._get_top_vendors(10),
            'top_products': self._get_top_products(10),
            'top_cwes': self._get_top_cwes(10),
            'top_capecs': self._get_top_capecs(10)
        }
        
        self.statistics = stats
        return stats
    
    def _calculate_severity_distribution(self) -> Dict[str, int]:
        """Calculate CVSS severity distribution"""
        severity_counts = Counter()
        for cve in self.nodes['cves'].values():
            severity = cve.get('cvss_v3', {}).get('base_severity', 'UNKNOWN')
            severity_counts[severity] += 1
        return dict(severity_counts)
    
    def _get_top_vendors(self, limit: int) -> List[Dict[str, Any]]:
        """Get top vendors by vulnerability count"""
        vendors = list(self.nodes['vendors'].values())
        vendors.sort(key=lambda x: x.get('vulnerability_count', 0), reverse=True)
        return vendors[:limit]
    
    def _get_top_products(self, limit: int) -> List[Dict[str, Any]]:
        """Get top products by vulnerability count"""
        products = list(self.nodes['products'].values())
        products.sort(key=lambda x: x.get('vulnerability_count', 0), reverse=True)
        return products[:limit]
    
    def _get_top_cwes(self, limit: int) -> List[Dict[str, Any]]:
        """Get top CWEs by vulnerability count"""
        cwes = list(self.nodes['cwes'].values())
        cwes.sort(key=lambda x: x.get('vulnerability_count', 0), reverse=True)
        return cwes[:limit]
    
    def _get_top_capecs(self, limit: int) -> List[Dict[str, Any]]:
        """Get top CAPECs by vulnerability count"""
        capecs = list(self.nodes['capecs'].values())
        capecs.sort(key=lambda x: x.get('vulnerability_count', 0), reverse=True)
        return capecs[:limit]
    
    def save_knowledge_graph(self):
        """Save the complete knowledge graph to files"""
        logger.info("Saving knowledge graph...")
        
        # Save nodes
        for node_type, nodes in self.nodes.items():
            output_file = self.output_dir / f"{node_type}_nodes.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(nodes, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved {len(nodes)} {node_type} nodes to {output_file}")
        
        # Save relationships
        for rel_type, relationships in self.relationships.items():
            output_file = self.output_dir / f"{rel_type}_relationships.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(relationships, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved {len(relationships)} {rel_type} relationships to {output_file}")
        
        # Save statistics
        stats_file = self.output_dir / "knowledge_graph_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.statistics, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved statistics to {stats_file}")
        
        # Save complete graph structure
        complete_graph = {
            'metadata': {
                'build_timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'description': 'CVE Knowledge Graph built without Neo4j'
            },
            'nodes': self.nodes,
            'relationships': self.relationships,
            'statistics': self.statistics
        }
        
        graph_file = self.output_dir / "complete_knowledge_graph.json"
        with open(graph_file, 'w', encoding='utf-8') as f:
            json.dump(complete_graph, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved complete knowledge graph to {graph_file}")
    
    def print_statistics(self):
        """Print a summary of the knowledge graph statistics"""
        if not self.statistics:
            self.calculate_statistics()
        
        stats = self.statistics
        
        print("\n📊 Knowledge Graph Statistics:")
        print("=" * 60)
        print(f"📈 Nodes:")
        for node_type, count in stats['node_counts'].items():
            print(f"  {node_type.upper()}: {count:,}")
        
        print(f"\n🔗 Relationships:")
        for rel_type, count in stats['relationship_counts'].items():
            print(f"  {rel_type.upper()}: {count:,}")
        
        print(f"\n🛡️ CVE Statistics:")
        cve_stats = stats['cve_statistics']
        print(f"  Total CVEs: {cve_stats['total_cves']:,}")
        print(f"  In KEV: {cve_stats['cves_in_kev']:,}")
        print(f"  With CVSS v3: {cve_stats['cves_with_cvss_v3']:,}")
        print(f"  With CVSS v2: {cve_stats['cves_with_cvss_v2']:,}")
        
        print(f"\n⚠️ Severity Distribution:")
        for severity, count in stats['severity_distribution'].items():
            print(f"  {severity}: {count:,}")
        
        print(f"\n🏭 Top 5 Vendors:")
        for i, vendor in enumerate(stats['top_vendors'][:5], 1):
            print(f"  {i}. {vendor['display_name']}: {vendor['vulnerability_count']:,} vulns")
        
        print(f"\n📦 Top 5 Products:")
        for i, product in enumerate(stats['top_products'][:5], 1):
            print(f"  {i}. {product['display_name']}: {product['vulnerability_count']:,} vulns")
    
    def build_knowledge_graph(self):
        """Build the complete knowledge graph"""
        logger.info("Starting knowledge graph construction...")
        
        # Load data
        cve_data = self.load_all_cve_data()
        cpe_data = self.load_cpe_data()
        
        if not cve_data:
            logger.error("No CVE data found! Please run the CVE processor first.")
            return
        
        # Build nodes and relationships
        self.build_cve_nodes(cve_data)
        self.build_cwe_nodes()
        self.build_capec_nodes()
        self.build_mitre_nodes()
        self.build_product_vendor_nodes(cpe_data)
        
        # Calculate statistics
        self.calculate_statistics()
        
        # Save everything
        self.save_knowledge_graph()
        
        # Print summary
        self.print_statistics()
        
        logger.info("✅ Knowledge graph construction complete!")
        logger.info(f"📁 Output directory: {self.output_dir}")

def main():
    builder = KnowledgeGraphBuilder()
    builder.build_knowledge_graph()

if __name__ == "__main__":
    main() 