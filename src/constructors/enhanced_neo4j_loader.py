#!/usr/bin/env python3
"""
Enhanced Neo4j Knowledge Graph Loader
Loads CVE data from processed documents and CPE parsing results into Neo4j.
"""

import sys
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase
import logging

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedNeo4jLoader:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.cve_data = {}
        self.cpe_data = {}
        
    def close(self):
        self.driver.close()
        
    def load_cve_data(self, cve_file_path: str):
        """Load processed CVE data"""
        logger.info(f"Loading CVE data from {cve_file_path}")
        
        with open(cve_file_path, 'r', encoding='utf-8') as f:
            cve_documents = json.load(f)
            
        for doc in cve_documents:
            cve_id = doc['id']
            self.cve_data[cve_id] = doc
            
        logger.info(f"Loaded {len(self.cve_data)} CVE documents")
        
    def load_cpe_data(self, cpe_file_path: str):
        """Load CPE parsing results"""
        logger.info(f"Loading CPE data from {cpe_file_path}")
        
        with open(cpe_file_path, 'r', encoding='utf-8') as f:
            self.cpe_data = json.load(f)
            
        logger.info(f"Loaded CPE data for {len(self.cpe_data.get('products', {}))} products")
        
    def create_cve_node(self, cve_id: str, cve_doc: Dict[str, Any]):
        """Create a CVE node with rich metadata"""
        with self.driver.session() as session:
            # Extract CVSS metrics
            cvss_v3 = cve_doc.get('cvss_v3', {})
            
            # Create CVE node with all available metadata
            query = """
            MERGE (cve:CVE {id: $cve_id})
            SET cve.title = $title,
                cve.description = $description,
                cve.source = $source,
                cve.published_date = $published_date,
                cve.modified_date = $modified_date,
                cve.cvss_v3_base_score = $cvss_base_score,
                cve.cvss_v3_vector = $cvss_vector,
                cve.cvss_v3_severity = $cvss_severity,
                cve.attack_vector = $attack_vector,
                cve.attack_complexity = $attack_complexity,
                cve.privileges_required = $privileges_required,
                cve.user_interaction = $user_interaction,
                cve.scope = $scope,
                cve.confidentiality_impact = $confidentiality_impact,
                cve.integrity_impact = $integrity_impact,
                cve.availability_impact = $availability_impact,
                cve.cwe_refs = $cwe_refs,
                cve.capec_refs = $capec_refs,
                cve.affected_products = $affected_products
            """
            
            session.run(query, {
                'cve_id': cve_id,
                'title': cve_doc.get('title', ''),
                'description': cve_doc.get('content', ''),
                'source': cve_doc.get('source', ''),
                'published_date': cve_doc.get('published_date', ''),
                'modified_date': cve_doc.get('modified_date', ''),
                'cvss_base_score': cvss_v3.get('base_score'),
                'cvss_vector': cvss_v3.get('vector_string', ''),
                'cvss_severity': cvss_v3.get('base_severity', ''),
                'attack_vector': cvss_v3.get('attack_vector', ''),
                'attack_complexity': cvss_v3.get('attack_complexity', ''),
                'privileges_required': cvss_v3.get('privileges_required', ''),
                'user_interaction': cvss_v3.get('user_interaction', ''),
                'scope': cvss_v3.get('scope', ''),
                'confidentiality_impact': cvss_v3.get('confidentiality_impact', ''),
                'integrity_impact': cvss_v3.get('integrity_impact', ''),
                'availability_impact': cvss_v3.get('availability_impact', ''),
                'cwe_refs': cve_doc.get('cwe_refs', []),
                'capec_refs': cve_doc.get('capec_refs', []),
                'affected_products': cve_doc.get('affected_products', [])
            })
            
    def create_cwe_nodes(self, cve_id: str, cwe_refs: List[str]):
        """Create CWE nodes and relationships"""
        with self.driver.session() as session:
            for cwe_id in cwe_refs:
                # Create CWE node
                session.run("""
                    MERGE (cwe:CWE {id: $cwe_id})
                """, {'cwe_id': cwe_id})
                
                # Create relationship
                session.run("""
                    MATCH (cve:CVE {id: $cve_id})
                    MATCH (cwe:CWE {id: $cwe_id})
                    MERGE (cve)-[:HAS_WEAKNESS]->(cwe)
                """, {'cve_id': cve_id, 'cwe_id': cwe_id})
                
    def create_capec_nodes(self, cve_id: str, capec_refs: List[str]):
        """Create CAPEC nodes and relationships"""
        with self.driver.session() as session:
            for capec_id in capec_refs:
                # Create CAPEC node
                session.run("""
                    MERGE (capec:CAPEC {id: $capec_id})
                """, {'capec_id': capec_id})
                
                # Create relationship
                session.run("""
                    MATCH (cve:CVE {id: $cve_id})
                    MATCH (capec:CAPEC {id: $capec_id})
                    MERGE (cve)-[:HAS_ATTACK_PATTERN]->(capec)
                """, {'cve_id': cve_id, 'capec_id': capec_id})
                
    def create_product_vendor_nodes(self, product_key: str, product_data: Dict[str, Any]):
        """Create Product and Vendor nodes from CPE data"""
        with self.driver.session() as session:
            vendor_name = product_data.get('vendor', '')
            product_name = product_data.get('product', '')
            
            # Create Vendor node
            session.run("""
                MERGE (vendor:Vendor {name: $vendor_name})
            """, {'vendor_name': vendor_name})
            
            # Create Product node
            session.run("""
                MERGE (product:Product {name: $product_name, vendor: $vendor_name})
                SET product.display_name = $display_name,
                    product.category = $category,
                    product.family = $family,
                    product.criticality_score = $criticality_score
            """, {
                'product_name': product_name,
                'vendor_name': vendor_name,
                'display_name': product_data.get('display_name', ''),
                'category': product_data.get('category', ''),
                'family': product_data.get('family', ''),
                'criticality_score': product_data.get('criticality_score', 0.0)
            })
            
            # Create relationship
            session.run("""
                MATCH (product:Product {name: $product_name, vendor: $vendor_name})
                MATCH (vendor:Vendor {name: $vendor_name})
                MERGE (product)-[:MANUFACTURED_BY]->(vendor)
            """, {'product_name': product_name, 'vendor_name': vendor_name})
            
            # Create version nodes
            versions = product_data.get('versions', {})
            for version_key, version_data in versions.items():
                if version_key != '*':  # Skip wildcard versions
                    session.run("""
                        MERGE (version:Version {version: $version, product: $product_name})
                        SET version.version_type = $version_type,
                            version.raw = $raw_version
                    """, {
                        'version': version_key,
                        'product_name': product_name,
                        'version_type': version_data.get('version_info', {}).get('type', ''),
                        'raw_version': version_data.get('version_info', {}).get('raw', '')
                    })
                    
                    # Create relationship
                    session.run("""
                        MATCH (product:Product {name: $product_name, vendor: $vendor_name})
                        MATCH (version:Version {version: $version, product: $product_name})
                        MERGE (product)-[:HAS_VERSION]->(version)
                    """, {
                        'product_name': product_name,
                        'vendor_name': vendor_name,
                        'version': version_key
                    })
                    
    def create_cve_product_relationships(self, cve_id: str, affected_products: List[str]):
        """Create relationships between CVEs and affected products"""
        with self.driver.session() as session:
            for product_name in affected_products:
                # Find matching products in CPE data
                for product_key, product_data in self.cpe_data.get('products', {}).items():
                    if product_data.get('product', '').lower() == product_name.lower():
                        session.run("""
                            MATCH (cve:CVE {id: $cve_id})
                            MATCH (product:Product {name: $product_name, vendor: $vendor_name})
                            MERGE (cve)-[:AFFECTS]->(product)
                        """, {
                            'cve_id': cve_id,
                            'product_name': product_data.get('product', ''),
                            'vendor_name': product_data.get('vendor', '')
                        })
                        break
                        
    def load_knowledge_graph(self, limit: Optional[int] = None):
        """Load the complete knowledge graph"""
        logger.info("Starting enhanced knowledge graph loading...")
        
        # Process CVE data
        cve_count = 0
        for cve_id, cve_doc in self.cve_data.items():
            if limit and cve_count >= limit:
                break
                
            try:
                logger.info(f"Processing CVE: {cve_id}")
                
                # Create CVE node with rich metadata
                self.create_cve_node(cve_id, cve_doc)
                
                # Create CWE nodes and relationships
                cwe_refs = cve_doc.get('cwe_refs', [])
                if cwe_refs:
                    self.create_cwe_nodes(cve_id, cwe_refs)
                    
                # Create CAPEC nodes and relationships
                capec_refs = cve_doc.get('capec_refs', [])
                if capec_refs:
                    self.create_capec_nodes(cve_id, capec_refs)
                    
                # Create relationships to affected products
                affected_products = cve_doc.get('affected_products', [])
                if affected_products:
                    self.create_cve_product_relationships(cve_id, affected_products)
                    
                cve_count += 1
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve_id}: {e}")
                continue
                
        # Process CPE data (products and vendors)
        product_count = 0
        for product_key, product_data in self.cpe_data.get('products', {}).items():
            try:
                self.create_product_vendor_nodes(product_key, product_data)
                product_count += 1
            except Exception as e:
                logger.error(f"Error processing product {product_key}: {e}")
                continue
                
        logger.info(f"✅ Enhanced knowledge graph loading complete!")
        logger.info(f"   - CVEs processed: {cve_count}")
        logger.info(f"   - Products processed: {product_count}")
        
    def get_graph_stats(self):
        """Get basic statistics about the loaded graph"""
        with self.driver.session() as session:
            # Node counts
            node_stats = session.run("""
                MATCH (n)
                RETURN labels(n) as NodeType, count(n) as Count
                ORDER BY Count DESC
            """)
            
            print("\n📊 Enhanced Knowledge Graph Statistics:")
            print("=" * 50)
            print("\n📈 Node Counts:")
            for record in node_stats:
                node_type = record['NodeType'][0] if record['NodeType'] else 'Unknown'
                print(f"  {node_type}: {record['Count']:,}")
                
            # Relationship counts
            rel_stats = session.run("""
                MATCH ()-[r]->()
                RETURN type(r) as RelationshipType, count(r) as Count
                ORDER BY Count DESC
            """)
            
            print("\n🔗 Relationship Counts:")
            for record in rel_stats:
                print(f"  {record['RelationshipType']}: {record['Count']:,}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Neo4j Knowledge Graph Loader")
    parser.add_argument("--cve-file", 
                       default="../../data/knowledge_base/enhanced_documents_cve_2024.json",
                       help="Path to processed CVE data file")
    parser.add_argument("--cpe-file",
                       default="../../data/knowledge_base/cpe_parsing_results_full.json", 
                       help="Path to CPE parsing results file")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="password", help="Neo4j password")
    parser.add_argument("--limit", type=int, help="Limit number of CVEs to process")
    parser.add_argument("--stats", action="store_true", help="Show graph statistics after loading")
    
    args = parser.parse_args()
    
    loader = EnhancedNeo4jLoader(args.uri, args.user, args.password)
    
    try:
        # Load data files
        loader.load_cve_data(args.cve_file)
        loader.load_cpe_data(args.cpe_file)
        
        # Load knowledge graph
        loader.load_knowledge_graph(args.limit)
        
        # Show statistics if requested
        if args.stats:
            loader.get_graph_stats()
            
    except Exception as e:
        logger.error(f"Error during loading: {e}")
    finally:
        loader.close()

if __name__ == "__main__":
    main() 