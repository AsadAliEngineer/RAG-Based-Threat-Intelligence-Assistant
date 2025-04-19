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
from src.constructors.kg_builder import (
    create_cve_node,
    create_cwe_nodes,
    create_capec_nodes,
    create_product_vendor_nodes,
    create_cve_product_relationships
)
from config import Config

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
            create_cve_node(session, cve_id, cve_doc)
            
    def create_cwe_nodes(self, cve_id: str, cwe_refs: List[str]):
        """Create CWE nodes and relationships"""
        with self.driver.session() as session:
            create_cwe_nodes(session, cve_id, cwe_refs)
                
    def create_capec_nodes(self, cve_id: str, capec_refs: List[str]):
        """Create CAPEC nodes and relationships"""
        with self.driver.session() as session:
            create_capec_nodes(session, cve_id, capec_refs)
                
    def create_product_vendor_nodes(self, product_key: str, product_data: Dict[str, Any]):
        """Create Product and Vendor nodes from CPE data"""
        with self.driver.session() as session:
            create_product_vendor_nodes(session, product_key, product_data)
            
    def create_cve_product_relationships(self, cve_id: str, affected_products: List[str]):
        """Create relationships between CVEs and affected products"""
        with self.driver.session() as session:
            create_cve_product_relationships(session, cve_id, affected_products)
                
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
    config = Config()
    parser.add_argument("--cve-file", 
                       default=str(config.enhanced_documents_path),
                       help="Path to processed CVE data file (default: knowledge_base/enhanced_documents_cve_2024.json)")
    parser.add_argument("--cpe-file",
                       default=str(config.knowledge_base_dir / 'cpe_parsing_results_full.json'),
                       help="Path to CPE parsing results file (default: knowledge_base/cpe_parsing_results_full.json)")
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