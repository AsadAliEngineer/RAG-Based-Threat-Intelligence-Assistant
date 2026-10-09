#!/usr/bin/env python3
"""
Export Knowledge Graph for RAG System (Without Neo4j)

This script exports the knowledge graph built by kg_builder_without_neo4j.py
into formats suitable for RAG system development, including embeddings-ready
documents and structured data.

Usage:
    python export_kg_for_rag_without_neo4j.py [--cve] [--product_vendor] [--stats] [--full]
"""

import json
import sys
from datetime import datetime
from typing import Dict, List, Any, Set
from pathlib import Path
import logging
from collections import defaultdict

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RAGExporter:
    def __init__(self):
        self.config = Config()
        self.knowledge_base_dir = self.config.knowledge_base_dir
        self.kg_dir = self.knowledge_base_dir / 'knowledge_graph'
        self.export_dir = self.knowledge_base_dir / 'rag_exports'
        self.export_dir.mkdir(exist_ok=True)
        
        # Load knowledge graph
        self.kg_data = self._load_knowledge_graph()
        
    def _load_knowledge_graph(self) -> Dict[str, Any]:
        """Load the complete knowledge graph"""
        graph_file = self.kg_dir / "complete_knowledge_graph.json"
        
        if not graph_file.exists():
            logger.error(f"Knowledge graph file not found: {graph_file}")
            logger.error("Please run kg_builder_without_neo4j.py first to build the knowledge graph.")
            return {}
        
        try:
            with open(graph_file, 'r', encoding='utf-8') as f:
                kg_data = json.load(f)
            logger.info("Knowledge graph loaded successfully")
            return kg_data
        except Exception as e:
            logger.error(f"Error loading knowledge graph: {e}")
            return {}
    
    def export_cve_documents(self) -> List[Dict[str, Any]]:
        """Export CVE data as documents for RAG processing"""
        logger.info("Exporting CVE documents for RAG...")
        
        if not self.kg_data:
            logger.error("No knowledge graph data available")
            return []
        
        nodes = self.kg_data.get('nodes', {})
        relationships = self.kg_data.get('relationships', {})
        
        # Create lookup dictionaries for relationships
        cve_products = defaultdict(list)
        cve_cwes = defaultdict(list)
        cve_capecs = defaultdict(list)
        cve_techniques = defaultdict(list)
        cve_tactics = defaultdict(list)
        
        # Build relationship lookups
        for rel in relationships.get('cve_product', []):
            cve_products[rel['cve_id']].append(rel['product_name'])
        
        for rel in relationships.get('cve_cwe', []):
            cve_cwes[rel['cve_id']].append(rel['cwe_id'])
        
        for rel in relationships.get('cve_capec', []):
            cve_capecs[rel['cve_id']].append(rel['capec_id'])
        
        for rel in relationships.get('cve_mitre_technique', []):
            cve_techniques[rel['cve_id']].append(rel['technique_id'])
        
        for rel in relationships.get('cve_mitre_tactic', []):
            cve_tactics[rel['cve_id']].append(rel['tactic_id'])
        
        documents = []
        for cve_id, cve in nodes.get('cves', {}).items():
            # Get related entities
            related_products = cve_products.get(cve_id, [])
            related_cwes = cve_cwes.get(cve_id, [])
            related_capecs = cve_capecs.get(cve_id, [])
            related_techniques = cve_techniques.get(cve_id, [])
            related_tactics = cve_tactics.get(cve_id, [])
            
            # Create RAG document
            doc = {
                "id": cve_id,
                "title": cve.get("title", ""),
                "description": cve.get("description", ""),
                "source": cve.get("source", ""),
                "published_date": cve.get("published_date", ""),
                "last_modified_date": cve.get("last_modified_date", ""),
                "cvss_v3": cve.get("cvss_v3", {}),
                "cvss_v2": cve.get("cvss_v2", {}),
                "affected_products": cve.get("affected_products", []),
                "related_products": related_products,
                "weaknesses": related_cwes,
                "attack_patterns": related_capecs,
                "mitre_techniques": related_techniques,
                "mitre_tactics": related_tactics,
                "is_in_kev": cve.get("is_in_kev", False),
                "tags": cve.get("tags", []),
                "text_for_embedding": self._create_cve_embedding_text(cve, related_products, 
                                                                     related_cwes, related_capecs,
                                                                     related_techniques, related_tactics),
                "metadata": {
                    "document_type": "CVE",
                    "severity": cve.get("cvss_v3", {}).get("base_severity", "UNKNOWN"),
                    "cvss_score": cve.get("cvss_v3", {}).get("base_score"),
                    "vulnerability_count": 1
                }
            }
            documents.append(doc)
        
        # Save as JSON
        output_file = self.export_dir / "cve_documents_for_rag.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(documents, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(documents)} CVE documents to {output_file}")
        return documents
    
    def _create_cve_embedding_text(self, cve: Dict[str, Any], products: List[str], 
                                  cwes: List[str], capecs: List[str], 
                                  techniques: List[str], tactics: List[str]) -> str:
        """Create text suitable for CVE embedding generation"""
        text_parts = []
        
        # Basic CVE info
        text_parts.append(f"CVE ID: {cve['id']}")
        if cve.get("title"):
            text_parts.append(f"Title: {cve['title']}")
        if cve.get("description"):
            text_parts.append(f"Description: {cve['description']}")
        
        # CVSS information
        cvss_v3 = cve.get("cvss_v3", {})
        if cvss_v3.get("base_severity"):
            text_parts.append(f"Severity: {cvss_v3['base_severity']}")
        if cvss_v3.get("base_score"):
            text_parts.append(f"CVSS v3 Score: {cvss_v3['base_score']}")
        if cvss_v3.get("vector_string"):
            text_parts.append(f"CVSS v3 Vector: {cvss_v3['vector_string']}")
        
        cvss_v2 = cve.get("cvss_v2", {})
        if cvss_v2.get("base_score"):
            text_parts.append(f"CVSS v2 Score: {cvss_v2['base_score']}")
        if cvss_v2.get("vector_string"):
            text_parts.append(f"CVSS v2 Vector: {cvss_v2['vector_string']}")
        
        # Attack vector and complexity
        if cvss_v3.get("attack_vector"):
            text_parts.append(f"Attack Vector: {cvss_v3['attack_vector']}")
        if cvss_v3.get("attack_complexity"):
            text_parts.append(f"Attack Complexity: {cvss_v3['attack_complexity']}")
        
        # Affected products
        affected_products = cve.get("affected_products", [])
        if affected_products:
            text_parts.append(f"Affected Products: {', '.join(affected_products)}")
        
        # Related entities
        if products:
            text_parts.append(f"Related Products: {', '.join(products)}")
        if cwes:
            text_parts.append(f"Common Weaknesses: {', '.join(cwes)}")
        if capecs:
            text_parts.append(f"Attack Patterns: {', '.join(capecs)}")
        if techniques:
            text_parts.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
        if tactics:
            text_parts.append(f"MITRE ATT&CK Tactics: {', '.join(tactics)}")
        
        # Tags
        tags = cve.get("tags", [])
        if tags:
            text_parts.append(f"Tags: {', '.join(tags)}")
        
        return " | ".join(text_parts)
    
    def export_product_vendor_data(self) -> List[Dict[str, Any]]:
        """Export product and vendor data for RAG"""
        logger.info("Exporting product-vendor data for RAG...")
        
        if not self.kg_data:
            logger.error("No knowledge graph data available")
            return []
        
        nodes = self.kg_data.get('nodes', {})
        relationships = self.kg_data.get('relationships', {})
        
        # Create vendor lookup
        vendor_products = defaultdict(list)
        for rel in relationships.get('product_vendor', []):
            vendor_products[rel['vendor_name']].append(rel['product_key'])
        
        products = []
        for product_key, product_data in nodes.get('products', {}).items():
            # Get vendor information
            vendor_name = product_data.get('vendor', '')
            vendor_info = nodes.get('vendors', {}).get(vendor_name, {})
            
            product = {
                "product_key": product_key,
                "product_name": product_data.get("name", ""),
                "vendor": vendor_name,
                "display_name": product_data.get("display_name", ""),
                "category": product_data.get("category", ""),
                "family": product_data.get("family", ""),
                "criticality_score": product_data.get("criticality_score", 0.0),
                "aliases": product_data.get("aliases", []),
                "vulnerability_count": product_data.get("vulnerability_count", 0),
                "versions": product_data.get("versions", []),
                "vendor_info": {
                    "name": vendor_info.get("name", ""),
                    "display_name": vendor_info.get("display_name", ""),
                    "vulnerability_count": vendor_info.get("vulnerability_count", 0),
                    "product_count": vendor_info.get("product_count", 0)
                },
                "text_for_embedding": self._create_product_embedding_text(product_data, vendor_info),
                "metadata": {
                    "document_type": "PRODUCT",
                    "category": product_data.get("category", ""),
                    "family": product_data.get("family", ""),
                    "criticality": product_data.get("criticality_score", 0.0)
                }
            }
            products.append(product)
        
        # Save as JSON
        output_file = self.export_dir / "product_vendor_data.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(products, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(products)} product-vendor records to {output_file}")
        return products
    
    def _create_product_embedding_text(self, product_data: Dict[str, Any], vendor_info: Dict[str, Any]) -> str:
        """Create text suitable for product embedding generation"""
        text_parts = []
        
        text_parts.append(f"Product: {product_data.get('display_name', '')}")
        text_parts.append(f"Vendor: {vendor_info.get('display_name', '')}")
        text_parts.append(f"Category: {product_data.get('category', '')}")
        text_parts.append(f"Family: {product_data.get('family', '')}")
        text_parts.append(f"Criticality Score: {product_data.get('criticality_score', 0.0)}")
        
        if product_data.get("aliases"):
            text_parts.append(f"Aliases: {', '.join(product_data['aliases'])}")
        
        if product_data.get("versions"):
            text_parts.append(f"Versions: {', '.join(product_data['versions'])}")
        
        text_parts.append(f"Vulnerability Count: {product_data.get('vulnerability_count', 0)}")
        
        return " | ".join(text_parts)
    
    def export_threat_intelligence_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Export threat intelligence data (CWE, CAPEC, MITRE) for RAG"""
        logger.info("Exporting threat intelligence data for RAG...")
        
        if not self.kg_data:
            logger.error("No knowledge graph data available")
            return {}
        
        nodes = self.kg_data.get('nodes', {})
        
        threat_data = {
            'cwes': [],
            'capecs': [],
            'mitre_techniques': [],
            'mitre_tactics': []
        }
        
        # Export CWEs
        for cwe_id, cwe_data in nodes.get('cwes', {}).items():
            cwe_doc = {
                "id": cwe_id,
                "name": cwe_data.get("name", ""),
                "vulnerability_count": cwe_data.get("vulnerability_count", 0),
                "text_for_embedding": f"CWE {cwe_id}: {cwe_data.get('name', '')} - {cwe_data.get('vulnerability_count', 0)} vulnerabilities",
                "metadata": {
                    "document_type": "CWE",
                    "vulnerability_count": cwe_data.get("vulnerability_count", 0)
                }
            }
            threat_data['cwes'].append(cwe_doc)
        
        # Export CAPECs
        for capec_id, capec_data in nodes.get('capecs', {}).items():
            capec_doc = {
                "id": capec_id,
                "name": capec_data.get("name", ""),
                "vulnerability_count": capec_data.get("vulnerability_count", 0),
                "text_for_embedding": f"CAPEC {capec_id}: {capec_data.get('name', '')} - {capec_data.get('vulnerability_count', 0)} vulnerabilities",
                "metadata": {
                    "document_type": "CAPEC",
                    "vulnerability_count": capec_data.get("vulnerability_count", 0)
                }
            }
            threat_data['capecs'].append(capec_doc)
        
        # Export MITRE Techniques
        for technique_id, technique_data in nodes.get('mitre_techniques', {}).items():
            technique_doc = {
                "id": technique_id,
                "name": technique_data.get("name", ""),
                "vulnerability_count": technique_data.get("vulnerability_count", 0),
                "text_for_embedding": f"MITRE Technique {technique_id}: {technique_data.get('name', '')} - {technique_data.get('vulnerability_count', 0)} vulnerabilities",
                "metadata": {
                    "document_type": "MITRE_TECHNIQUE",
                    "vulnerability_count": technique_data.get("vulnerability_count", 0)
                }
            }
            threat_data['mitre_techniques'].append(technique_doc)
        
        # Export MITRE Tactics
        for tactic_id, tactic_data in nodes.get('mitre_tactics', {}).items():
            tactic_doc = {
                "id": tactic_id,
                "name": tactic_data.get("name", ""),
                "vulnerability_count": tactic_data.get("vulnerability_count", 0),
                "text_for_embedding": f"MITRE Tactic {tactic_id}: {tactic_data.get('name', '')} - {tactic_data.get('vulnerability_count', 0)} vulnerabilities",
                "metadata": {
                    "document_type": "MITRE_TACTIC",
                    "vulnerability_count": tactic_data.get("vulnerability_count", 0)
                }
            }
            threat_data['mitre_tactics'].append(tactic_doc)
        
        # Save each type separately
        for threat_type, documents in threat_data.items():
            output_file = self.export_dir / f"{threat_type}_data.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, indent=2, ensure_ascii=False)
            logger.info(f"Exported {len(documents)} {threat_type} documents to {output_file}")
        
        return threat_data
    
    def export_statistics(self) -> Dict[str, Any]:
        """Export comprehensive statistics about the RAG-ready data"""
        logger.info("Exporting RAG data statistics...")
        
        if not self.kg_data:
            logger.error("No knowledge graph data available")
            return {}
        
        stats = self.kg_data.get('statistics', {})
        
        # Add RAG-specific statistics
        rag_stats = {
            "export_timestamp": datetime.now().isoformat(),
            "knowledge_graph_stats": stats,
            "rag_export_info": {
                "export_directory": str(self.export_dir),
                "document_types": ["CVE", "PRODUCT", "CWE", "CAPEC", "MITRE_TECHNIQUE", "MITRE_TACTIC"],
                "embedding_ready": True,
                "structured_data": True
            }
        }
        
        # Save statistics
        stats_file = self.export_dir / "rag_export_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(rag_stats, f, indent=2, ensure_ascii=False)
        
        # Print summary
        print("\n📊 RAG Export Statistics:")
        print("=" * 50)
        print(f"📁 Export Directory: {self.export_dir}")
        print(f"📈 Knowledge Graph Nodes: {stats.get('node_counts', {}).get('cves', 0):,} CVEs")
        print(f"🏭 Products: {stats.get('node_counts', {}).get('products', 0):,}")
        print(f"🏢 Vendors: {stats.get('node_counts', {}).get('vendors', 0):,}")
        print(f"🔍 Threat Intelligence:")
        print(f"   - CWEs: {stats.get('node_counts', {}).get('cwes', 0):,}")
        print(f"   - CAPECs: {stats.get('node_counts', {}).get('capecs', 0):,}")
        print(f"   - MITRE Techniques: {stats.get('node_counts', {}).get('mitre_techniques', 0):,}")
        print(f"   - MITRE Tactics: {stats.get('node_counts', {}).get('mitre_tactics', 0):,}")
        
        logger.info(f"Statistics exported to {stats_file}")
        return rag_stats
    
    def run_full_export(self):
        """Run complete export of all data types for RAG"""
        logger.info("Starting full RAG export...")
        
        if not self.kg_data:
            logger.error("No knowledge graph data available. Please run kg_builder_without_neo4j.py first.")
            return
        
        # Export all data types
        cve_docs = self.export_cve_documents()
        product_data = self.export_product_vendor_data()
        threat_data = self.export_threat_intelligence_data()
        stats = self.export_statistics()
        
        # Create export summary
        summary = {
            "export_timestamp": datetime.now().isoformat(),
            "export_summary": {
                "cve_documents": len(cve_docs),
                "product_records": len(product_data),
                "cwe_records": len(threat_data.get('cwes', [])),
                "capec_records": len(threat_data.get('capecs', [])),
                "mitre_technique_records": len(threat_data.get('mitre_techniques', [])),
                "mitre_tactic_records": len(threat_data.get('mitre_tactics', [])),
                "export_directory": str(self.export_dir)
            },
            "files_created": [
                "cve_documents_for_rag.json",
                "product_vendor_data.json",
                "cwes_data.json",
                "capecs_data.json", 
                "mitre_techniques_data.json",
                "mitre_tactics_data.json",
                "rag_export_statistics.json"
            ]
        }
        
        # Save summary
        summary_file = self.export_dir / "rag_export_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info("✅ Full RAG export complete!")
        logger.info(f"📁 Export directory: {self.export_dir}")
        logger.info(f"📄 Files created: {len(summary['files_created'])}")
        
        return summary

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="RAG Exporter (Without Neo4j)")
    parser.add_argument("--cve", action="store_true", help="Export CVE documents")
    parser.add_argument("--product_vendor", action="store_true", help="Export product-vendor data")
    parser.add_argument("--threat_intelligence", action="store_true", help="Export threat intelligence data")
    parser.add_argument("--stats", action="store_true", help="Export statistics")
    parser.add_argument("--full", action="store_true", help="Run full export (all)")
    
    args = parser.parse_args()
    
    exporter = RAGExporter()
    
    try:
        if args.full:
            exporter.run_full_export()
        elif args.cve:
            exporter.export_cve_documents()
        elif args.product_vendor:
            exporter.export_product_vendor_data()
        elif args.threat_intelligence:
            exporter.export_threat_intelligence_data()
        elif args.stats:
            exporter.export_statistics()
        else:
            print("No export type specified. Use --cve, --product_vendor, --threat_intelligence, --stats, or --full")
            parser.print_help()
            
    except Exception as e:
        logger.error(f"Error during export: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 