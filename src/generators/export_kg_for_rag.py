#!/usr/bin/env python3
"""
Export Knowledge Graph Data for RAG System Development

This script exports CVE data from Neo4j in formats suitable for:
- Vector database ingestion
- Document processing
- RAG pipeline development
"""

import json
import csv
import os
from datetime import datetime
from neo4j import GraphDatabase
from typing import List, Dict, Any

class KGExporter:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.export_dir = "../../data/knowledge_graph/exports"
        os.makedirs(self.export_dir, exist_ok=True)
        
    def close(self):
        self.driver.close()
        
    def export_cve_documents(self):
        """Export CVE data as documents for RAG processing"""
        print("Exporting CVE documents for RAG...")
        
        with self.driver.session() as session:
            # Get all CVEs with their metadata
            result = session.run("""
                MATCH (cve:CVE)
                OPTIONAL MATCH (cve)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
                OPTIONAL MATCH (cve)-[:HAS_WEAKNESS]->(cwe:CWE)
                OPTIONAL MATCH (cve)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
                RETURN DISTINCT cve, 
                       collect(DISTINCT product.name) as products,
                       collect(DISTINCT vendor.name) as vendors,
                       collect(DISTINCT cwe.id) as cwes,
                       collect(DISTINCT capec.id) as capecs
                ORDER BY cve.id
            """)
            
            documents = []
            for record in result:
                cve = record["cve"]
                doc = {
                    "id": cve["id"],
                    "title": cve.get("title", ""),
                    "description": cve.get("description", ""),
                    "cvss_v3_base_score": cve.get("cvss_v3_base_score"),
                    "cvss_v3_severity": cve.get("cvss_v3_severity"),
                    "attack_vector": cve.get("attack_vector"),
                    "attack_complexity": cve.get("attack_complexity"),
                    "privileges_required": cve.get("privileges_required"),
                    "user_interaction": cve.get("user_interaction"),
                    "scope": cve.get("scope"),
                    "confidentiality_impact": cve.get("confidentiality_impact"),
                    "integrity_impact": cve.get("integrity_impact"),
                    "availability_impact": cve.get("availability_impact"),
                    "affected_products": record["products"],
                    "affected_vendors": record["vendors"],
                    "weaknesses": record["cwes"],
                    "attack_patterns": record["capecs"],
                    "text_for_embedding": self._create_embedding_text(cve, record)
                }
                documents.append(doc)
            
            # Save as JSON
            output_file = os.path.join(self.export_dir, "cve_documents_for_rag.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, indent=2, ensure_ascii=False)
            
            print(f"Exported {len(documents)} CVE documents to {output_file}")
            return documents
    
    def _create_embedding_text(self, cve: Dict, record: Any) -> str:
        """Create text suitable for embedding generation"""
        text_parts = []
        
        # Basic CVE info
        text_parts.append(f"CVE ID: {cve['id']}")
        if cve.get("title"):
            text_parts.append(f"Title: {cve['title']}")
        if cve.get("description"):
            text_parts.append(f"Description: {cve['description']}")
        
        # CVSS information
        if cve.get("cvss_v3_severity"):
            text_parts.append(f"Severity: {cve['cvss_v3_severity']}")
        if cve.get("cvss_v3_base_score"):
            text_parts.append(f"CVSS Score: {cve['cvss_v3_base_score']}")
        
        # Attack vector and complexity
        if cve.get("attack_vector"):
            text_parts.append(f"Attack Vector: {cve['attack_vector']}")
        if cve.get("attack_complexity"):
            text_parts.append(f"Attack Complexity: {cve['attack_complexity']}")
        
        # Affected products and vendors
        if record["products"]:
            text_parts.append(f"Affected Products: {', '.join(record['products'])}")
        if record["vendors"]:
            text_parts.append(f"Affected Vendors: {', '.join(record['vendors'])}")
        
        # Weaknesses and attack patterns
        if record["cwes"]:
            text_parts.append(f"Common Weaknesses: {', '.join(record['cwes'])}")
        if record["capecs"]:
            text_parts.append(f"Attack Patterns: {', '.join(record['capecs'])}")
        
        return " | ".join(text_parts)
    
    def export_product_vendor_data(self):
        """Export product and vendor relationships"""
        print("Exporting product-vendor data...")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
                OPTIONAL MATCH (product)-[:HAS_VERSION]->(version:Version)
                RETURN product.name as product_name,
                       product.category as category,
                       product.family as family,
                       product.criticality_score as criticality,
                       vendor.name as vendor_name,
                       collect(DISTINCT version.version) as versions
            """)
            
            products = []
            for record in result:
                product = {
                    "product_name": record["product_name"],
                    "category": record["category"],
                    "family": record["family"],
                    "criticality_score": record["criticality"],
                    "vendor_name": record["vendor_name"],
                    "versions": record["versions"]
                }
                products.append(product)
            
            # Save as JSON
            output_file = os.path.join(self.export_dir, "product_vendor_data.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(products, f, indent=2, ensure_ascii=False)
            
            print(f"Exported {len(products)} product-vendor records to {output_file}")
            return products
    
    def export_relationships(self):
        """Export relationship data for graph analysis"""
        print("Exporting relationship data...")
        
        relationships = {
            "cve_product": [],
            "cve_cwe": [],
            "cve_capec": [],
            "product_vendor": []
        }
        
        with self.driver.session() as session:
            # CVE-Product relationships
            result = session.run("""
                MATCH (cve:CVE)-[:AFFECTS]->(product:Product)
                RETURN cve.id as cve_id, product.name as product_name
            """)
            for record in result:
                relationships["cve_product"].append({
                    "cve_id": record["cve_id"],
                    "product_name": record["product_name"]
                })
            
            # CVE-CWE relationships
            result = session.run("""
                MATCH (cve:CVE)-[:HAS_WEAKNESS]->(cwe:CWE)
                RETURN cve.id as cve_id, cwe.id as cwe_id
            """)
            for record in result:
                relationships["cve_cwe"].append({
                    "cve_id": record["cve_id"],
                    "cwe_id": record["cwe_id"]
                })
            
            # CVE-CAPEC relationships
            result = session.run("""
                MATCH (cve:CVE)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
                RETURN cve.id as cve_id, capec.id as capec_id
            """)
            for record in result:
                relationships["cve_capec"].append({
                    "cve_id": record["cve_id"],
                    "capec_id": record["capec_id"]
                })
            
            # Product-Vendor relationships
            result = session.run("""
                MATCH (product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
                RETURN product.name as product_name, vendor.name as vendor_name
            """)
            for record in result:
                relationships["product_vendor"].append({
                    "product_name": record["product_name"],
                    "vendor_name": record["vendor_name"]
                })
        
        # Save as JSON
        output_file = os.path.join(self.export_dir, "relationships.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(relationships, f, indent=2, ensure_ascii=False)
        
        print(f"Exported relationship data to {output_file}")
        print(f"   - CVE-Product: {len(relationships['cve_product'])} relationships")
        print(f"   - CVE-CWE: {len(relationships['cve_cwe'])} relationships")
        print(f"   - CVE-CAPEC: {len(relationships['cve_capec'])} relationships")
        print(f"   - Product-Vendor: {len(relationships['product_vendor'])} relationships")
        
        return relationships
    
    def export_statistics(self):
        """Export current graph statistics"""
        print("Exporting graph statistics...")
        
        with self.driver.session() as session:
            stats = {}
            
            # Node counts
            result = session.run("MATCH (n:CVE) RETURN count(n) as count")
            record = result.single()
            stats["cve_count"] = record["count"] if record else 0
            
            result = session.run("MATCH (n:Product) RETURN count(n) as count")
            record = result.single()
            stats["product_count"] = record["count"] if record else 0
            
            result = session.run("MATCH (n:Vendor) RETURN count(n) as count")
            record = result.single()
            stats["vendor_count"] = record["count"] if record else 0
            
            result = session.run("MATCH (n:CWE) RETURN count(n) as count")
            record = result.single()
            stats["cwe_count"] = record["count"] if record else 0
            
            result = session.run("MATCH (n:CAPEC) RETURN count(n) as count")
            record = result.single()
            stats["capec_count"] = record["count"] if record else 0
            
            # Relationship counts
            result = session.run("MATCH ()-[r:AFFECTS]->() RETURN count(r) as count")
            record = result.single()
            stats["affects_relationships"] = record["count"] if record else 0
            
            result = session.run("MATCH ()-[r:HAS_WEAKNESS]->() RETURN count(r) as count")
            record = result.single()
            stats["weakness_relationships"] = record["count"] if record else 0
            
            result = session.run("MATCH ()-[r:HAS_ATTACK_PATTERN]->() RETURN count(r) as count")
            record = result.single()
            stats["attack_pattern_relationships"] = record["count"] if record else 0
            
            # Add export timestamp
            stats["export_timestamp"] = datetime.now().isoformat()
            stats["export_purpose"] = "RAG System Development"
        
        # Save as JSON
        output_file = os.path.join(self.export_dir, "graph_statistics.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print(f"Exported graph statistics to {output_file}")
        return stats
    
    def run_full_export(self):
        """Run complete export for RAG development"""
        print("Starting Knowledge Graph Export for RAG Development")
        print("=" * 60)
        
        try:
            # Export all data types
            cve_docs = self.export_cve_documents()
            product_data = self.export_product_vendor_data()
            relationships = self.export_relationships()
            statistics = self.export_statistics()
            
            # Create export summary
            summary = {
                "export_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "purpose": "RAG System Development",
                    "files_created": [
                        "cve_documents_for_rag.json",
                        "product_vendor_data.json", 
                        "relationships.json",
                        "graph_statistics.json"
                    ],
                    "data_counts": {
                        "cve_documents": len(cve_docs),
                        "product_vendor_records": len(product_data),
                        "total_relationships": sum(len(rel) for rel in relationships.values())
                    }
                }
            }
            
            # Save summary
            summary_file = os.path.join(self.export_dir, "export_summary.json")
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            
            print("\n" + "=" * 60)
            print("Knowledge Graph Export Complete!")
            print(f"Export directory: {self.export_dir}")
            print(f"Files created: {len(summary['export_summary']['files_created'])}")
            print(f"CVE documents: {len(cve_docs)}")
            print(f"Product-vendor records: {len(product_data)}")
            print(f"Total relationships: {summary['export_summary']['data_counts']['total_relationships']}")
            print("\n Ready for RAG System Development!")
            
        except Exception as e:
            print(f"Export failed: {e}")
            raise
        finally:
            self.close()

def main():
    """Main function to run the export"""
    exporter = KGExporter()
    exporter.run_full_export()

if __name__ == "__main__":
    main() 
