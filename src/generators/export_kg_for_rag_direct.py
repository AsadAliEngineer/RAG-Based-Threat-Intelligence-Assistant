#!/usr/bin/env python3
"""
Export Knowledge Graph Data for RAG System Development (Direct from Files)

This script exports data directly from processed CVE files and CPE extraction results
without requiring Neo4j, making it suitable for RAG system development.

Usage examples:
  Export CVE documents:
    python -m src.generators.export_kg_for_rag_direct --cve
  Export product-vendor data:
    python -m src.generators.export_kg_for_rag_direct --product_vendor
  Export statistics:
    python -m src.generators.export_kg_for_rag_direct --stats
  Run full export (all):
    python -m src.generators.export_kg_for_rag_direct --full
"""

import json
import csv
import os
import sys
from datetime import datetime
from typing import List, Dict, Any
import logging
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DirectKGExporter:
    def __init__(self):
        self.config = Config()
        self.knowledge_base_dir = self.config.knowledge_base_dir
        self.export_dir = self.knowledge_base_dir / 'rag_exports'
        self.export_dir.mkdir(exist_ok=True)
        
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
    
    def export_cve_documents(self) -> List[Dict[str, Any]]:
        """Export CVE data as documents for RAG processing"""
        logger.info("Exporting CVE documents for RAG...")
        
        cve_data = self.load_all_cve_data()
        documents = []
        
        for cve in cve_data:
            doc = {
                "id": cve["id"],
                "title": cve.get("title", ""),
                "description": cve.get("content", ""),
                "source": cve.get("source", ""),
                "published_date": cve.get("published_date", ""),
                "last_modified_date": cve.get("last_modified_date", ""),
                "cvss_v3": cve.get("cvss_v3", {}),
                "cvss_v2": cve.get("cvss_v2", {}),
                "affected_products": cve.get("affected_products", []),
                "cwe_refs": cve.get("cwe_refs", []),
                "capec_entries": cve.get("capec_entries", []),
                "mitre_techniques": cve.get("mitre_techniques", []),
                "mitre_tactics": cve.get("mitre_tactics", []),
                "cpe_configurations": cve.get("cpe_configurations", []),
                "is_in_kev": cve.get("is_in_kev", False),
                "tags": cve.get("tags", []),
                "text_for_embedding": self._create_embedding_text(cve)
            }
            documents.append(doc)
        
        # Save as JSON
        output_file = self.export_dir / "cve_documents_for_rag.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(documents, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(documents)} CVE documents to {output_file}")
        return documents
    
    def _create_embedding_text(self, cve: Dict[str, Any]) -> str:
        """Create text suitable for embedding generation"""
        text_parts = []
        
        # Basic CVE info
        text_parts.append(f"CVE ID: {cve['id']}")
        if cve.get("title"):
            text_parts.append(f"Title: {cve['title']}")
        if cve.get("content"):
            text_parts.append(f"Description: {cve['content']}")
        
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
        
        # Weaknesses and attack patterns
        cwe_refs = cve.get("cwe_refs", [])
        if cwe_refs:
            text_parts.append(f"Common Weaknesses: {', '.join(cwe_refs)}")
        
        capec_entries = cve.get("capec_entries", [])
        if capec_entries:
            text_parts.append(f"Attack Patterns: {', '.join(capec_entries)}")
        
        mitre_techniques = cve.get("mitre_techniques", [])
        if mitre_techniques:
            text_parts.append(f"MITRE ATT&CK Techniques: {', '.join(mitre_techniques)}")
        
        mitre_tactics = cve.get("mitre_tactics", [])
        if mitre_tactics:
            text_parts.append(f"MITRE ATT&CK Tactics: {', '.join(mitre_tactics)}")
        
        # Tags
        tags = cve.get("tags", [])
        if tags:
            text_parts.append(f"Tags: {', '.join(tags)}")
        
        return " | ".join(text_parts)
    
    def export_product_vendor_data(self) -> List[Dict[str, Any]]:
        """Export product and vendor relationships"""
        logger.info("Exporting product-vendor data...")
        
        cpe_data = self.load_cpe_data()
        products = []
        
        for product_key, product_data in cpe_data.get('products', {}).items():
            product = {
                "product_key": product_key,
                "product_name": product_data.get("product", ""),
                "vendor": product_data.get("vendor", ""),
                "display_name": product_data.get("display_name", ""),
                "category": product_data.get("category", ""),
                "family": product_data.get("family", ""),
                "criticality_score": product_data.get("criticality_score", 0.0),
                "aliases": product_data.get("aliases", []),
                "vulnerability_count": product_data.get("vulnerability_count", 0),
                "versions": list(product_data.get("versions", {}).keys()),
                "text_for_embedding": self._create_product_embedding_text(product_data)
            }
            products.append(product)
        
        # Save as JSON
        output_file = self.export_dir / "product_vendor_data.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(products, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(products)} product-vendor records to {output_file}")
        return products
    
    def _create_product_embedding_text(self, product_data: Dict[str, Any]) -> str:
        """Create text suitable for product embedding generation"""
        text_parts = []
        
        text_parts.append(f"Product: {product_data.get('display_name', '')}")
        text_parts.append(f"Vendor: {product_data.get('vendor', '')}")
        text_parts.append(f"Category: {product_data.get('category', '')}")
        text_parts.append(f"Family: {product_data.get('family', '')}")
        
        if product_data.get("aliases"):
            text_parts.append(f"Aliases: {', '.join(product_data['aliases'])}")
        
        if product_data.get("versions"):
            text_parts.append(f"Versions: {', '.join(list(product_data['versions'].keys()))}")
        
        return " | ".join(text_parts)
    
    def export_statistics(self) -> Dict[str, Any]:
        """Export comprehensive statistics about the knowledge graph"""
        logger.info("Exporting knowledge graph statistics...")
        
        cve_data = self.load_all_cve_data()
        cpe_data = self.load_cpe_data()
        
        # CVE statistics
        total_cves = len(cve_data)
        cves_with_cvss_v3 = sum(1 for cve in cve_data if cve.get("cvss_v3", {}).get("base_score"))
        cves_with_cvss_v2 = sum(1 for cve in cve_data if cve.get("cvss_v2", {}).get("base_score"))
        cves_in_kev = sum(1 for cve in cve_data if cve.get("is_in_kev", False))
        
        # Severity distribution
        severity_counts = {}
        for cve in cve_data:
            severity = cve.get("cvss_v3", {}).get("base_severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Product statistics
        total_products = len(cpe_data.get('products', {}))
        total_vendors = len(cpe_data.get('vendors', {}))
        
        # CWE and CAPEC statistics
        all_cwes = set()
        all_capecs = set()
        all_mitre_techniques = set()
        all_mitre_tactics = set()
        
        for cve in cve_data:
            all_cwes.update(cve.get("cwe_refs", []))
            all_capecs.update(cve.get("capec_entries", []))
            all_mitre_techniques.update(cve.get("mitre_techniques", []))
            all_mitre_tactics.update(cve.get("mitre_tactics", []))
        
        stats = {
            "export_timestamp": datetime.now().isoformat(),
            "cve_statistics": {
                "total_cves": total_cves,
                "cves_with_cvss_v3": cves_with_cvss_v3,
                "cves_with_cvss_v2": cves_with_cvss_v2,
                "cves_in_kev": cves_in_kev,
                "severity_distribution": severity_counts
            },
            "product_statistics": {
                "total_products": total_products,
                "total_vendors": total_vendors
            },
            "threat_intelligence": {
                "unique_cwes": len(all_cwes),
                "unique_capecs": len(all_capecs),
                "unique_mitre_techniques": len(all_mitre_techniques),
                "unique_mitre_tactics": len(all_mitre_tactics)
            },
            "sample_data": {
                "sample_cwes": list(all_cwes)[:10],
                "sample_capecs": list(all_capecs)[:10],
                "sample_mitre_techniques": list(all_mitre_techniques)[:10],
                "sample_mitre_tactics": list(all_mitre_tactics)[:10]
            }
        }
        
        # Save as JSON
        output_file = self.export_dir / "knowledge_graph_statistics.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        # Print summary
        print("\n📊 Knowledge Graph Statistics:")
        print("=" * 50)
        print(f"📈 CVEs: {total_cves:,}")
        print(f"   - With CVSS v3: {cves_with_cvss_v3:,}")
        print(f"   - With CVSS v2: {cves_with_cvss_v2:,}")
        print(f"   - In KEV: {cves_in_kev:,}")
        print(f"🏭 Products: {total_products:,}")
        print(f"🏢 Vendors: {total_vendors:,}")
        print(f"🔍 Threat Intelligence:")
        print(f"   - CWEs: {len(all_cwes):,}")
        print(f"   - CAPECs: {len(all_capecs):,}")
        print(f"   - MITRE Techniques: {len(all_mitre_techniques):,}")
        print(f"   - MITRE Tactics: {len(all_mitre_tactics):,}")
        
        logger.info(f"Statistics exported to {output_file}")
        return stats
    
    def run_full_export(self):
        """Run complete export of all data types"""
        logger.info("Starting full knowledge graph export for RAG...")
        
        # Export CVE documents
        cve_docs = self.export_cve_documents()
        
        # Export product-vendor data
        product_data = self.export_product_vendor_data()
        
        # Export statistics
        stats = self.export_statistics()
        
        # Create export summary
        summary = {
            "export_timestamp": datetime.now().isoformat(),
            "export_summary": {
                "cve_documents": len(cve_docs),
                "product_records": len(product_data),
                "export_directory": str(self.export_dir)
            },
            "files_created": [
                "cve_documents_for_rag.json",
                "product_vendor_data.json", 
                "knowledge_graph_statistics.json"
            ]
        }
        
        # Save summary
        summary_file = self.export_dir / "export_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info("✅ Full knowledge graph export complete!")
        logger.info(f"📁 Export directory: {self.export_dir}")
        logger.info(f"📄 Files created: {len(summary['files_created'])}")
        
        return summary

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Direct Knowledge Graph Exporter for RAG")
    parser.add_argument("--cve", action="store_true", help="Export CVE documents")
    parser.add_argument("--product_vendor", action="store_true", help="Export product-vendor data")
    parser.add_argument("--stats", action="store_true", help="Export statistics")
    parser.add_argument("--full", action="store_true", help="Run full export (all)")
    
    args = parser.parse_args()
    
    exporter = DirectKGExporter()
    
    try:
        if args.full:
            exporter.run_full_export()
        elif args.cve:
            exporter.export_cve_documents()
        elif args.product_vendor:
            exporter.export_product_vendor_data()
        elif args.stats:
            exporter.export_statistics()
        else:
            print("No export type specified. Use --cve, --product_vendor, --stats, or --full")
            parser.print_help()
            
    except Exception as e:
        logger.error(f"Error during export: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 