#!/usr/bin/env python3
"""
Neo4j Knowledge Graph Analytics
Performs analysis on the CVE knowledge graph and generates insights.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
import pandas as pd
from datetime import datetime
import json

class GraphAnalytics:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
        
    def run_query(self, query, parameters=None):
        """Execute a Cypher query and return results"""
        with self.driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]
    
    def get_basic_stats(self):
        """Get basic statistics about the knowledge graph"""
        print("Basic Knowledge Graph Statistics")
        print("=" * 50)
        
        # Node counts
        node_stats = self.run_query("""
            MATCH (n)
            RETURN labels(n) as NodeType, count(n) as Count
            ORDER BY Count DESC
        """)
        
        print("\nNode Counts:")
        for stat in node_stats:
            node_type = stat['NodeType'][0] if stat['NodeType'] else 'Unknown'
            print(f"  {node_type}: {stat['Count']:,}")
        
        # Relationship counts
        rel_stats = self.run_query("""
            MATCH ()-[r]->()
            RETURN type(r) as RelationshipType, count(r) as Count
            ORDER BY Count DESC
        """)
        
        print("\nRelationship Counts:")
        for stat in rel_stats:
            print(f"  {stat['RelationshipType']}: {stat['Count']:,}")
    
    def get_cve_analysis(self):
        """Analyze CVE data"""
        print("\nCVE Analysis")
        print("=" * 50)
        
        # CVE distribution by year
        cve_by_year = self.run_query("""
            MATCH (cve:CVE)
            WITH cve, split(cve.id, '-')[1] as year
            RETURN year as Year, count(cve) as CVECount
            ORDER BY year DESC
        """)
        
        print("\nCVE Distribution by Year:")
        for stat in cve_by_year:
            print(f"  {stat['Year']}: {stat['CVECount']:,} CVEs")
        
        # CVE distribution by severity
        cve_by_severity = self.run_query("""
            MATCH (cve:CVE)
            WHERE cve.cvss_v3_severity IS NOT NULL
            RETURN cve.cvss_v3_severity as Severity, count(cve) as CVECount
            ORDER BY CVECount DESC
        """)
        
        print("\nCVE Distribution by Severity:")
        for stat in cve_by_severity:
            print(f"  {stat['Severity']}: {stat['CVECount']:,} CVEs")
        
        # Top vendors by CVE count
        top_vendors = self.run_query("""
            MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
            RETURN vendor.name as Vendor, count(DISTINCT cve) as CVECount
            ORDER BY CVECount DESC
            LIMIT 10
        """)
        
        print("\nTop Vendors by CVE Count:")
        for i, vendor in enumerate(top_vendors, 1):
            print(f"  {i}. {vendor['Vendor']}: {vendor['CVECount']:,} CVEs")
        
        # Top products by CVE count
        top_products = self.run_query("""
            MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
            RETURN product.name as Product, vendor.name as Vendor, count(cve) as CVECount
            ORDER BY CVECount DESC
            LIMIT 10
        """)
        
        print("\nTop Products by CVE Count:")
        for i, product in enumerate(top_products, 1):
            print(f"  {i}. {product['Product']} ({product['Vendor']}): {product['CVECount']:,} CVEs")
        
        # Most common CWEs
        top_cwes = self.run_query("""
            MATCH (cve:CVE)-[:HAS_WEAKNESS]->(cwe:CWE)
            RETURN cwe.id as CWE, count(cve) as CVECount
            ORDER BY CVECount DESC
            LIMIT 10
        """)
        
        print("\nMost Common Weaknesses (CWE):")
        for i, cwe in enumerate(top_cwes, 1):
            print(f"  {i}. {cwe['CWE']}: {cwe['CVECount']:,} CVEs")
    
    def get_vendor_ecosystem_analysis(self):
        """Analyze vendor product ecosystems"""
        print("\nVendor Ecosystem Analysis")
        print("=" * 50)
        
        # Vendors with most products
        vendors_by_products = self.run_query("""
            MATCH (vendor:Vendor)<-[:MANUFACTURED_BY]-(product:Product)
            RETURN vendor.name as Vendor, count(DISTINCT product) as ProductCount
            ORDER BY ProductCount DESC
            LIMIT 15
        """)
        
        print("\nVendors by Product Count:")
        for i, vendor in enumerate(vendors_by_products, 1):
            print(f"  {i}. {vendor['Vendor']}: {vendor['ProductCount']:,} products")
        
        # Most vulnerable vendors (CVEs per product)
        vulnerable_vendors = self.run_query("""
            MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
            WITH vendor, count(DISTINCT cve) as cveCount, count(DISTINCT product) as productCount
            WHERE productCount > 0
            RETURN vendor.name as Vendor, cveCount as CVEs, productCount as Products,
                   toFloat(cveCount) / productCount as CVEsPerProduct
            ORDER BY CVEsPerProduct DESC
            LIMIT 15
        """)
        
        print("\nMost Vulnerable Vendors (CVEs per Product):")
        for i, vendor in enumerate(vulnerable_vendors, 1):
            print(f"  {i}. {vendor['Vendor']}: {vendor['CVEsPerProduct']:.2f} CVEs/product "
                  f"({vendor['CVEs']:,} CVEs, {vendor['Products']:,} products)")
    
    def get_attack_pattern_analysis(self):
        """Analyze attack patterns and weaknesses"""
        print("\nAttack Pattern Analysis")
        print("=" * 50)
        
        # Most common attack patterns
        top_capecs = self.run_query("""
            MATCH (cve:CVE)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
            RETURN capec.id as CAPEC, count(cve) as CVECount
            ORDER BY CVECount DESC
            LIMIT 10
        """)
        
        print("\nMost Common Attack Patterns (CAPEC):")
        for i, capec in enumerate(top_capecs, 1):
            print(f"  {i}. {capec['CAPEC']}: {capec['CVECount']:,} CVEs")
        
        # CVE-CWE-CAPEC relationships
        cwe_capec_relationships = self.run_query("""
            MATCH (cve:CVE)-[:HAS_WEAKNESS]->(cwe:CWE)
            MATCH (cve)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
            RETURN cwe.id as CWE, capec.id as CAPEC, count(cve) as CVECount
            ORDER BY CVECount DESC
            LIMIT 10
        """)
        
        print("\nTop CWE-CAPEC Combinations:")
        for i, rel in enumerate(cwe_capec_relationships, 1):
            print(f"  {i}. {rel['CWE']} + {rel['CAPEC']}: {rel['CVECount']:,} CVEs")
    
    def get_version_analysis(self):
        """Analyze version information"""
        print("\nVersion Analysis")
        print("=" * 50)
        
        # Products with version information
        products_with_versions = self.run_query("""
            MATCH (product:Product)-[:HAS_VERSION]->(version:Version)
            RETURN count(DISTINCT product) as ProductsWithVersions
        """)
        
        total_products = self.run_query("""
            MATCH (product:Product)
            RETURN count(product) as TotalProducts
        """)
        
        if products_with_versions and total_products:
            version_coverage = (products_with_versions[0]['ProductsWithVersions'] / 
                              total_products[0]['TotalProducts']) * 100
            print(f"\nVersion Coverage: {version_coverage:.1f}% of products have version information")
        
        # Products with multiple versions
        multi_version_products = self.run_query("""
            MATCH (product:Product)-[:HAS_VERSION]->(version:Version)
            WITH product, count(version) as versionCount
            WHERE versionCount > 1
            RETURN product.name as Product, product.vendor as Vendor, versionCount
            ORDER BY versionCount DESC
            LIMIT 10
        """)
        
        print("\nProducts with Multiple Versions:")
        for i, product in enumerate(multi_version_products, 1):
            print(f"  {i}. {product['Product']} ({product['Vendor']}): {product['versionCount']} versions")
    
    def get_data_quality_report(self):
        """Generate data quality report"""
        print("\nData Quality Report")
        print("=" * 50)
        
        # Products without vendors
        products_without_vendors = self.run_query("""
            MATCH (product:Product)
            WHERE NOT (product)-[:MANUFACTURED_BY]->()
            RETURN count(product) as Count
        """)
        
        if products_without_vendors:
            print(f"\nWARNING: Products without vendor relationships: {products_without_vendors[0]['Count']:,}")
        
        # CVEs without products
        cves_without_products = self.run_query("""
            MATCH (cve:CVE)
            WHERE NOT (cve)-[:AFFECTS]->()
            RETURN count(cve) as Count
        """)
        
        if cves_without_products:
            print(f"WARNING: CVEs without product relationships: {cves_without_products[0]['Count']:,}")
        
        # CVEs without CVSS scores
        cves_without_cvss = self.run_query("""
            MATCH (cve:CVE)
            WHERE cve.cvss_v3_base_score IS NULL
            RETURN count(cve) as Count
        """)
        
        if cves_without_cvss:
            print(f"WARNING: CVEs without CVSS scores: {cves_without_cvss[0]['Count']:,}")
        
        # Duplicate products
        duplicate_products = self.run_query("""
            MATCH (product:Product)
            WITH product.name as name, product.vendor as vendor, collect(product) as products
            WHERE size(products) > 1
            RETURN count(name) as Count
        """)
        
        if duplicate_products:
            print(f"WARNING: Products with potential duplicates: {duplicate_products[0]['Count']:,}")
    
    def export_analytics_to_json(self, filename="graph_analytics.json"):
        """Export analytics data to JSON file"""
        print(f"\nExporting analytics to {filename}")
        
        analytics_data = {
            "timestamp": datetime.now().isoformat(),
            "basic_stats": {
                "nodes": self.run_query("MATCH (n) RETURN labels(n) as NodeType, count(n) as Count"),
                "relationships": self.run_query("MATCH ()-[r]->() RETURN type(r) as RelationshipType, count(r) as Count")
            },
            "cve_analysis": {
                "by_year": self.run_query("MATCH (cve:CVE) WITH cve, split(cve.id, '-')[1] as year RETURN year as Year, count(cve) as CVECount ORDER BY year DESC"),
                "top_vendors": self.run_query("MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor) RETURN vendor.name as Vendor, count(DISTINCT cve) as CVECount ORDER BY CVECount DESC LIMIT 20"),
                "top_products": self.run_query("MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor) RETURN product.name as Product, vendor.name as Vendor, count(cve) as CVECount ORDER BY CVECount DESC LIMIT 20")
            },
            "vendor_analysis": {
                "by_products": self.run_query("MATCH (vendor:Vendor)<-[:MANUFACTURED_BY]-(product:Product) RETURN vendor.name as Vendor, count(DISTINCT product) as ProductCount ORDER BY ProductCount DESC LIMIT 20"),
                "vulnerability_ratio": self.run_query("MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor) WITH vendor, count(DISTINCT cve) as cveCount, count(DISTINCT product) as productCount WHERE productCount > 0 RETURN vendor.name as Vendor, cveCount as CVEs, productCount as Products, toFloat(cveCount) / productCount as CVEsPerProduct ORDER BY CVEsPerProduct DESC LIMIT 20")
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(analytics_data, f, indent=2)
        
        print(f"SUCCESS: Analytics exported to {filename}")
    
    def run_full_analysis(self):
        """Run complete analysis"""
        print("Starting Enhanced Knowledge Graph Analytics")
        print("=" * 60)
        
        try:
            self.get_basic_stats()
            self.get_cve_analysis()
            self.get_vendor_ecosystem_analysis()
            self.get_attack_pattern_analysis()
            self.get_version_analysis()
            self.get_data_quality_report()
            self.export_analytics_to_json()
            
            print("\nSUCCESS: Analysis complete!")
            
        except Exception as e:
            print(f"ERROR: Error during analysis: {e}")
        finally:
            self.close()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Neo4j Knowledge Graph Analytics")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="password", help="Neo4j password")
    parser.add_argument("--export", help="Export filename for JSON analytics")
    
    args = parser.parse_args()
    
    analytics = GraphAnalytics(args.uri, args.user, args.password)
    
    if args.export:
        analytics.export_analytics_to_json(args.export)
    else:
        analytics.run_full_analysis()

if __name__ == "__main__":
    main() 