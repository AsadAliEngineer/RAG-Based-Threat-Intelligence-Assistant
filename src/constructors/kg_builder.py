from typing import Dict, List, Any
from neo4j import Session

def create_cve_node(session: Session, cve_id: str, cve_doc: Dict[str, Any]) -> None:
    """Create a CVE node with rich metadata in Neo4j."""
    cvss_v3 = cve_doc.get('cvss_v3', {})
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

def create_cwe_nodes(session: Session, cve_id: str, cwe_refs: List[str]) -> None:
    """Create CWE nodes and relationships in Neo4j."""
    for cwe_id in cwe_refs:
        session.run("""
            MERGE (cwe:CWE {id: $cwe_id})
        """, {'cwe_id': cwe_id})
        session.run("""
            MATCH (cve:CVE {id: $cve_id})
            MATCH (cwe:CWE {id: $cwe_id})
            MERGE (cve)-[:HAS_WEAKNESS]->(cwe)
        """, {'cve_id': cve_id, 'cwe_id': cwe_id})

def create_capec_nodes(session: Session, cve_id: str, capec_refs: List[str]) -> None:
    """Create CAPEC nodes and relationships in Neo4j."""
    for capec_id in capec_refs:
        session.run("""
            MERGE (capec:CAPEC {id: $capec_id})
        """, {'capec_id': capec_id})
        session.run("""
            MATCH (cve:CVE {id: $cve_id})
            MATCH (capec:CAPEC {id: $capec_id})
            MERGE (cve)-[:HAS_ATTACK_PATTERN]->(capec)
        """, {'cve_id': cve_id, 'capec_id': capec_id})

def create_product_vendor_nodes(session: Session, product_key: str, product_data: Dict[str, Any]) -> None:
    """Create Product and Vendor nodes from CPE data in Neo4j."""
    vendor_name = product_data.get('vendor', '')
    product_name = product_data.get('product', '')
    session.run("""
        MERGE (vendor:Vendor {name: $vendor_name})
    """, {'vendor_name': vendor_name})
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
    session.run("""
        MATCH (product:Product {name: $product_name, vendor: $vendor_name})
        MATCH (vendor:Vendor {name: $vendor_name})
        MERGE (product)-[:MANUFACTURED_BY]->(vendor)
    """, {'product_name': product_name, 'vendor_name': vendor_name})
    versions = product_data.get('versions', {})
    for version_key, version_data in versions.items():
        if version_key != '*':
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
            session.run("""
                MATCH (product:Product {name: $product_name, vendor: $vendor_name})
                MATCH (version:Version {version: $version, product: $product_name})
                MERGE (product)-[:HAS_VERSION]->(version)
            """, {
                'product_name': product_name,
                'vendor_name': vendor_name,
                'version': version_key
            })

def create_cve_product_relationships(session: Session, cve_id: str, affected_products: List[str]) -> None:
    """Create relationships between CVEs and affected products in Neo4j."""
    for product_name in affected_products:
        session.run("""
            MATCH (cve:CVE {id: $cve_id})
            MATCH (product:Product {name: $product_name})
            MERGE (cve)-[:AFFECTS]->(product)
        """, {'cve_id': cve_id, 'product_name': product_name}) 