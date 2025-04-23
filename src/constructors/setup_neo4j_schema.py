from neo4j import GraphDatabase

# Neo4j connection config
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "password"

def setup_schema(driver):
    """Set up Neo4j schema constraints and indexes"""
    with driver.session() as session:
        print("Setting up Neo4j schema...")
        
        # Core Constraints (Data Integrity)
        constraints = [
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT product_cpe IF NOT EXISTS FOR (p:Product) REQUIRE p.cpe IS UNIQUE",
            "CREATE CONSTRAINT vendor_name IF NOT EXISTS FOR (v:Vendor) REQUIRE v.name IS UNIQUE",
            "CREATE CONSTRAINT version_id IF NOT EXISTS FOR (ver:Version) REQUIRE ver.id IS UNIQUE",
            "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (cwe:CWE) REQUIRE cwe.id IS UNIQUE",
            "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (capec:CAPEC) REQUIRE capec.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_id IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE"
        ]
        
        # Performance Indexes
        indexes = [
            "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
            "CREATE INDEX cve_cvss_score IF NOT EXISTS FOR (c:CVE) ON (c.cvss_v3_score)",
            "CREATE INDEX cve_published_date IF NOT EXISTS FOR (c:CVE) ON (c.published_date)",
            "CREATE INDEX product_category IF NOT EXISTS FOR (p:Product) ON (p.product_category)",
            "CREATE INDEX product_vendor IF NOT EXISTS FOR (p:Product) ON (p.vendor)",
            "CREATE INDEX product_criticality IF NOT EXISTS FOR (p:Product) ON (p.criticality_score)",
            "CREATE INDEX version_release_date IF NOT EXISTS FOR (ver:Version) ON (ver.release_date)"
        ]
        
        # Full-Text Search Indexes
        fulltext_indexes = [
            "CREATE FULLTEXT INDEX cve_description IF NOT EXISTS FOR (c:CVE) ON EACH [c.description]",
            "CREATE FULLTEXT INDEX product_search IF NOT EXISTS FOR (p:Product) ON EACH [p.product, p.product_family, p.product_category]",
            "CREATE FULLTEXT INDEX vendor_search IF NOT EXISTS FOR (v:Vendor) ON EACH [v.name, v.aliases]"
        ]
        
        # Execute constraints
        print("Creating constraints...")
        for constraint in constraints:
            try:
                session.run(constraint)
                print(f"OK {constraint}")
            except Exception as e:
                print(f"WARNING {constraint} - {e}")
        
        # Execute indexes
        print("\nCreating indexes...")
        for index in indexes:
            try:
                session.run(index)
                print(f"OK {index}")
            except Exception as e:
                print(f"WARNING {index} - {e}")
        
        # Execute full-text indexes
        print("\nCreating full-text indexes...")
        for index in fulltext_indexes:
            try:
                session.run(index)
                print(f"OK {index}")
            except Exception as e:
                print(f"WARNING {index} - {e}")
        
        print("\nSchema setup complete!")

def test_connection(driver):
    """Test Neo4j connection"""
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            record = result.single()
            if record and record["test"] == 1:
                print("OK Neo4j connection successful!")
                return True
    except Exception as e:
        print(f"ERROR Neo4j connection failed: {e}")
        return False

def main():
    print("=== Neo4j Schema Setup ===")
    
    # Connect to Neo4j
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    # Test connection
    if not test_connection(driver):
        print("Please ensure Neo4j is running on localhost:7687")
        driver.close()
        return
    
    # Setup schema
    setup_schema(driver)
    
    driver.close()
    print("\nSUCCESS Neo4j schema setup complete!")
    print("\nYou can now:")
    print("1. Open Neo4j Browser at: http://localhost:7474")
    print("2. Login with: neo4j/password")
    print("3. Run the neo4j_loader.py script to load your data")

if __name__ == "__main__":
    main() 