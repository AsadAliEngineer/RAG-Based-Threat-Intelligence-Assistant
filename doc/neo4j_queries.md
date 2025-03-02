# Neo4j Knowledge Graph Queries

Use these queries in Neo4j Browser (http://localhost:7474) to explore your CVE knowledge graph.

## Basic Exploration Queries

### 1. View All Node Types
```cypher
CALL db.labels() YIELD label
RETURN label
```

### 2. Count Nodes by Type
```cypher
MATCH (n)
RETURN labels(n) as NodeType, count(n) as Count
ORDER BY Count DESC
```

### 3. View All Relationship Types
```cypher
CALL db.relationshipTypes() YIELD relationshipType
RETURN relationshipType
```

### 4. Count Relationships by Type
```cypher
MATCH ()-[r]->()
RETURN type(r) as RelationshipType, count(r) as Count
ORDER BY Count DESC
```

## CVE Analysis Queries

### 5. View Recent CVEs with Affected Products
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)
RETURN cve.cve_id as CVE, product.name as Product, product.vendor as Vendor
ORDER BY cve.cve_id DESC
LIMIT 20
```

### 6. Find CVEs Affecting Specific Vendors
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
WHERE vendor.name =~ '(?i).*microsoft.*'
RETURN cve.cve_id as CVE, product.name as Product, vendor.name as Vendor
ORDER BY cve.cve_id DESC
LIMIT 10
```

### 7. Count CVEs per Vendor
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
RETURN vendor.name as Vendor, count(DISTINCT cve) as CVECount
ORDER BY CVECount DESC
LIMIT 20
```

### 8. Count CVEs per Product
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)
RETURN product.name as Product, product.vendor as Vendor, count(cve) as CVECount
ORDER BY CVECount DESC
LIMIT 20
```

## Product and Vendor Analysis

### 9. View All Vendors
```cypher
MATCH (vendor:Vendor)
RETURN vendor.name as Vendor
ORDER BY vendor.name
```

### 10. View All Products with Their Vendors
```cypher
MATCH (product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
RETURN product.name as Product, vendor.name as Vendor
ORDER BY vendor.name, product.name
LIMIT 50
```

### 11. Find Products by Vendor
```cypher
MATCH (product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
WHERE vendor.name =~ '(?i).*google.*'
RETURN product.name as Product, vendor.name as Vendor
ORDER BY product.name
```

## Version Analysis

### 12. View Products with Version Information
```cypher
MATCH (product:Product)-[:HAS_VERSION]->(version:Version)
RETURN product.name as Product, product.vendor as Vendor, 
       version.version as Version, version.version_type as Type
ORDER BY product.name, version.version
LIMIT 30
```

### 13. Find Products with Multiple Versions
```cypher
MATCH (product:Product)-[:HAS_VERSION]->(version:Version)
WITH product, count(version) as versionCount
WHERE versionCount > 1
RETURN product.name as Product, product.vendor as Vendor, versionCount
ORDER BY versionCount DESC
LIMIT 20
```

## Graph Visualization Queries

### 14. Visualize CVE and Its Affected Products
```cypher
MATCH (cve:CVE {cve_id: 'CVE-2024-0193'})-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
OPTIONAL MATCH (product)-[:HAS_VERSION]->(version:Version)
RETURN cve, product, vendor, version
```

### 15. Visualize Vendor's Product Ecosystem
```cypher
MATCH (vendor:Vendor {name: 'redhat'})-[:HAS_PRODUCT]-(product:Product)
OPTIONAL MATCH (product)-[:HAS_VERSION]->(version:Version)
OPTIONAL MATCH (cve:CVE)-[:AFFECTS]->(product)
RETURN vendor, product, version, cve
```

### 16. Visualize CVE Impact Network
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
WHERE cve.cve_id =~ 'CVE-2024-.*'
RETURN cve, product, vendor
LIMIT 10
```

## Advanced Analytics

### 17. Find Most Vulnerable Vendors
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
WITH vendor, count(DISTINCT cve) as cveCount, count(DISTINCT product) as productCount
RETURN vendor.name as Vendor, cveCount as CVEs, productCount as Products,
       toFloat(cveCount) / productCount as CVEsPerProduct
ORDER BY cveCount DESC
LIMIT 20
```

### 18. Find Products with Most CVEs
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:HAS_VENDOR]->(vendor:Vendor)
WITH product, vendor, count(cve) as cveCount
RETURN product.name as Product, vendor.name as Vendor, cveCount as CVEs
ORDER BY cveCount DESC
LIMIT 20
```

### 19. CVE Distribution by Year
```cypher
MATCH (cve:CVE)
WITH cve, split(cve.cve_id, '-')[1] as year
RETURN year as Year, count(cve) as CVECount
ORDER BY year DESC
```

## Data Quality Queries

### 20. Find Products Without Vendors
```cypher
MATCH (product:Product)
WHERE NOT (product)-[:HAS_VENDOR]->()
RETURN product.name as Product, product.vendor as Vendor
```

### 21. Find CVEs Without Products
```cypher
MATCH (cve:CVE)
WHERE NOT (cve)-[:AFFECTS]->()
RETURN cve.cve_id as CVE
```

### 22. Find Duplicate Products
```cypher
MATCH (product:Product)
WITH product.name as name, product.vendor as vendor, collect(product) as products
WHERE size(products) > 1
RETURN name as Product, vendor as Vendor, size(products) as DuplicateCount
ORDER BY DuplicateCount DESC
```

## Tips for Neo4j Browser

1. **Use the Graph View**: Click the "Graph" tab to see visual representations
2. **Use the Table View**: Click the "Table" tab for tabular data
3. **Export Results**: Use the download button to export results as CSV
4. **Save Queries**: Use the star button to save frequently used queries
5. **Use Parameters**: Replace hardcoded values with parameters like `{vendorName: 'microsoft'}`

## Performance Tips

- Add `LIMIT` clauses to large queries
- Use `DISTINCT` when you want unique results
- Use `OPTIONAL MATCH` when relationships might not exist
- Use regex patterns `(?i)` for case-insensitive matching 