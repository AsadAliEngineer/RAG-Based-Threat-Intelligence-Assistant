# 🏗️ Knowledge Graph Construction System

This directory contains the core components for building and managing the CVE knowledge graph using Neo4j. The system processes CVE data, extracts product information from CPE strings, and creates a comprehensive graph database for vulnerability analysis.

## 📊 Current Knowledge Graph Statistics

### **Node Counts**
- **CVE**: 38,995 (with CVSS scores, attack vectors, descriptions)
- **Product**: 14,499 (with vendor, category, criticality scores)
- **Vendor**: 4,117 (normalized vendor names)
- **Version**: 10,323 (semantic versioning information)
- **CWE**: 549 (Common Weakness Enumeration)
- **CAPEC**: 436 (Common Attack Pattern Enumeration and Classification)

### **Relationship Counts**
- **AFFECTS**: 106,234 (CVE → Product relationships)
- **HAS_ATTACK_PATTERN**: 240,480 (CVE → CAPEC relationships)
- **HAS_WEAKNESS**: 38,384 (CVE → CWE relationships)
- **MANUFACTURED_BY**: 14,499 (Product → Vendor relationships)
- **HAS_VERSION**: 10,478 (Product → Version relationships)

### **Key Insights**
- **Top Vendors by Products**: Qualcomm (1,656), Dell (1,269), Cisco (767)
- **Version Coverage**: 56.2% of products have version information
- **Most Common Weakness**: CWE-79 (Cross-site Scripting)
- **Attack Patterns**: CAPEC-592, CAPEC-63, CAPEC-209 are most prevalent

## 📅 Data Scope & Expansion

### **Current Dataset**
This knowledge graph is currently built using **CVE data from 2024 only**, sourced from:
- **CVE Data File**: `data/knowledge_base/enhanced_documents_cve_2024.json` (149MB)
- **CPE Data File**: `data/knowledge_base/cpe_parsing_results_full.json` (29MB)

### **Encouraging Expansion**
While this sample demonstrates the system's capabilities with 2024 data, you are **strongly encouraged** to:

1. **Test with Historical Data**: Expand to include CVEs from previous years (2010-2023)
2. **Add More Data Sources**: Integrate additional vulnerability databases
3. **Include Real-time Updates**: Set up automated CVE data ingestion
4. **Enhance with Threat Intelligence**: Add MITRE ATT&CK, ExploitDB, and other sources

### **Scaling Considerations**
- **Memory Requirements**: Full historical dataset (~2010-2024) may require 16GB+ RAM
- **Processing Time**: Larger datasets will require longer processing times
- **Storage**: Neo4j database size will scale with data volume
- **Query Performance**: Consider additional indexing for larger datasets

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │    │  Processing      │    │  Neo4j Graph    │
│   • NVD CVE     │───►│  Pipeline        │───►│  Database       │
│   • CPE Data    │    │  • CPE Parser    │    │  • 38K+ CVEs    │
│   • CWE/CAPEC   │    │  • CVE Enrich    │    │  • 14K Products │
│   • ExploitDB   │    │  • Graph Loader  │    │  • Rich Rel.    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                              ┌──────────────────┐
                                              │  Analytics &     │
                                              │  Intelligence    │
                                              │  • Graph Queries │
                                              │  • Vulnerability │
                                              │  • Trend Analysis│
                                              └──────────────────┘
```

## 📁 Component Overview

### **Core Files**

| File | Purpose | Key Features |
|------|---------|--------------|
| `enhanced_neo4j_loader.py` | Main graph loader | Loads 38K+ CVEs with rich metadata |
| `cpe_parser_system.py` | CPE parsing engine | Parses CPE 2.3, vendor normalization |
| `graph_analytics.py` | Analytics engine | Vulnerability insights, trend analysis |
| `setup_neo4j_schema.py` | Schema setup | Creates constraints and indexes |
| `run_cpe_extraction.py` | CPE extraction | Extracts products from CPE data |
| `kg_schema.py` | Schema definition | Defines node types and relationships |
| `neo4j_queries.md` | Query examples | Cypher query documentation |

### **Data Files**
- `graph_analytics.json` - Current graph statistics and analytics

## 🚀 Quick Start

### 1. **Setup Neo4j Schema**
```bash
python setup_neo4j_schema.py
```

### 2. **Load Knowledge Graph**
```bash
# Load full dataset (38,995 CVEs)
python enhanced_neo4j_loader.py --stats

# Load sample for testing
python enhanced_neo4j_loader.py --limit 100 --stats
```

### 3. **Run Analytics**
```bash
python graph_analytics.py
```

### 4. **Explore in Neo4j Browser**
- Open http://localhost:7474
- Login: `neo4j` / `password`
- Use queries from `neo4j_queries.md`

## 🔧 Technical Implementation

### **CPE Parser System** (`cpe_parser_system.py`)

The CPE parser implements advanced parsing capabilities:

```python
# Example usage
from cpe_parser_system import CPEParser

parser = CPEParser()
result = parser.parse_cpe_string("cpe:2.3:a:microsoft:windows:10.0.19041:*:*:*:*:*:*:*:*")

# Returns structured data with:
# - Vendor normalization
# - Product classification
# - Version parsing
# - Confidence scoring
```

**Key Features:**
- **CPE 2.3 Compliance**: Full support for CPE 2.3 specification
- **Vendor Normalization**: Handles vendor name variations
- **Product Classification**: Categorizes products by type and family
- **Version Parsing**: Semantic version analysis with confidence scoring
- **Error Handling**: Robust error recovery and validation

### **Enhanced Neo4j Loader** (`enhanced_neo4j_loader.py`)

The loader creates a comprehensive knowledge graph:

```python
# Example usage
from enhanced_neo4j_loader import EnhancedNeo4jLoader

loader = EnhancedNeo4jLoader()
loader.load_cve_data("path/to/cve_data.json")
loader.load_cpe_data("path/to/cpe_data.json")
loader.load_knowledge_graph()
```

**Key Features:**
- **Rich CVE Metadata**: CVSS scores, attack vectors, CWE/CAPEC mappings
- **Product Ecosystem**: Complete vendor-product-version relationships
- **Batch Processing**: Efficient loading of large datasets
- **Error Recovery**: Graceful handling of data inconsistencies
- **Progress Tracking**: Real-time loading progress and statistics

### **Graph Analytics** (`graph_analytics.py`)

Provides comprehensive analytics and insights:

```python
# Example usage
from graph_analytics import GraphAnalytics

analytics = GraphAnalytics()
analytics.run_full_analysis()
```

**Analytics Capabilities:**
- **Vulnerability Trends**: Distribution by severity, year, vendor
- **Vendor Risk Assessment**: Vulnerability density analysis
- **Attack Pattern Analysis**: CWE-CAPEC correlation
- **Data Quality Reports**: Coverage and consistency analysis
- **Export Capabilities**: JSON export for external analysis

## 📊 Data Schema

### **Node Types**

#### **CVE Node**
```cypher
CREATE (cve:CVE {
    id: "CVE-2024-21732",
    title: "CVE CVE-2024-21732",
    description: "FlyCms through abbaa5a allows XSS...",
    cvss_v3_base_score: 6.1,
    cvss_v3_severity: "MEDIUM",
    attack_vector: "NETWORK",
    attack_complexity: "LOW",
    privileges_required: "NONE",
    user_interaction: "REQUIRED",
    scope: "CHANGED",
    confidentiality_impact: "LOW",
    integrity_impact: "LOW",
    availability_impact: "NONE",
    cwe_refs: ["CWE-79"],
    capec_refs: ["CAPEC-209", "CAPEC-592"],
    affected_products: ["flycms"]
})
```

#### **Product Node**
```cypher
CREATE (product:Product {
    name: "flycms",
    vendor: "flycms_project",
    display_name: "flycms_project flycms",
    category: "Unknown",
    family: "Flycms",
    criticality_score: 5.0
})
```

#### **Vendor Node**
```cypher
CREATE (vendor:Vendor {
    name: "flycms_project"
})
```

#### **CWE Node**
```cypher
CREATE (cwe:CWE {
    id: "CWE-79"
})
```

#### **CAPEC Node**
```cypher
CREATE (capec:CAPEC {
    id: "CAPEC-209"
})
```

#### **Version Node**
```cypher
CREATE (version:Version {
    version: "1.0.0",
    product: "flycms",
    version_type: "semantic",
    raw: "1.0.0"
})
```

### **Relationship Types**

- `(CVE)-[:AFFECTS]->(Product)` - CVE affects a product
- `(CVE)-[:HAS_WEAKNESS]->(CWE)` - CVE has a specific weakness
- `(CVE)-[:HAS_ATTACK_PATTERN]->(CAPEC)` - CVE has attack patterns
- `(Product)-[:MANUFACTURED_BY]->(Vendor)` - Product is manufactured by vendor
- `(Product)-[:HAS_VERSION]->(Version)` - Product has specific versions

## 🔍 Advanced Query Examples

### **Vulnerability Analysis**

#### **Find CVEs by Vendor**
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
WHERE vendor.name =~ '(?i).*microsoft.*'
RETURN cve.id, cve.cvss_v3_severity, product.name
ORDER BY cve.cvss_v3_base_score DESC
```

#### **Vulnerability Distribution by Severity**
```cypher
MATCH (cve:CVE)
WHERE cve.cvss_v3_severity IS NOT NULL
RETURN cve.cvss_v3_severity as Severity, count(cve) as CVECount
ORDER BY CVECount DESC
```

### **Attack Pattern Analysis**

#### **Most Common CWE-CAPEC Combinations**
```cypher
MATCH (cve:CVE)-[:HAS_WEAKNESS]->(cwe:CWE)
MATCH (cve)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
RETURN cwe.id, capec.id, count(cve) as CVECount
ORDER BY CVECount DESC LIMIT 10
```

#### **Attack Pattern Prevalence**
```cypher
MATCH (cve:CVE)-[:HAS_ATTACK_PATTERN]->(capec:CAPEC)
RETURN capec.id as CAPEC, count(cve) as CVECount
ORDER BY CVECount DESC LIMIT 10
```

### **Vendor Risk Assessment**

#### **Vendors with Highest Vulnerability Density**
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
WITH vendor, count(DISTINCT cve) as cveCount, count(DISTINCT product) as productCount
WHERE productCount > 0
RETURN vendor.name, toFloat(cveCount) / productCount as CVEsPerProduct
ORDER BY CVEsPerProduct DESC
```

#### **Top Vendors by Product Count**
```cypher
MATCH (vendor:Vendor)<-[:MANUFACTURED_BY]-(product:Product)
RETURN vendor.name as Vendor, count(DISTINCT product) as ProductCount
ORDER BY ProductCount DESC LIMIT 20
```

### **Temporal Analysis**

#### **CVE Distribution by Year**
```cypher
MATCH (cve:CVE)
WITH cve, split(cve.id, '-')[1] as year
RETURN year as Year, count(cve) as CVECount
ORDER BY year DESC
```

#### **Recent High-Severity CVEs**
```cypher
MATCH (cve:CVE)
WHERE cve.cvss_v3_severity = 'HIGH' OR cve.cvss_v3_severity = 'CRITICAL'
RETURN cve.id, cve.cvss_v3_base_score, cve.cvss_v3_severity
ORDER BY cve.cvss_v3_base_score DESC LIMIT 20
```

## 📈 Performance Optimization

### **Indexing Strategy**
```cypher
// Create indexes for common query patterns
CREATE INDEX cve_id IF NOT EXISTS FOR (c:CVE) ON (c.id);
CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.cvss_v3_severity);
CREATE INDEX product_vendor IF NOT EXISTS FOR (p:Product) ON (p.vendor);
CREATE INDEX vendor_name IF NOT EXISTS FOR (v:Vendor) ON (v.name);
```

### **Query Optimization Tips**
- Use `LIMIT` clauses for large result sets
- Use `DISTINCT` when you want unique results
- Use `OPTIONAL MATCH` when relationships might not exist
- Use regex patterns `(?i)` for case-insensitive matching

## 🔧 Configuration Options

### **Enhanced Neo4j Loader Options**
```bash
python enhanced_neo4j_loader.py --help

Options:
  --cve-file PATH     Path to processed CVE data file
  --cpe-file PATH     Path to CPE parsing results file
  --uri URI           Neo4j URI (default: bolt://localhost:7687)
  --user USER         Neo4j username (default: neo4j)
  --password PASS     Neo4j password (default: password)
  --limit N           Limit number of CVEs to process
  --stats             Show graph statistics after loading
```

### **Graph Analytics Options**
```bash
python graph_analytics.py --help

Options:
  --uri URI           Neo4j URI (default: bolt://localhost:7687)
  --user USER         Neo4j username (default: neo4j)
  --password PASS     Neo4j password (default: password)
  --export PATH       Export analytics to JSON file
```

## 🚨 Troubleshooting

### **Common Issues**

1. **Neo4j Connection Errors**
   ```bash
   # Check if Neo4j is running
   docker ps | grep neo4j
   
   # Restart Neo4j if needed
   docker restart neo4j
   ```

2. **Memory Issues**
   ```bash
   # Load smaller batches for testing
   python enhanced_neo4j_loader.py --limit 1000
   ```

3. **Data Quality Issues**
   ```bash
   # Run data quality analysis
   python graph_analytics.py
   ```

### **Performance Monitoring**
```cypher
// Check database size
CALL dbms.listConfig() YIELD name, value
WHERE name = 'dbms.memory.heap.initial_size'
RETURN name, value;

// Monitor query performance
PROFILE MATCH (cve:CVE) RETURN count(cve);
```

## 🎯 Future Enhancements

### **Planned Features**
- [ ] Real-time CVE data updates
- [ ] Advanced graph visualization
- [ ] Machine learning vulnerability prediction
- [ ] MITRE ATT&CK integration
- [ ] ExploitDB correlation
- [ ] Threat intelligence feeds

### **Performance Improvements**
- [ ] Parallel processing for large datasets
- [ ] Incremental updates
- [ ] Advanced caching strategies
- [ ] Query optimization

## 📚 Additional Resources

- **[Query Examples](neo4j_queries.md)** - Comprehensive Cypher query examples
- **[Graph Analytics](graph_analytics.py)** - Analytics and insights engine
- **[RAG System](../generators/rag_system.py)** - Retrieval-Augmented Generation system
- **[Neo4j Documentation](https://neo4j.com/docs/)** - Official Neo4j documentation
- **[Cypher Query Language](https://neo4j.com/docs/cypher-manual/current/)** - Cypher reference

## 🤝 Contributing

Contributions to the knowledge graph construction system are welcome:

- **Data Source Integration**: Add support for new vulnerability data sources
- **Analytics Enhancement**: Improve graph analytics and insights
- **Performance Optimization**: Optimize loading and query performance
- **Documentation**: Improve documentation and examples

## 📄 License

This component is part of the main project and is licensed under the MIT License. 