# 🏗️ Knowledge Graph Construction System

This directory contains the core components for building and managing the CVE knowledge graph using Neo4j. The system processes CVE data, extracts product information from CPE strings, and creates a comprehensive graph database for vulnerability analysis.

## 📊 Current Knowledge Graph Statistics

Note that the statistics are for 2024 CVEs only. Feel free to add more data.

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
