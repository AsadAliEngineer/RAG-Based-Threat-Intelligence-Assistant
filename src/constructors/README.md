# Knowledge Graph Construction System

This directory contains the core components for building and managing the CVE knowledge graph. The system processes CVE data, extracts product information from CPE strings, and creates a comprehensive graph database for vulnerability analysis. **Two workflows are supported: Neo4j-based and JSON-based (no Neo4j required).**

## Current Knowledge Graph Statistics (Latest)

### **Complete Coverage (1999-2025)**
- **CVE Data Files**: `data/knowledge_base/enhanced_documents_cve_*.json` (1999-2025)
- **CPE Data File**: `data/knowledge_base/cpe_parsing_results_full.json`

### **Node Counts**
- **CVE**: 190,310 (with CVSS scores, attack vectors, descriptions, CWE, CAPEC, MITRE mappings)
- **Product**: 124,290 (with vendor, category, criticality scores)
- **Vendor**: 19,692 (normalized vendor names)
- **CWE**: 458 (Common Weakness Enumeration)
- **CAPEC**: 428 (Common Attack Pattern Enumeration and Classification)
- **MITRE Techniques**: 169 (ATT&CK techniques)
- **MITRE Tactics**: 37 (ATT&CK tactics)

### **Relationship Counts**
- **CVE_PRODUCT**: 1,095,059 (CVE → Product relationships)
- **CVE_CWE**: 129,171 (CVE → CWE relationships)
- **CVE_CAPEC**: 872,847 (CVE → CAPEC relationships)
- **CVE_MITRE_TECHNIQUE**: 207,492 (CVE → MITRE technique relationships)
- **CVE_MITRE_TACTIC**: 78,892 (CVE → MITRE tactic relationships)
- **PRODUCT_VENDOR**: 124,288 (Product → Vendor relationships)

### **CVE Statistics**
- **Total CVEs**: 190,310
- **In KEV**: 1,060 (Known Exploited Vulnerabilities)
- **With CVSS v3**: 152,676 (80% coverage)
- **With CVSS v2**: 85,443 (45% coverage)

### **Severity Distribution**
- **CRITICAL**: 23,552 CVEs
- **HIGH**: 60,367 CVEs
- **MEDIUM**: 66,086 CVEs
- **LOW**: 2,671 CVEs
- **UNKNOWN**: 37,634 CVEs

### **Top Vendors by Vulnerability Count**
1. **HP**: 14,569 vulnerabilities
2. **Intel**: 10,014 vulnerabilities
3. **Cisco**: 5,733 vulnerabilities
4. **Lenovo**: 4,123 vulnerabilities
5. **Siemens**: 4,083 vulnerabilities

## Architecture Overview

### **Two Workflow Options**

#### **Option 1: Neo4j-Based Workflow (Full Graph Database)**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │    │  Processing      │    │  Neo4j Graph    │
│   • NVD CVE     │───►│  Pipeline        │───►│  Database       │
│   • CPE Data    │    │  • CPE Parser    │    │  • 190K+ CVEs   │
│   • CWE/CAPEC   │    │  • CVE Enrich    │    │  • 124K Products│
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

#### **Option 2: JSON-Based Workflow (No Neo4j Required)**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │    │  Processing      │    │  JSON Knowledge │
│   • NVD CVE     │───►│  Pipeline        │───►│  Graph          │
│   • CPE Data    │    │  • CPE Parser    │    │  • 190K+ CVEs   │
│   • CWE/CAPEC   │    │  • CVE Enrich    │    │  • 124K Products│
│   • ExploitDB   │    │  • KG Builder    │    │  • Rich Rel.    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                              ┌──────────────────┐
                                              │  RAG System      │
                                              │  • Vector Search │
                                              │  • LLM Response  │
                                              │  • Hybrid Search │
                                              └──────────────────┘
```

## Quick Start

### **Option 1: Neo4j-Based Workflow**

#### **1. Setup Neo4j Schema**
```bash
python setup_neo4j_schema.py
```

#### **2. Load Knowledge Graph**
```bash
# Load full dataset (190,310 CVEs)
python enhanced_neo4j_loader.py --stats

# Load sample for testing
python enhanced_neo4j_loader.py --limit 100 --stats
```

#### **3. Run Analytics**
```bash
python graph_analytics.py
```

#### **4. Export for RAG**
```bash
python -m src.generators.export_kg_for_rag --full
```

### **Option 2: JSON-Based Workflow (Recommended for Development)**

#### **1. Build Knowledge Graph (No Neo4j Required)**
```bash
# Build complete knowledge graph
python kg_builder_without_neo4j.py
```

#### **2. Export for RAG System**
```bash
# Export KG data for RAG (JSON-based)
python -m src.generators.export_kg_for_rag_without_neo4j --full
```

#### **3. Access Knowledge Graph Data**
```bash
# Knowledge graph files are available in:
# data/knowledge_base/knowledge_graph/
# data/knowledge_base/rag_exports/
```


##  Data Schema

### **Node Types**

#### **CVE Node**
```json
{
  "id": "CVE-2024-21732",
  "title": "CVE CVE-2024-21732",
  "description": "FlyCms through abbaa5a allows XSS...",
  "cvss_v3": {
    "base_score": 6.1,
    "base_severity": "MEDIUM",
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW"
  },
  "affected_products": ["flycms"],
  "cwe_refs": ["CWE-79"],
  "capec_entries": ["CAPEC-209", "CAPEC-592"],
  "mitre_techniques": ["T1505.003"],
  "mitre_tactics": ["T1505"],
  "is_in_kev": false,
  "tags": ["technique_t1505.003", "capec_capec-209"]
}
```

#### **Product Node**
```json
{
  "name": "flycms",
  "vendor": "flycms_project",
  "display_name": "flycms_project flycms",
  "category": "Web Application",
  "family": "Content Management",
  "criticality_score": 5.0,
  "vulnerability_count": 15,
  "versions": ["1.0.0", "1.1.0"]
}
```

#### **Vendor Node**
```json
{
  "name": "flycms_project",
  "display_name": "Flycms Project",
  "vulnerability_count": 15,
  "product_count": 1
}
```

### **Relationship Types**

- `(CVE)-[:AFFECTS]->(Product)` - CVE affects a product
- `(CVE)-[:HAS_WEAKNESS]->(CWE)` - CVE has a specific weakness
- `(CVE)-[:HAS_ATTACK_PATTERN]->(CAPEC)` - CVE has attack patterns
- `(CVE)-[:USES_TECHNIQUE]->(MITRE_TECHNIQUE)` - CVE uses MITRE technique
- `(CVE)-[:BELONGS_TO_TACTIC]->(MITRE_TACTIC)` - CVE belongs to MITRE tactic
- `(Product)-[:MANUFACTURED_BY]->(Vendor)` - Product is manufactured by vendor

## Advanced Query Examples

### **Neo4j Cypher Queries**

#### **Find CVEs by Vendor**
```cypher
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
WHERE vendor.name =~ '(?i).*microsoft.*'
RETURN cve.id, cve.cvss_v3.base_severity, product.name
ORDER BY cve.cvss_v3.base_score DESC
```

#### **Vulnerability Distribution by Severity**
```cypher
MATCH (cve:CVE)
WHERE cve.cvss_v3.base_severity IS NOT NULL
RETURN cve.cvss_v3.base_severity as Severity, count(cve) as CVECount
ORDER BY CVECount DESC
```

### **JSON-Based Queries**

#### **Find Critical CVEs**
```python
import json

with open('data/knowledge_base/knowledge_graph/cves_nodes.json', 'r') as f:
    cves = json.load(f)

critical_cves = [
    cve for cve in cves.values() 
    if cve.get('cvss_v3', {}).get('base_severity') == 'CRITICAL'
]
```

#### **Vendor Risk Analysis**
```python
with open('data/knowledge_base/knowledge_graph/vendors_nodes.json', 'r') as f:
    vendors = json.load(f)

high_risk_vendors = [
    vendor for vendor in vendors.values()
    if vendor.get('vulnerability_count', 0) > 1000
]
```

