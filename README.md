# 🔒 CVE Knowledge Graph & Security Intelligence System

This project combines a Neo4j knowledge graph (KG) for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. 

## 🚀 Quick Start

### Installation

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd CVE-KGRAG
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Start Neo4j Database**
   ```bash
   # IMPORTANT: Set your own secure Neo4j password!
   export NEO4J_PASSWORD=<your_password>
   docker run -d \
     --name neo4j \
     -p 7474:7474 -p 7687:7687 \
     -e NEO4J_AUTH=neo4j:${NEO4J_PASSWORD} \
     -e NEO4J_PLUGINS='["apoc"]' \
     neo4j:latest
   ```

3. **Build Knowledge Graph**
   ```bash
   cd src/constructors
   python setup_neo4j_schema.py
   python enhanced_neo4j_loader.py --stats
   ```

4. **Test RAG System**
   ```bash
   cd ../generators
   python rag_system.py
   ```

5. **Explore the Graph**
   - **Neo4j Browser**: http://localhost:7474 (login: neo4j/password)
   - **Analytics**: `python graph_analytics.py`
   - **Query Examples**: See `neo4j_queries.md`

## 🏗️ System Overview

```
Data Sources → Processing Pipeline → Neo4j Graph → Vector Database → RAG System
    • NVD CVE         • CPE Parser        • 38K+ CVEs        • 39K Chunks     • Semantic Search
    • CPE Data        • CVE Enrich        • 14K Products     • Embeddings     • Vulnerability Analysis
    • CWE/CAPEC       • Graph Loader      • Rich Relations   • ChromaDB       • Natural Language Queries
```

## 📁 Project Structure

```
src/
├── constructors/           # Knowledge Graph Construction
├── collectors/            # Data Collection
├── processors/            # Data Processing
└── generators/            # RAG & LLM Generation Components

data/
├── knowledge_base/        # Processed Data (CVE, CPE)
├── knowledge_graph/       # Constructed KG (Analytics, Exports, Backups)
├── CVE/                   # Raw CVE Data
├── CTI/                   # Threat Intelligence
└── reports/               # Analysis Reports
```

## 🚀 Usage Examples

### **RAG System Queries**
```python
from generators.rag_system import CVERAGSystem

# Initialize RAG system
rag = CVERAGSystem()

# Search for vulnerabilities with rich context
results = rag.search_cves("SQL injection vulnerabilities", n_results=3)
# Output includes: CVE ID, severity, affected products/vendors, 
# CWE weaknesses, CAPEC attack patterns, and similarity scores

# Example output:
# CVE-2024-45174 (HIGH)
#   Products: cloudclassroom-php_project
#   Vendors: vishalmathur  
#   CWE: CWE-89
#   CAPEC: CAPEC-108, CAPEC-470, CAPEC-7, CAPEC-110, CAPEC-109, CAPEC-66

# Get vulnerability summary
summary = rag.get_vulnerability_summary("Cross-site scripting")

# Find similar CVEs
similar = rag.get_similar_cves("CVE-2024-12345")
```

### **Graph Database Queries**
```cypher
// Find CVEs by vendor
MATCH (cve:CVE)-[:AFFECTS]->(product:Product)-[:MANUFACTURED_BY]->(vendor:Vendor)
WHERE vendor.name =~ '(?i).*microsoft.*'
RETURN cve.id, cve.cvss_v3_severity, product.name
ORDER BY cve.cvss_v3_base_score DESC
```

## 📚 Documentation

- **[Knowledge Graph Details](src/constructors/README.md)** - Comprehensive KG documentation
- **[Query Examples](src/constructors/neo4j_queries.md)** - Cypher query examples
- **[Graph Analytics](src/constructors/graph_analytics.py)** - Analytics and insights
- **[RAG System](src/generators/rag_system.py)** - Retrieval-Augmented Generation system

## 🤝 Contributing

Contributions are welcome for additional data source integrations, enhanced analytics algorithms, graph visualization improvements, and documentation.
