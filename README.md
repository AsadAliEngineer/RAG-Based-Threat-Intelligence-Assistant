# 🔒 CVE Knowledge Graph & Security Intelligence System

This project combines a Neo4j knowledge graph (KG) for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. 

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Docker Desktop (for Neo4j)
- 8GB+ RAM recommended

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
   > **First time?** Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and pull the [Neo4j image](https://hub.docker.com/_/neo4j) with `docker pull neo4j:latest` if you haven't already.
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

3. **Collect, Correlate, and Process Data**
   ```bash
   cd src/collectors
   python main_collector.py
   # Downloads and preprocesses CVE, CPE, CWE, CAPEC, and threat intelligence data.
   # Produces raw and intermediate files in data/knowledge_base and data/CVE.
   
   cd ../processors
   python process_all_cves.py
   # Correlates and enriches the collected data, producing processed CVE and CPE documents for graph construction.
   ```

4. **Parse CPEs and Extract Products/Vendors**
   ```bash
   cd ../constructors
   python run_cpe_extraction.py
   # Parses CPE strings from processed CVE data, extracts and normalizes products and vendors,
   # and outputs structured product/vendor data for graph construction.
   ```
   > **Note:** Processed and parsed data are not included in the repository. You must run the collection, processing, and CPE parsing steps to generate the required files before building the knowledge graph.

5. **Build Knowledge Graph**
   ```bash
   cd ../constructors
   python setup_neo4j_schema.py
   python enhanced_neo4j_loader.py --stats
   ```

6. **Test RAG System**
   ```bash
   cd ../generators
   python rag_system.py
   ```

7. **Explore the Graph**
   - **Neo4j Browser**: need to login
   - **Analytics**: `python graph_analytics.py`
   - **Query Examples**: See `neo4j_queries.md`


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
