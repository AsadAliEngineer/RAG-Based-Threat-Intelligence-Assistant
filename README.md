# 🔒 CVE Knowledge Graph & Security Intelligence System

A comprehensive CVE knowledge graph system with advanced product extraction, Neo4j graph database, and AI-powered security intelligence capabilities. This system processes and analyzes vulnerability data to create a rich, interconnected knowledge base for security research and threat analysis.

## 🧠 Hybrid KG+RAG Architecture

This project combines a Neo4j knowledge graph (KG) for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. The KG enables deep analytics and relationship queries, while the RAG system retrieves rich, context-aware CVE information for natural language queries and LLM-powered analysis.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Docker Desktop (for Neo4j)
- 8GB+ RAM recommended

### Installation

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd LLM-RAG-SimGame
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Start Neo4j Database**
   ```bash
   docker run -d \
     --name neo4j \
     -p 7474:7474 -p 7687:7687 \
     -e NEO4J_AUTH=neo4j/password \
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

## 🔧 Core Components

- **CPE Parser System**: Parses CPE 2.3 strings with vendor normalization
- **Enhanced Neo4j Loader**: Loads rich CVE metadata and product ecosystem
- **Graph Analytics**: Vulnerability insights and trend analysis
- **RAG System**: Semantic search and retrieval for CVE analysis

## 📈 Key Features

- **Rich CVE Metadata**: CVSS scores, attack vectors, CWE/CAPEC mappings
- **Product Ecosystem**: Vendor normalization, version information, criticality scoring
- **Graph Analytics**: Vulnerability distribution, risk assessment, trend analysis
- **Semantic Search**: Natural language queries for vulnerability discovery
- **Vector Database**: 39,108 CVE chunks with 384-dimensional embeddings
- **Data Quality**: Automated duplicate detection, relationship validation
- **Extensible Design**: Modular architecture for additional data sources

## 🎯 Current Achievements

### **✅ Phase 1: Knowledge Graph Construction - COMPLETE**
- **38,995 CVEs** with rich metadata (CVSS scores, attack vectors, descriptions)
- **14,499 Products** from 4,117 vendors with version information
- **549 CWE** and **436 CAPEC** references for attack patterns
- **106,234 CVE-Product relationships** showing vulnerability impact
- **Neo4j Graph Database** with comprehensive schema and constraints

### **✅ Phase 2: RAG System Development - COMPLETE**
- **Vector Database**: 39,108 CVE document chunks in ChromaDB
- **Semantic Search**: Natural language vulnerability queries
- **Embedding Model**: all-MiniLM-L6-v2 (384-dimensional vectors)
- **Search Capabilities**: SQL injection, XSS, RCE, buffer overflow detection
- **Analytics**: Severity distribution, vendor analysis, similarity scoring
- **Rich Context**: CWE weaknesses, CAPEC attack patterns, MITRE ATT&CK techniques

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

## 🎯 Next Steps

- [ ] **LLM Integration**: Connect to GPT-4, Claude, or local models
- [ ] **Chat Interface**: Build conversational security assistant
- [ ] **Web Dashboard**: Create user-friendly interface
- [ ] **Real-time Updates**: Automated CVE data ingestion
- [ ] **Advanced Analytics**: Machine learning vulnerability prediction
- [ ] **MITRE ATT&CK Integration**: Threat intelligence mapping

## 📚 Documentation

- **[Knowledge Graph Details](src/constructors/README.md)** - Comprehensive KG documentation
- **[Query Examples](src/constructors/neo4j_queries.md)** - Cypher query examples
- **[Graph Analytics](src/constructors/graph_analytics.py)** - Analytics and insights
- **[RAG System](src/generators/rag_system.py)** - Retrieval-Augmented Generation system

## 🤝 Contributing

This project demonstrates advanced techniques in:
- **Graph Database Design** for security intelligence
- **CPE Parsing** and product extraction
- **CVE Data Processing** and enrichment
- **Graph Analytics** for vulnerability insights
- **RAG Systems** for semantic search and retrieval

Contributions are welcome for additional data source integrations, enhanced analytics algorithms, graph visualization improvements, and documentation.
