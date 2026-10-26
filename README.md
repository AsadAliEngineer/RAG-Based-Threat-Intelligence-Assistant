
<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/Yuni0217/CVE-KGRAG">
  </a>
  <br />

  <!-- Badges -->
  <img src="https://img.shields.io/github/repo-size/Yuning-J/CVE-KGRAG?style=for-the-badge" alt="GitHub repo size" height="25">
  <img src="https://img.shields.io/github/last-commit/Yuning-J/CVE-KGRAG?style=for-the-badge" alt="GitHub last commit" height="25">
  <img src="https://img.shields.io/github/license/Yuning-J/CVE-KGRAG?style=for-the-badge" alt="License" height="25">
  <br />
  
  <h3 align="center">CVE-KGRAG</h3>
  <p align="center">
    CVE Knowledge Graph & Security Intelligence System with RAG
  </p>
</p>

This project combines a comprehensive knowledge graph for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. We automate the process of curation, processing and correlation of CVE, CPE, CWE, CAPEC, MITRE ATT&CK, ExploitDB, CISA and other threat intelligence data.

## 📊 Current Statistics (Latest)

### **Knowledge Graph Coverage (1999-2025)**
- **190,310 CVEs** with rich metadata (CVSS, affected products, CWE, CAPEC, MITRE mappings)
- **124,290 products** from **19,692 vendors**
- **458 CWEs**, **428 CAPECs**, **169 MITRE techniques**, **37 MITRE tactics**
- **2.4M+ relationships** between entities
- **80% have CVSS v3** scores (152,676 CVEs)
- **1,060 CVEs** in Known Exploited Vulnerabilities (KEV) list

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

## 🚀 Quick Start

### **Option 1: Neo4j-Based Workflow (Full Graph Database)**

1. **Start Neo4j (Docker)**
   ```bash
   cp .env.example .env  # Set your own password in .env
   docker-compose up -d
   ```

2. **Download All CVE Data (1999-2025)**
   ```bash
   python scripts/download_all_cves.py
   ```
   This will download all CVE data from NVD into `data/CVE/zip/`.

3. **Run the Data Pipeline**
   ```bash
   # Collect and process data
   python src/collectors/main_collector.py
   python src/processors/process_all_cves.py

   # Parse CPEs and extract products/vendors
   python src/constructors/run_cpe_extraction.py

   # Build the knowledge graph in Neo4j
   python src/constructors/setup_neo4j_schema.py
   python src/constructors/enhanced_neo4j_loader.py --stats
   ```

4. **Export for RAG & Run RAG System**
   ```bash
   # Export KG data for RAG
   python -m src.generators.export_kg_for_rag --full

   # Build vector DB and search
   python -m src.generators.rag_system --build
   python -m src.generators.rag_system --search "SQL injection vulnerabilities"
   ```

### **Option 2: Non-Neo4j Workflow (JSON-Based, Recommended for Development)**

1. **Download All CVE Data (1999-2025)**
   ```bash
   python scripts/download_all_cves.py
   ```

2. **Run the Data Pipeline**
   ```bash
   # Collect and process data
   python src/collectors/main_collector.py
   python src/processors/process_all_cves.py

   # Parse CPEs and extract products/vendors
   python src/constructors/run_cpe_extraction.py

   # Build the knowledge graph (JSON-based, no Neo4j required)
   python src/constructors/kg_builder_without_neo4j.py
   ```

3. **Export for RAG System**
   ```bash
   # Export KG data for RAG (JSON-based)
   python src/generators/export_kg_for_rag_without_neo4j.py --full
   ```

4. **Build RAG System (Development Phase)**
   ```bash
   # Install RAG dependencies
   pip install fastapi uvicorn chromadb sentence-transformers ollama pydantic

   # Set up Ollama with Llama 3.1
   ollama pull llama3.1:8b

   # Run RAG system (implementation in progress)
   # python src/rag_system/api_server.py
   ```

## 🏗️ Architecture Overview

### **Data Pipeline**
```
Raw CVE Data (NVD) → Processed CVE Data → CPE Extraction → Knowledge Graph → RAG Exports
```

### **Knowledge Graph Structure**
```
Nodes: CVEs, Products, Vendors, CWEs, CAPECs, MITRE Techniques, MITRE Tactics
Relationships: CVE→Product, CVE→CWE, CVE→CAPEC, CVE→MITRE, Product→Vendor
```

### **RAG System Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Query Input   │───▶│  Hybrid Search  │───▶│  Vector Search  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Graph Search   │    │  LLM Response   │
                       └─────────────────┘    └─────────────────┘
```

## 📁 Project Structure

```
src/
├── collectors/          # Data collection from various sources
├── processors/          # CVE processing and enrichment
├── constructors/        # Knowledge graph construction
│   ├── kg_builder_without_neo4j.py    # JSON-based KG builder
│   ├── enhanced_neo4j_loader.py       # Neo4j-based KG loader
│   └── run_cpe_extraction.py          # CPE parsing
├── generators/          # RAG system generation
│   ├── export_kg_for_rag_without_neo4j.py  # JSON-based export
│   └── export_kg_for_rag.py                 # Neo4j-based export
└── rag_system/          # RAG system implementation (in progress)

data/
├── CVE/                 # Raw CVE data from NVD
├── CTI/                 # Threat intelligence data
├── knowledge_base/      # Processed data and exports
│   ├── enhanced_documents_cve_*.json  # Processed CVEs by year
│   ├── cpe_parsing_results_full.json  # Product/vendor data
│   ├── knowledge_graph/               # JSON-based KG
│   └── rag_exports/                   # RAG-ready data
└── knowledge_graph/     # Neo4j-based KG (if using Neo4j)
```

## 🧪 Testing

```bash
pytest
```

## 🔧 Configuration

- **Main config**: `config.py`
- **RAG config**: `src/generators/rag_config.py`
- **Example Cypher queries**: `src/constructors/neo4j_queries.md`

## 📚 Documentation

- **Constructors README**: `src/constructors/README.md` - Detailed knowledge graph documentation
- **For new data types or advanced usage**: See in-code docstrings and comments

## 🚀 Next Steps (Development Phase)

### **RAG System Implementation**
1. **Vector Database Setup** (ChromaDB)
2. **Embedding Generation** (BGE-Large-EN)
3. **LLM Integration** (Ollama + Llama 3.1)
4. **FastAPI Service** (Query Interface)
5. **Hybrid Search Engine** (Vector + Keyword + Graph)

### **Technology Stack (Development)**
- **Vector DB**: ChromaDB (local, free)
- **Embeddings**: BGE-Large-EN (open source, excellent quality)
- **LLM**: Llama 3.1 8B via Ollama (open source, good performance)
- **API Framework**: FastAPI (modern, fast, async)
- **Data Processing**: Pydantic (type safety)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
