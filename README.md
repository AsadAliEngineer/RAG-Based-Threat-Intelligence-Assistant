
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

This project combines a comprehensive knowledge graph for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. We automate the process of curation, processing and correlation of CVE, CPE, CWE, CAPEC, MITRE ATT&CK, ExploitDB, CISA and other threat intelligence data. Also integrated Llama model for performance optimization.

## Current Statistics (Latest)

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

# Implementation Guide

## **Option 1: Start RAG System (Recommended)**

### **Prerequisites**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Ollama from https://ollama.ai
# Then pull required models:
ollama pull llama3.1:8b
ollama pull llama3.1:70b  # Optional: for higher quality responses
```

### **Download All CVE Data (1999-2025)**
```bash
python scripts/download_all_cves.py
```

### **Run the Data Pipeline**
```bash
# Collect and process data
python src/collectors/main_collector.py
python src/processors/process_all_cves.py

# Parse CPEs and extract products/vendors
python src/constructors/run_cpe_extraction.py
```

### **Construction of KG and RAG System**
```bash
# Build the knowledge graph (JSON-based, no Neo4j required)
python src/constructors/kg_builder_without_neo4j.py

# Export KG data for RAG (JSON-based)
python src/generators/export_kg_for_rag_without_neo4j.py --full
```

### **Build Vector Database**
```bash
# Build the vector database for semantic search
python -m src.generators.rag_system --build
```
### **Start the System**

#### **Method A: Individual Services**
```bash
# Terminal 1: Start API Server
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Start Gradio UI (Optional)
python src/ui/gradio_app.py
```

#### **Method B: One-Command Startup**
```bash
# Start all services at once
python scripts/start_services.py
```

### **Test the System**
```bash
# Test search functionality
curl -X POST http://localhost:8000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "Log4j vulnerability", "top_k": 5}'

# Test RAG query
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CVE-2021-44228?", "top_k": 5, "use_large_model": false}'
```

## **Option 2: Neo4j-Based Workflow**

1. **Start Neo4j (Docker)**
   ```bash
   cp .env.example .env  # Set your own password in .env
   docker-compose up -d
   ```

2. **Download All CVE Data (1999-2025)**
   ```bash
   python scripts/download_all_cves.py
   ```

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


## Architecture Overview

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
│   Query Input   │───▶│  FastAPI API    │───▶│  Vector Search  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Gradio UI      │    │  LLM Response   │
                       └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  ChromaDB       │    │  Ollama LLM     │
                       └─────────────────┘    └─────────────────┘
```


## Project Structure

```
src/
├── api/                 # FastAPI server implementation
│   ├── main.py          # Main API application
│   ├── routes.py        # API endpoints
│   └── models.py        # Pydantic models
├── ui/                  # User interfaces
│   └── gradio_app.py    # Gradio web interface
├── collectors/          # Data collection from various sources
├── processors/          # CVE processing and enrichment
├── constructors/        # Knowledge graph construction
│   ├── kg_builder_without_neo4j.py    # JSON-based KG builder
│   ├── enhanced_neo4j_loader.py       # Neo4j-based KG loader
│   └── run_cpe_extraction.py          # CPE parsing
├── generators/          # RAG system generation
│   ├── export_kg_for_rag_without_neo4j.py  # JSON-based export
│   ├── export_kg_for_rag.py                 # Neo4j-based export
│   └── rag_system.py    # RAG system implementation
└── retrieval/           # Search and retrieval components
    └── query_router.py  # Query routing logic

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

### **API Endpoints**
- `POST /api/v1/query` - Full RAG queries with LLM responses
- `POST /api/v1/search` - Vector search only
- `POST /api/v1/summary` - Statistical analysis
- `GET /api/v1/health` - System health check
  
## Testing

```bash
pytest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

