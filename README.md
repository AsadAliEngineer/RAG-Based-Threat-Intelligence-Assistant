
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
    CVE Knowledge Graph & Security Intelligence System with Enhanced RAG
  </p>
</p>

This project combines a comprehensive knowledge graph for structured vulnerability data and relationships with an enhanced Retrieval-Augmented Generation (RAG) system for semantic search. We automate the process of curation, processing and correlation of CVE, CPE, CWE, CAPEC, MITRE ATT&CK, ExploitDB, CISA and other threat intelligence data.


## Current Statistics (Latest)

### **Knowledge Graph Coverage (1999-2025)**
- **190,310 CVEs** with rich metadata (CVSS, affected products, CWE, CAPEC, MITRE mappings)
- **124,290 products** from **19,692 vendors**
- **458 CWEs**, **428 CAPECs**, **169 MITRE techniques**, **37 MITRE tactics**
- **2.4M+ relationships** between entities
- **80% have CVSS v3** scores (152,676 CVEs)
- **1,060 CVEs** in Known Exploited Vulnerabilities (KEV) list

### **NetworkX Graph Statistics**
- **335,178 nodes** (CVEs, Products, Vendors, CWEs, CAPECs)
- **1,126,306 edges** (relationships between entities)
- **246 vulnerability clusters** based on CWE and product relationships
- **Graph density**: 0.000010 (sparse, efficient graph structure)

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

# Quick Start

## **Prerequisites**
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Ollama from https://ollama.ai
# Then pull required models:
ollama pull llama3.1:8b
ollama pull llama3.1:70b  # Optional: for higher quality responses
```

## **Complete Setup Workflow**

### **Step 1: Download CVE Data (1999-2025)**
```bash
# Download all CVE data from NVD
python scripts/download_all_cves.py
```

### **Step 2: Process and Build Knowledge Graph**
```bash
# Collect and process threat intelligence data
python src/collectors/main_collector.py

# Process all CVE data with enrichment
python src/processors/process_all_cves.py

# Parse CPEs and extract products/vendors
python src/constructors/run_cpe_extraction.py

# Build the knowledge graph (JSON-based, no Neo4j required)
python src/constructors/kg_builder_without_neo4j.py
```

### **Step 3: Build Enhanced Graph Features**
```bash
# Build NetworkX graph with similarity features and centrality calculations
python src/constructors/networkx_graph_builder.py
```

### **Step 4: Build Vector Database**
```bash

python -m src.generators.export_kg_for_rag_direct --stats

# Build vector database with graph-enhanced embeddings
python -m src.generators.rag_system --build
```
### **Step 5: LLM Training (Optional)**
### **Step 5a: Prepare Training Dataset**
```bash
# Create training dataset from knowledge graph
python src/training/dataset_preparation.py

# Analyze data quality if needed
python src/training/run_data_analysis.py
```

### **Step 5b: Check System Requirements**
```bash
# Verify system can handle training
python src/training/system_check.py
```

### **Step 5c: Run Fine-Tuning**
```bash
python src/training/production_training.py
```

### **Step 5d: Test Fine-Tuned Model**
```bash
# Test the fine-tuned model
python src/training/hf_inference_engine.py
```

### **Step 6: Start Services**
```bash
# Terminal 1: Start API Server
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Start Gradio UI (Optional)
python src/ui/gradio_app.py
```

## **Test the System**
```bash

# Test standard RAG
python -m src.generators.rag_system --search "Log4j vulnerability"

# Test API endpoints
curl -X POST http://localhost:8000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "SQL injection vulnerabilities", "top_k": 5}'
```

## **Access Interfaces**
-  Gradio UI: http://localhost:7860
-  API Documentatio*: http://localhost:8000/docs  
-  API Health Check: http://localhost:8000/api/v1/health

##  Architecture Overview

### **Data Pipeline**
```
Raw CVE Data (NVD) → Processed CVE Data → CPE Extraction → Knowledge Graph → NetworkX Graph → Vector DB
```

### **Knowledge Graph Structure**
```
Nodes: CVEs, Products, Vendors, CWEs, CAPECs, MITRE Techniques, MITRE Tactics
Relationships: CVE→Product, CVE→CWE, CVE→CAPEC, CVE→MITRE, Product→Vendor
```

### **Enhanced RAG System Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Query Input   │───▶│  FastAPI API    │───▶│  Hybrid Search  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Gradio UI      │    │  Graph Features │
                       └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  ChromaDB       │    │  NetworkX Graph │
                       └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Vector Search  │    │  Similarity     │
                       └─────────────────┘    │  Matrix         │
                                │             └─────────────────┘
                                ▼
                       ┌─────────────────┐
                       │  LLM Response   │
                       └─────────────────┘
```

### Configuration

- **Main config**: `config.py`
- **RAG config**: `src/generators/rag_config.py`
- **NetworkX config**: Built into `networkx_graph_builder.py`
- **Example Cypher queries**: `src/constructors/neo4j_queries.md`

### **API Endpoints**
- `POST /api/v1/query` - Full RAG queries with LLM responses
- `POST /api/v1/search` - Vector search only
- `POST /api/v1/summary` - Statistical analysis
- `GET /api/v1/health` - System health check

## License

This project is licensed under the MIT License - see the LICENSE file for details.
