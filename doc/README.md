
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

# Install training dependencies (including bitsandbytes for quantization)
python scripts/install_training_deps.py

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
# Build vector database with graph-enhanced embeddings
python -m src.generators.rag_system --build
```

### **Step 5: Start Services**
```bash
# Terminal 1: Start API Server
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: Start Gradio UI (Optional)
python src/ui/gradio_app.py
```

## **LLM Fine-Tuning (Optional)**

### **Step 5a: Prepare Training Dataset**
```bash
# Create training dataset from knowledge graph
python src/training/dataset_preparation.py

# Analyze data quality (recommended)
python src/training/run_data_analysis.py

# Fix data quality issues if needed
python src/training/dataset_preparation.py  # Now includes data quality fixes
```

### **Step 5b: Check System Requirements**
```bash
# Verify system can handle training
python src/training/system_check.py
```

### **Step 5c: Run Fine-Tuning**
```bash
# Option 1: Production training (recommended)
python src/training/production_training.py

# Option 2: Custom fine-tuning with specific parameters
python src/training/fine_tuning_pipeline.py --subset 50 --learning_rate 1e-6
```

### **Step 5d: Test Fine-Tuned Model**
```bash
# Test the fine-tuned model
python src/training/hf_inference_engine.py

# Test with KG-enhanced RAG system
python test_kg_enhanced_rag.py
```

## **Test the System**
```bash
# Test KG-enhanced RAG system
python test_kg_enhanced_rag.py

# Test API integration
python test_kg_enhanced_rag.py --api

# Test standard RAG
python -m src.generators.rag_system --search "Log4j vulnerability"

# Test API endpoints
curl -X POST http://localhost:8000/enhanced-query \
  -H "Content-Type: application/json" \
  -d '{"query": "SQL injection vulnerabilities", "top_k": 5}'
```

## **Available Scripts**

### **Core Training Infrastructure (`src/training/`)**
- `production_training.py` - Production-ready fine-tuning with proven optimal settings
- `fine_tuning_pipeline.py` - Main fine-tuning pipeline for CVE LLM (customizable)
- `dataset_preparation.py` - Create training datasets from knowledge graph (includes data quality fixes)
- `hf_inference_engine.py` - HuggingFace inference engine (supports both base and fine-tuned models)
- `ollama_inference_engine.py` - Alternative Ollama-based inference engine
- `analyze_training_data.py` - Comprehensive data quality analysis
- `run_data_analysis.py` - Quick data analysis runner
- `system_check.py` - Check system resources and dependencies

### **Utility Scripts (`scripts/`)**
- `check_compatibility.py` - Check PyTorch, CUDA, and bitsandbytes version compatibility
- `install_training_deps.py` - Install training dependencies (including bitsandbytes)
- `prepare_training_dataset.py` - Prepare existing dataset for fine-tuning
- `build_indexes.py` - Build search indexes for CVE data
- `run_phase2_pipeline.py` - Run knowledge graph construction
- `start_services.py` - Start API and services
- `setup_environment.py` - Environment setup and validation
- `monitor_performance.py` - Performance monitoring
- `download_all_cves.py` - Download CVE data

### **Training Datasets**
- `enhanced_training_dataset_with_mitigations.json` (1,500 entries) - Ready for fine-tuning
- `enhanced_training_dataset_fixed.json` - Data quality improved version (recommended)
- `enhanced_cve_dataset_with_mitigations.json` (190K entries) - Raw CVE data

## **Access Interfaces**
- ** Gradio UI**: http://localhost:7860
- ** API Documentation**: http://localhost:8000/docs  
- ** API Health Check**: http://localhost:8000/api/v1/health

##  Architecture Overview

### **Data Pipeline**
```
Raw CVE Data (NVD) → Processed CVE Data → CPE Extraction → Knowledge Graph → NetworkX Graph → Vector DB → KG-Enhanced RAG
```

### **KG Enhancement Features**
- **Related CVEs**: Find similar vulnerabilities using graph relationships
- **Vendor Patterns**: Analyze vulnerability patterns across vendors
- **Product Patterns**: Identify common weaknesses in products
- **Attack Chains**: Build MITRE ATT&CK attack chains
- **Centrality Metrics**: Calculate vulnerability importance in the graph
- **Relationship Insights**: Generate contextual insights about CVE relationships

### **Knowledge Graph Structure**
```
Nodes: CVEs, Products, Vendors, CWEs, CAPECs, MITRE Techniques, MITRE Tactics
Relationships: CVE→Product, CVE→CWE, CVE→CAPEC, CVE→MITRE, Product→Vendor
```

### **Enhanced RAG System Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Query Input   │───▶│  FastAPI API    │───▶│  KG-Enhanced    │
└─────────────────┘    └─────────────────┘    │  RAG System     │
                                │             └─────────────────┘
                                ▼                       │
                       ┌─────────────────┐              │
                       │  Gradio UI      │              │
                       └─────────────────┘              │
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  ChromaDB       │    │  NetworkX Graph │
                       │  Vector Search  │    │  KG Enhancement │
                       └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Fine-tuned     │    │  Relationship   │
                       │  LLM Response   │    │  Insights       │
                       └─────────────────┘    └─────────────────┘
```

### Configuration

- **Main config**: `config.py`
- **RAG config**: `src/generators/rag_config.py`
- **NetworkX config**: Built into `networkx_graph_builder.py`
- **Training config**: Built into `src/training/fine_tuning_pipeline.py`
- **Example Cypher queries**: `src/constructors/neo4j_queries.md`

### **Training Configuration**
The production training pipeline uses proven optimal settings:
- **Model**: `meta-llama/Meta-Llama-3-8B` (configurable)
- **Batch Size**: 1 (optimized for stability)
- **Learning Rate**: 1e-6 (proven optimal from scaling tests)
- **Max Steps**: 100 (configurable)
- **Max Length**: 256 tokens (optimized for CVE analysis)
- **LoRA Rank**: 1 (minimal, prevents overfitting)
- **Weight Decay**: 0.999 (high regularization)
- **Mixed Precision**: FP16 (GPU only)

### **Training Requirements**
- **GPU**: 8GB+ VRAM recommended (4GB minimum)
- **Memory**: 16GB+ RAM
- **Storage**: 20GB+ free space
- **Dependencies**: `python scripts/install_training_deps.py`

### **Bitsandbytes Compatibility**
The fine-tuning pipeline uses 4-bit quantization for memory efficiency. If `bitsandbytes` installation fails:
- **Fallback**: Automatically uses 16-bit precision (more memory usage)
- **Compatibility Check**: `python scripts/check_compatibility.py` - Ensures PyTorch, CUDA, and bitsandbytes versions are compatible
- **Manual Install**: `pip install bitsandbytes`
- **Alternative**: Use CPU training or smaller models

### **API Endpoints**
- `POST /query` - Standard RAG queries with LLM responses
- `POST /enhanced-query` - KG-enhanced queries with fine-tuned model
- `POST /remediation` - Specialized remediation analysis
- `POST /search` - Vector search only
- `POST /summary` - Statistical analysis
- `GET /health` - System health check

### **Training Workflow**
1. **Dataset Preparation**: Create training dataset from knowledge graph
2. **Data Quality Analysis**: Analyze and fix data quality issues
3. **System Check**: Verify hardware and dependencies
4. **Fine-Tuning**: Train specialized CVE LLM with proven settings (1-2 hours)
5. **Testing**: Evaluate model performance with KG-enhanced RAG
6. **Integration**: Use fine-tuned model in enhanced RAG system

### **Expected Training Outcomes**
- **Model Location**: `models/fine_tuned_cve_production/`
- **Training Time**: 1-2 hours (GPU) / 8+ hours (CPU)
- **Model Size**: ~16GB (8B parameters with LoRA)
- **Performance**: Enhanced CVE analysis with KG context
- **Integration**: Seamless integration with KG-enhanced RAG system
- **Testing**: Use `test_kg_enhanced_rag.py` for comprehensive testing

## License

This project is licensed under the MIT License - see the LICENSE file for details.
