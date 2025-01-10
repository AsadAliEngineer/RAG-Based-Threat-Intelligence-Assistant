
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
    CVE Knowledge Graph & Security Intelligence System.
 
  </p>
</p>

This project combines a Neo4j knowledge graph (KG) for structured vulnerability data and relationships with a Retrieval-Augmented Generation (RAG) system for semantic search. We also automate the process of curation, processing and correlation of CVE, CPE, CWE, CAPEC, MITRE ATT&CK, ExploitDB, CISA and other threat intelligence data.

## Usage Examples

### **RAG System Queries**
```python
from generators.rag_system import CVERAGSystem

# Initialize RAG system
rag = CVERAGSystem()

# Search for vulnerabilities with rich context
results = rag.search_cves("SQL injection vulnerabilities", n_results=3)

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

##  Quick Start

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

   Put your downloaded zipped CVE in data/CVE/zip folder, and proceed the following:
   
   ```bash
   cd src/collectors
   python main_collector.py
   # Downloads and preprocesses CVE, CPE, CWE, CAPEC, and threat intelligence data.
   # Produces raw and intermediate files in data/knowledge_base and data/CVE.
   
   cd ../processors
   python process_all_cves.py
   # Correlates and enriches the collected data, producing processed CVE and CPE documents for graph construction.
   ```

5. **Parse CPEs and Extract Products/Vendors**
   ```bash
   cd ../constructors
   python run_cpe_extraction.py
   # Parses CPE strings from processed CVE data, extracts and normalizes products and vendors,
   # and outputs structured product/vendor data for graph construction.
   ```
   > **Note:** Processed and parsed data are not included in the repository. You must run the collection, processing, and CPE parsing steps to generate the required files before building the knowledge graph.

6. **Build Knowledge Graph**
   ```bash
   cd ../constructors
   python setup_neo4j_schema.py
   python enhanced_neo4j_loader.py --stats
   ```

7. **Test RAG System**
   ```bash
   cd ../generators
   python rag_system.py
   ```

8. **Explore the Graph**
   - **Neo4j Browser**: need to login
   - **Analytics**: `python graph_analytics.py`
   - **Query Examples**: See `neo4j_queries.md`


## 🧩 Modular CTI Data Conversion Pipeline

The CTI data conversion process is now fully modular and extensible. Each data type (KEV, CSAF, CAPEC, ATT&CK, etc.) is handled by its own converter class, and the main orchestrator script runs all conversions in a clean, maintainable way.

### **How to Run the Modular CTI Conversion**

From the project root:

```bash
cd src/collectors/data_collection
python convert_cti_raw_to_docs.py
```

This will:
- Convert all supported CTI data sources (KEV, CSAF, CAPEC, ATT&CK, etc.)
- Output processed JSON documents to the appropriate folders in `data/CTI/docs/`
- Log the process to `data/logs/cti_conversion.log`

### **Adding New Data Types**
To add a new data type, simply implement a new converter class in `cti_converters/` and add it to the orchestrator script.


## 🧪 Testing

To run all tests (requires pytest):

```bash
pip install pytest
pytest src/collectors/data_collection
```

If you add new modules or converters, add corresponding tests in the same directory or a `tests/` subfolder.

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


## 📚 Documentation

- **[Knowledge Graph Details](src/constructors/README.md)** - Comprehensive KG documentation
- **[Query Examples](src/constructors/neo4j_queries.md)** - Cypher query examples

## 🤝 Contributing

Contributions are welcome for additional data source integrations, enhanced analytics algorithms, graph visualization improvements, and documentation.

## Neo4j Setup with Docker Compose

### 1. Configure Environment Variables
Copy the example environment file and set your own password:

```bash
cp .env.example .env
# Then edit .env to set your own password
```

Do NOT commit your real .env file to version control.

## RAG System and Knowledge Graph Export: Quick Usage

All configuration is centralized in `src/generators/rag_config.py`.

### Export Knowledge Graph Data

From the project root, run:

- Export CVE documents:
  ```bash
  python -m src.generators.export_kg_for_rag --cve
  ```
- Export product-vendor data:
  ```bash
  python -m src.generators.export_kg_for_rag --product_vendor
  ```
- Export relationships:
  ```bash
  python -m src.generators.export_kg_for_rag --relationships
  ```
- Export statistics:
  ```bash
  python -m src.generators.export_kg_for_rag --stats
  ```
- Run full export (all steps):
  ```bash
  python -m src.generators.export_kg_for_rag --full
  ```

### Run the RAG System

- Build the vector database:
  ```bash
  python -m src.generators.rag_system --build
  ```
- Search for a query:
  ```bash
  python -m src.generators.rag_system --search "SQL injection vulnerabilities"
  ```
- Get a vulnerability summary:
  ```bash
  python -m src.generators.rag_system --summary "SQL injection"
  ```

For more options, use `--help` with either script.
