
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

## 🚀 Quick Start

1. **Start Neo4j (Docker)**
   ```bash
   cp .env.example .env  # Set your own password in .env
   docker-compose up -d
   ```

2. **Run the Data Pipeline**
   ```bash
   # Collect and process data
   python src/collectors/main_collector.py
   python src/processors/process_all_cves.py

   # Parse CPEs and extract products/vendors
   python src/constructors/run_cpe_extraction.py

   # Build the knowledge graph
   python src/constructors/setup_neo4j_schema.py
   python src/constructors/enhanced_neo4j_loader.py --stats
   ```

3. **Export for RAG & Run RAG System**
   ```bash
   # Export KG data for RAG
   python -m src.generators.export_kg_for_rag --full

   # Build vector DB and search
   python -m src.generators.rag_system --build
   python -m src.generators.rag_system --search "SQL injection vulnerabilities"
   ```

---

### 🧪 Testing

```bash
pytest
```

---

### 📁 Project Structure

```
src/         # All code (collectors, processors, constructors, generators)
data/        # All data (raw, processed, knowledge_base, knowledge_graph)
```

---

### 📚 More

- All config: `src/generators/rag_config.py`
- Example Cypher queries: `src/constructors/neo4j_queries.md`
- For new data types or advanced usage, see in-code docstrings and comments.
