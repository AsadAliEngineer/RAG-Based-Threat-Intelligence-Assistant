# 🗂️ Knowledge Graph Data Storage

This directory contains the constructed knowledge graph data, analytics, and exports from the Neo4j database.

## 📁 Directory Structure

```
knowledge_graph/
├── analytics/         # Graph analytics and statistics (the current one is based on 2024 CVEs only, feel free to add more)
├── exports/           # Data exports from Neo4j
├── backups/           # Database backups and snapshots
└── README.md          # This file
```

## 📊 Contents

### **analytics/**
- Graph statistics and analytics reports
- Vulnerability trend analysis
- Data quality reports
- Performance metrics

### **exports/**
- Neo4j database exports (CSV, JSON)
- Subgraph exports for specific analysis
- Relationship data dumps
- Node property exports

### **backups/**
- Neo4j database backups
- Graph snapshots at different points in time
- Configuration backups
- Schema version history

## 🔄 Data Flow

```
Raw Data (CVE/, CTI/) 
    ↓
Processed Data (knowledge_base/)
    ↓
Knowledge Graph Construction (src/constructors/)
    ↓
Neo4j Database
    ↓
Analytics & Exports (knowledge_graph/)
```

## 📝 Usage

### **Generating Exports**
```bash
# Export all nodes and relationships
cypher-shell -u neo4j -p password \
  "MATCH (n) RETURN n" > exports/all_nodes.csv

# Export specific node types
cypher-shell -u neo4j -p password \
  "MATCH (cve:CVE) RETURN cve" > exports/cve_nodes.csv
```

### **Creating Backups**
```bash
# Neo4j backup
neo4j-admin backup --database=neo4j --to=/path/to/backups/

# Graph analytics backup
cp analytics/graph_analytics.json backups/$(date +%Y%m%d)_analytics.json
```

## 🔗 Related Files

- **Source Data**: `../knowledge_base/` - Processed CVE and CPE data
- **Construction Scripts**: `../../src/constructors/` - KG building components
- **Analytics Scripts**: `../../src/constructors/graph_analytics.py` 
