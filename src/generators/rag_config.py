"""
Centralized configuration for the RAG system.
Edit this file to update paths, model names, and other settings in one place.
"""

import os

# Base data directory (edit as needed)
BASE_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/knowledge_graph'))

# Exported CVE documents for RAG
CVE_DATA_PATH = os.path.join(BASE_DATA_DIR, 'exports/cve_documents_for_rag.json')

# Vector database directory
VECTOR_DB_PATH = os.path.join(BASE_DATA_DIR, 'vector_db')

# Embedding model name (HuggingFace/SBERT)
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# Chunking parameters
CHUNK_SIZE = 512
CHUNK_OVERLAP = 50

# Neo4j connection (for export)
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'password')  # Use env var or .env for security

# Logging level
LOGGING_LEVEL = os.getenv('RAG_LOGGING_LEVEL', 'INFO') 