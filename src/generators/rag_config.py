"""
Centralized configuration for the RAG system.
Edit this file to update paths, model names, and other settings in one place.
"""

import os
import torch
from pathlib import Path

# Base data directory (edit as needed)
BASE_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/knowledge_base'))

# Exported CVE documents for RAG - Use the enhanced documents with full knowledge graph data
CVE_DATA_PATH = os.path.join(BASE_DATA_DIR, 'rag_exports/cve_documents_for_rag.json')  # Full knowledge graph data

# Year-based data paths
CVE_YEAR_PATHS = {
    '2021': os.path.join(BASE_DATA_DIR, 'enhanced_documents_cve_2021.json'),
    '2022': os.path.join(BASE_DATA_DIR, 'enhanced_documents_cve_2022.json'),
    '2023': os.path.join(BASE_DATA_DIR, 'enhanced_documents_cve_2023.json'),
    '2024': os.path.join(BASE_DATA_DIR, 'enhanced_documents_cve_2024.json'),
    '2025': os.path.join(BASE_DATA_DIR, 'enhanced_documents_cve_2025.json'),
}

# Vector database directory
VECTOR_DB_PATH = os.path.join(BASE_DATA_DIR, 'vector_db_new')

# Embedding model name (HuggingFace/SBERT) - Updated to use publicly available model
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"  # Produces 384-dimensional embeddings, publicly available

# GPU Configuration for RTX A6000
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
EMBEDDING_BATCH_SIZE = 256  # Optimized for RTX A6000
MAX_SEQ_LENGTH = 512

# Chunking parameters
CHUNK_SIZE = 512
CHUNK_OVERLAP = 50

# Search parameters
VECTOR_SEARCH_TOP_K = 50
RERANK_TOP_K = 10
HYBRID_ALPHA = 0.7  # Weight for vector search vs keyword search

# Performance tuning
MAX_QUERY_LENGTH = 1000
MAX_CONTEXT_LENGTH = 8000
MAX_RESPONSE_LENGTH = 2000
MAX_SEARCH_RESULTS = 50
MAX_CHUNKS_PER_RESPONSE = 1000

# Timeouts (in seconds)
EMBEDDING_TIMEOUT = 5
SEARCH_TIMEOUT = 10
LLM_GENERATION_TIMEOUT = 30
QUERY_ROUTING_TIMEOUT = 5
SUMMARY_TIMEOUT = 15

# API rate limiting
MAX_REQUESTS_PER_MINUTE = 60
RATE_LIMIT_WINDOW = 60  # seconds

# Hugging Face Access Token for Llama models
def get_hf_token():
    """Get Hugging Face access token from llama_token.txt"""
    token_file = Path(__file__).parent.parent.parent / "llama_token.txt"
    if token_file.exists():
        with open(token_file, 'r') as f:
            return f.read().strip()
    return os.getenv('HF_TOKEN', '')

HF_TOKEN = get_hf_token()

# LLM Configuration
USE_OLLAMA = os.getenv('USE_OLLAMA', 'false').lower() == 'true'  # Default to Hugging Face
OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
OLLAMA_MODEL_PRIMARY = os.getenv('OLLAMA_MODEL_PRIMARY', 'llama3.1:8b-instruct-fp16')
OLLAMA_MODEL_FAST = os.getenv('OLLAMA_MODEL_FAST', 'llama3.1:8b-instruct-fp16')

# Alternative: Direct Hugging Face models (if not using Ollama)
HF_MODEL_PRIMARY = "meta-llama/Llama-3.1-8B-Instruct"
HF_MODEL_FAST = "meta-llama/Llama-3.1-8B-Instruct"

# API Configuration
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', '8000'))
API_WORKERS = int(os.getenv('API_WORKERS', '1'))

# Neo4j connection (for export)
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'password')  # Use env var or .env for security

# Logging level
LOGGING_LEVEL = os.getenv('RAG_LOGGING_LEVEL', 'INFO') 