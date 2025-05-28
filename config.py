"""
Configuration management for the RAG chatbot
"""

import os
from typing import Optional
from pathlib import Path


class Config:
    """Centralized configuration for all data paths and API endpoints."""
    def __init__(self):
        # Project root is the directory containing this config.py
        self.project_root = Path(__file__).resolve().parent
        self.base_data_dir = self.project_root / "data"
        self.knowledge_base_dir = self.base_data_dir / "knowledge_base"
        self.enhanced_documents_path = self._resolve_enhanced_documents_path()
        self.cti_data_dir = self.base_data_dir / "CTI" / "raw"
        self.cti_docs_dir = self.base_data_dir / "CTI" / "docs"
        self.system_data_dir = self.base_data_dir / "system"
        self.logs_dir = self.base_data_dir / "logs"
        self.csaf_dir = self.cti_data_dir / "csaf"
        self.known_exploited_vuln_csv = self.cti_data_dir / "known_exploited_vulnerabilities.csv"
        self.es_file = self.system_data_dir / "ES_enriched.json"


        self.api_endpoints = {
            "mitre_attack": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        }

        self.PATHS = {
            "cti_data_dir": self.cti_data_dir,
            "cti_docs_dir": self.cti_docs_dir,
            "system_data_dir": self.system_data_dir,
            "logs_dir": self.logs_dir
        }

        
        # Embedding Configuration
        self.embedding_model_name = os.getenv("EMBEDDING_MODEL_NAME", "all-MiniLM-L6-v2")
        
        # Search Configuration
        self.default_top_k = int(os.getenv("DEFAULT_TOP_K", "5"))
        self.semantic_weight = float(os.getenv("SEMANTIC_WEIGHT", "0.7"))
        
        # Data Configuration
        self.data_dir = os.getenv("DATA_DIR", "data")
        self.cache_dir = os.getenv("CACHE_DIR", "data/knowledge_base")
        
        # Device Configuration
        self.device = os.getenv("DEVICE", "cpu")  # cpu, cuda, mps 

    def _resolve_enhanced_documents_path(self) -> Path:
        """Pick the latest available enhanced CVE document file, with a stable fallback."""
        explicit_path = os.getenv("ENHANCED_DOCUMENTS_PATH")
        if explicit_path:
            return Path(explicit_path)

        candidates = sorted(self.knowledge_base_dir.glob("enhanced_documents_cve_*.json"))
        if candidates:
            return candidates[-1]

        return self.knowledge_base_dir / "enhanced_documents_cve_2024.json"
