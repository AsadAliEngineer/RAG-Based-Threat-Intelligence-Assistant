#!/usr/bin/env python3
"""
Environment setup script for the RAG system
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnvironmentSetup:
    """Setup environment for the RAG system"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.requirements_file = self.project_root / "requirements.txt"
        self.env_file = self.project_root / ".env"
        self.token_file = self.project_root / "llama_token.txt"
        
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.project_root / "data" / "knowledge_base" / "vector_db",
            self.project_root / "data" / "knowledge_base" / "rag_exports",
            self.project_root / "logs",
            self.project_root / "cache",
            self.project_root / "models"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def check_hf_token(self):
        """Check if Hugging Face token is available"""
        if self.token_file.exists():
            with open(self.token_file, 'r') as f:
                token = f.read().strip()
            if token and token.startswith('hf_'):
                logger.info("✅ Hugging Face token found")
                return True
            else:
                logger.warning("⚠️ Invalid Hugging Face token format")
                return False
        else:
            logger.warning("⚠️ No llama_token.txt found")
            return False
    
    def create_env_file(self):
        """Create .env file with default settings"""
        if not self.env_file.exists():
            env_content = """# RAG System Environment Variables

# GPU Configuration
CUDA_VISIBLE_DEVICES=0
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512

# LLM Configuration
USE_OLLAMA=true
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL_PRIMARY=llama3.1:70b-instruct-q4_K_M
OLLAMA_MODEL_FAST=llama3.1:8b-instruct-fp16

# Hugging Face Configuration (fallback)
HF_TOKEN=your_huggingface_token_here
HF_MODEL_PRIMARY=meta-llama/Llama-3.1-70B-Instruct
HF_MODEL_FAST=meta-llama/Llama-3.1-8B-Instruct

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=1

# Model Configuration
EMBEDDING_MODEL_NAME=BAAI/bge-large-en-v1.5
EMBEDDING_BATCH_SIZE=256
MAX_CONTEXT_LENGTH=8192

# Search Configuration
DEFAULT_TOP_K=10
SEMANTIC_WEIGHT=0.7

# Logging
RAG_LOGGING_LEVEL=INFO
"""
            with open(self.env_file, 'w') as f:
                f.write(env_content)
            logger.info(f"Created .env file: {self.env_file}")
        else:
            logger.info(f".env file already exists: {self.env_file}")
    
    def check_python_version(self):
        """Check Python version"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 10):
            logger.error("Python 3.10 or higher is required")
            return False
        logger.info(f"Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    
    def check_gpu(self):
        """Check GPU availability"""
        try:
            import torch
            if torch.cuda.is_available():
                gpu_name = torch.cuda.get_device_name(0)
                gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
                logger.info(f"GPU detected: {gpu_name} ({gpu_memory:.1f} GB)")
                return True
            else:
                logger.warning("No GPU detected. System will use CPU (slower performance)")
                return False
        except ImportError:
            logger.warning("PyTorch not installed. Cannot check GPU.")
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        if not self.requirements_file.exists():
            logger.error(f"Requirements file not found: {self.requirements_file}")
            return False
        
        try:
            logger.info("Installing Python dependencies...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(self.requirements_file)
            ], check=True)
            logger.info("Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            return False
    
    def check_ollama(self):
        """Check if Ollama is installed and running"""
        try:
            result = subprocess.run(["ollama", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Ollama found: {result.stdout.strip()}")
                return True
            else:
                logger.warning("Ollama not found or not working")
                return False
        except FileNotFoundError:
            logger.warning("Ollama not installed. Please install Ollama from https://ollama.ai")
            return False
    
    def download_ollama_models(self):
        """Download required Ollama models"""
        models = [
            "llama3.1:8b-instruct-fp16"
            # Removed 70B model to avoid disk space issues
            # "llama3.1:70b-instruct-q4_K_M"
        ]
        
        for model in models:
            try:
                logger.info(f"Downloading Ollama model: {model}")
                subprocess.run(["ollama", "pull", model], check=True)
                logger.info(f"Successfully downloaded: {model}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download {model}: {e}")
                return False
        
        return True
    
    def test_hf_models(self):
        """Test Hugging Face model access"""
        if not self.check_hf_token():
            return False
        
        try:
            import requests
            token = self.token_file.read_text().strip()
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test access to Llama models
            test_url = "https://huggingface.co/api/models/meta-llama/Llama-3.1-8B-Instruct"
            response = requests.get(test_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                logger.info("✅ Hugging Face models accessible")
                return True
            else:
                logger.warning(f"⚠️ Hugging Face access failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.warning(f"⚠️ Could not test Hugging Face access: {e}")
            return False
    
    def create_requirements_file(self):
        """Create requirements.txt if it doesn't exist"""
        if not self.requirements_file.exists():
            requirements = """# Core dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
pydantic-settings==2.1.0

# Vector database
chromadb==0.4.18

# Embeddings
sentence-transformers==2.2.2
torch==2.1.1
torchvision==0.16.1
torchaudio==2.1.1

# HTTP client
aiohttp==3.9.1
requests==2.31.0

# Data processing
numpy==1.24.3
pandas==2.1.4
tqdm==4.66.1

# UI
gradio==4.7.1

# Utilities
python-dotenv==1.0.0
psutil==5.9.6
"""
            with open(self.requirements_file, 'w') as f:
                f.write(requirements)
            logger.info(f"Created requirements.txt: {self.requirements_file}")
    
    def run_health_check(self):
        """Run health check on the system"""
        logger.info("Running health check...")
        
        checks = {
            "Python Version": self.check_python_version(),
            "GPU Available": self.check_gpu(),
            "Hugging Face Token": self.check_hf_token(),
            "Hugging Face Models": self.test_hf_models(),
            "Ollama Installed": self.check_ollama(),
            "Directories Created": True,  # Will be set after setup
            "Requirements File": self.requirements_file.exists()
        }
        
        logger.info("Health Check Results:")
        for check, status in checks.items():
            status_str = "✅ PASS" if status else "❌ FAIL"
            logger.info(f"  {check}: {status_str}")
        
        return all(checks.values())
    
    def run(self):
        """Run complete setup"""
        logger.info("🚀 Starting RAG System Environment Setup")
        logger.info("=" * 50)
        
        # Create requirements file
        self.create_requirements_file()
        
        # Setup directories
        self.setup_directories()
        
        # Create .env file
        self.create_env_file()
        
        # Install dependencies
        if not self.install_dependencies():
            logger.error("Failed to install dependencies")
            return False
        
        # Check Hugging Face token
        hf_available = self.check_hf_token() and self.test_hf_models()
        
        # Check Ollama
        ollama_available = self.check_ollama()
        if ollama_available:
            # Download models
            if not self.download_ollama_models():
                logger.warning("Failed to download some Ollama models")
        
        # Run health check
        health_ok = self.run_health_check()
        
        logger.info("=" * 50)
        if health_ok:
            logger.info("✅ Environment setup completed successfully!")
            logger.info("Next steps:")
            
            if ollama_available:
                logger.info("1. Start Ollama: ollama serve")
            elif hf_available:
                logger.info("1. Using Hugging Face models (no local setup needed)")
            else:
                logger.info("1. Install Ollama or ensure Hugging Face token is valid")
            logger.info("2. Build KG: python src/constructors/kg_builder_without_neo4j")
            logger.info("3. Export data: python src/generators/export_kg_for_rag_without_neo4j")
            logger.info("4. Build vector DB: python -m src.generators.rag_system --build")
            logger.info("5. Start API: python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000")
            logger.info("6. Start UI: python src/ui/gradio_app.py")
        else:
            logger.error("❌ Environment setup completed with issues")
            logger.error("Please check the logs above and resolve any issues")
        
        return health_ok

def main():
    """Main function"""
    setup = EnvironmentSetup()
    success = setup.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 