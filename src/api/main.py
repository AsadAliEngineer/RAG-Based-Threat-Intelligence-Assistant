"""
Main FastAPI application for the RAG system
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import torch
import uvicorn
from src.api.routes import router, app_state
from src.api.models import QueryType

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources"""
    # Startup
    logger.info("Starting RAG system initialization...")
    
    try:
        logger.info("Loading RAG system...")
        # Initialize RAG system
        from src.generators.rag_system import CVERAGSystem
        rag_system = CVERAGSystem()
        app_state['rag_system'] = rag_system
        logger.info("RAG system loaded successfully")
        
        # Initialize LLM client (try Ollama first, fallback to Hugging Face)
        logger.info("Initializing LLM client...")
        from src.generation.llm_client import LLMClient
        try:
            # Try Ollama first
            logger.info("Trying Ollama...")
            llm_client = LLMClient(use_ollama=True)
            health = await llm_client.health_check()
            if health['status'] == 'healthy':
                logger.info("Using Ollama for LLM")
            else:
                logger.warning("Ollama not available, falling back to Hugging Face")
                llm_client = LLMClient(use_ollama=False)
        except Exception as e:
            logger.warning(f"Ollama failed: {e}, using Hugging Face")
            llm_client = LLMClient(use_ollama=False)
        
        app_state['llm_client'] = llm_client
        logger.info("LLM client initialized successfully")
        
        # Initialize query router
        logger.info("Loading query router...")
        from src.retrieval.query_router import QueryRouter
        query_router = QueryRouter()
        app_state['query_router'] = query_router
        logger.info("Query router loaded successfully")
        
        logger.info("RAG system initialized successfully!")
        
    except Exception as e:
        logger.error(f"Failed to initialize RAG system: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise
    
    yield
    
    # Cleanup
    logger.info("Shutting down RAG system...")

app = FastAPI(
    title="CVE RAG System",
    description="Retrieval-Augmented Generation for Cybersecurity Vulnerability Analysis",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router, prefix="/api/v1")

@app.get("/startup")
async def startup_check():
    """Simple startup check that doesn't require full system"""
    return {
        "status": "API server is running",
        "message": "FastAPI server started successfully",
        "timestamp": "2024-01-01T00:00:00Z"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CVE RAG System API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
        "startup": "/startup"
    }

@app.get("/docs")
async def docs():
    """API documentation"""
    return {"message": "API documentation available at /docs"}

if __name__ == "__main__":
    print("Starting CVE RAG System API...")
    print("API: http://localhost:8000")
    print("Docs: http://localhost:8000/docs")
    print("Health: http://localhost:8000/api/v1/health")
    
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    ) 