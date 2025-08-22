# src/api/main.py
"""
Main FastAPI application with Enhanced RAG System
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Import routes and app_state
from src.api.routes import router, app_state

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Enhanced CVE RAG System API",
    description="Enhanced search system with comprehensive CVE indexes",
    version="2.0.0"
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
app.include_router(router)

@app.on_event("startup")
async def startup():
    logger.info("Enhanced CVE RAG System API starting up...")
    
    # Initialize app_state with required components
    try:
        # Initialize Enhanced RAG System
        from src.generators.enhanced_rag_system import EnhancedRAGSystem
        
        config = {
            'base_path': 'data/knowledge_base',
            'start_year': 2002,
            'end_year': 2025,
            'max_cache_years': 3,
            'use_embeddings': False,
            'cache_ttl': 7200
        }
        
        logger.info("Initializing Enhanced RAG System...")
        rag_system = EnhancedRAGSystem(config)
        app_state['rag_system'] = rag_system
        
        # Get system stats
        stats = rag_system.get_stats()
        logger.info(f"RAG System ready: {stats.get('total_cves_indexed', 0):,} CVEs indexed")
        logger.info(f"Years available: {stats.get('year_range', 'N/A')}")
        
        # Initialize other components (optional - will be handled gracefully if not available)
        try:
            from src.generation.llm_client import LLMClient
            llm_client = LLMClient()
            app_state['llm_client'] = llm_client
            logger.info("LLM Client initialized")
        except ImportError:
            logger.warning("LLM Client not available - will use search-only mode")
            app_state['llm_client'] = None
            
        try:
            from src.retrieval.query_router import QueryRouter
            query_router = QueryRouter()
            app_state['query_router'] = query_router
            logger.info("Query Router initialized")
        except ImportError:
            logger.warning("Query Router not available - will use basic routing")
            app_state['query_router'] = None
            
        logger.info("✅ All components initialized successfully!")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize components: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    logger.info("Enhanced CVE RAG System API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )