# src/api/main.py
"""
SIMPLIFIED FastAPI application with Enhanced RAG System
This version focuses on the working CVERAGSystem implementation
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import sys
import os

# Add the project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

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
    title="Simplified CVE RAG System API",
    description="Simplified, working search system for CVE data",
    version="2.0.0-simplified"
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
    logger.info("🚀 Simplified CVE RAG System API starting up...")

    try:
        # Step 1: Initialize the working RAG System
        logger.info("📊 Initializing CVE RAG System...")
        from src.generators.rag_system import CVERAGSystem

        rag_system = CVERAGSystem()
        app_state['rag_system'] = rag_system

        # Step 2: Verify it's working
        try:
            stats = rag_system.get_collection_stats()
            total_docs = stats.get('total_documents', 0)
            if total_docs == 0:
                logger.warning("⚠️  No documents found in vector database. You may need to build it first.")
                logger.warning("    Run: python -m src.generators.rag_system --build")
            else:
                logger.info(f"✅ RAG System ready: {total_docs:,} documents indexed")
        except Exception as e:
            logger.warning(f"⚠️  Could not get stats: {e}")

        # Step 3: Test a simple search
        try:
            test_results = rag_system.search_cves("test", n_results=1)
            logger.info(f"✅ Search test successful: {len(test_results)} results")
        except Exception as e:
            logger.warning(f"⚠️  Search test failed: {e}")

        # Step 4: Initialize optional components
        logger.info("🤖 Initializing optional components...")

        # LLM Client (optional)
        try:
            from src.generation.llm_client import LLMClient
            llm_client = LLMClient()
            app_state['llm_client'] = llm_client
            logger.info("✅ LLM Client initialized")
        except ImportError as e:
            logger.info("ℹ️  LLM Client not available - API will work in search-only mode")
            app_state['llm_client'] = None
        except Exception as e:
            logger.warning(f"⚠️  LLM Client initialization failed: {e}")
            app_state['llm_client'] = None

        logger.info("🎉 Simplified API initialization complete!")
        logger.info("📍 Available endpoints:")
        logger.info("   - GET  /api/v1/health")
        logger.info("   - POST /api/v1/search")
        logger.info("   - POST /api/v1/query")
        logger.info("   - POST /api/v1/summary")
        logger.info("   - GET  /api/v1/stats")

    except Exception as e:
        logger.error(f"❌ Critical initialization failure: {e}")
        logger.error("   Please check that:")
        logger.error("   1. Vector database is built (run with --build)")
        logger.error("   2. CVE data files exist in data/knowledge_base/")
        logger.error("   3. All dependencies are installed")
        raise


@app.on_event("shutdown")
async def shutdown():
    logger.info("👋 Simplified CVE RAG System API shutting down...")


if __name__ == "__main__":
    import uvicorn

    logger.info("🔥 Starting development server...")
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )