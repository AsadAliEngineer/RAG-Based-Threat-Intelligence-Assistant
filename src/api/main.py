# src/api/main.py
"""
Main FastAPI application with Hybrid RAG System
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Import routes
from src.api.routes import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="CVE RAG System API",
    description="Hybrid search system for CVE vulnerabilities",
    version="1.0.0"
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

# Log startup
@app.on_event("startup")
async def startup():
    logger.info("CVE RAG System API starting up...")
    logger.info("Using Hybrid Search Architecture")

@app.on_event("shutdown")
async def shutdown():
    logger.info("CVE RAG System API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )