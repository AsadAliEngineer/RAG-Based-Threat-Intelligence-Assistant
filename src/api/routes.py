# src/api/routes.py
"""
SIMPLIFIED and FIXED FastAPI routes for the Enhanced RAG System
This version removes complex technology detection and focuses on the working CVERAGSystem methods
"""

import asyncio
import logging
import time
import traceback
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from .models import (
    QueryRequest, QueryResponse, SearchResult, QueryType,
    SummaryRequest, SummaryResponse, HealthResponse
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global application state
app_state: Dict[str, Any] = {}

router = APIRouter(prefix="/api/v1")


def get_rag_system():
    """Get the RAG system from app state"""
    rag_system = app_state.get('rag_system')
    if not rag_system:
        raise HTTPException(status_code=503, detail="RAG system not initialized")
    return rag_system


def get_llm_client():
    """Get the LLM client from app state (optional)"""
    return app_state.get('llm_client')


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        rag_system = get_rag_system()
        stats = rag_system.get_collection_stats()

        # Check GPU availability
        import torch
        gpu_available = torch.cuda.is_available()
        gpu_name = torch.cuda.get_device_name(0) if gpu_available else None

        return HealthResponse(
            status="healthy",
            gpu_available=gpu_available,
            gpu_name=gpu_name,
            vector_db_documents=stats.get("total_documents", 0),
            model_loaded=True
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            gpu_available=False,
            vector_db_documents=0,
            model_loaded=False
        )


@router.post("/search")
async def search_cves(request: QueryRequest):
    """
    SIMPLIFIED Search endpoint - uses only the working CVERAGSystem.search_cves method
    """
    try:
        start_time = time.time()

        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        rag_system = get_rag_system()

        # Simple search timeout (reduced from 20-30s to 10s)
        search_timeout = 10.0

        logger.info(f"Starting search for: {request.query[:50]}...")

        # Use the working search_cves method with proper parameter mapping
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(
                    rag_system.search_cves,
                    request.query,
                    request.top_k,  # n_results parameter
                    getattr(request, 'severity_filter', None),
                    getattr(request, 'vendor_filter', None)
                ),
                timeout=search_timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Search timeout ({search_timeout}s) for query: {request.query[:50]}...")
            raise HTTPException(status_code=408,
                                detail=f"Search timed out after {search_timeout}s. Please try a more specific query.")
        except Exception as e:
            logger.error(f"Search error: {e}")
            raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

        # Convert to response format
        pydantic_results = []
        for result in search_results:
            pydantic_results.append(SearchResult(
                id=result.get('id', ''),
                text=result.get('text', result.get('content', '')),
                metadata=result.get('metadata', {}),
                score=result.get('score', 0.0),
                distance=result.get('distance', 1.0)
            ))

        processing_time = time.time() - start_time
        logger.info(f"Search completed in {processing_time:.2f}s, found {len(pydantic_results)} results")

        return pydantic_results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search processing failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Search processing failed: {str(e)}")


@router.post("/query")
async def query_cves(request: QueryRequest):
    """
    SIMPLIFIED Query endpoint with optional LLM response generation
    """
    try:
        start_time = time.time()

        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        rag_system = get_rag_system()
        llm_client = get_llm_client()

        # Limit top_k for performance
        adjusted_top_k = min(request.top_k, 20)

        logger.info(f"Starting query for: {request.query[:50]}...")

        # Step 1: Get search results (simplified)
        search_timeout = 10.0
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(
                    rag_system.search_cves,
                    request.query,
                    adjusted_top_k,
                    getattr(request, 'severity_filter', None),
                    getattr(request, 'vendor_filter', None)
                ),
                timeout=search_timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Search timeout for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail="Search timed out. Please try a more specific query.")

        # Step 2: Generate LLM response (optional)
        llm_response = "Search completed successfully. LLM response generation not available."

        if llm_client and search_results:
            try:
                # Use top context documents
                max_context_docs = getattr(request, 'max_context_docs', 3)
                context_docs = search_results[:max_context_docs]

                # Build simple context
                context_text = "\n\n".join([
                    f"CVE: {doc.get('id', 'Unknown')}\n"
                    f"Description: {doc.get('text', doc.get('content', ''))[:400]}..."
                    for doc in context_docs
                ])

                # Simple prompt
                prompt = f"""Based on the following CVE information, provide a helpful answer to the user's question.

Question: {request.query}

CVE Information:
{context_text}

Please provide a clear, accurate response focusing on the most relevant vulnerabilities and their impacts.

Response:"""

                # Generate with timeout
                llm_response = await asyncio.wait_for(
                    asyncio.to_thread(
                        llm_client.generate_response,
                        prompt,
                        getattr(request, 'use_large_model', False)
                    ),
                    timeout=15.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"LLM timeout for query: {request.query[:50]}...")
                llm_response = "Response generation timed out. Search results are available below."
            except Exception as e:
                logger.warning(f"LLM error: {e}")
                llm_response = f"Response generation error. Search results are available below."

        # Convert search results to proper format
        pydantic_results = []
        for result in search_results:
            pydantic_results.append(SearchResult(
                id=result.get('id', ''),
                text=result.get('text', result.get('content', '')),
                metadata=result.get('metadata', {}),
                score=result.get('score', 0.0),
                distance=result.get('distance', 1.0)
            ))

        processing_time = time.time() - start_time
        logger.info(f"Query completed in {processing_time:.2f}s")

        return QueryResponse(
            query=request.query,
            response=llm_response,
            search_results=pydantic_results,
            query_type=QueryType.SEARCH,
            processing_time=processing_time,
            model_used="simplified_rag"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Query processing failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Query processing failed: {str(e)}")


@router.post("/summary")
async def get_vulnerability_summary(request: SummaryRequest):
    """Get vulnerability summary using CVERAGSystem.get_vulnerability_summary"""
    try:
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        rag_system = get_rag_system()

        logger.info(f"Getting summary for: {request.query[:50]}...")

        # Use the built-in summary method with timeout
        try:
            summary_data = await asyncio.wait_for(
                asyncio.to_thread(
                    rag_system.get_vulnerability_summary,
                    request.query
                ),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=408, detail="Summary generation timed out")

        # Check for error in summary
        if "error" in summary_data:
            raise HTTPException(status_code=404, detail=summary_data["error"])

        # Get sample results for the response
        sample_results = rag_system.search_cves(request.query, n_results=5)
        pydantic_samples = []
        for result in sample_results:
            pydantic_samples.append(SearchResult(
                id=result.get('id', ''),
                text=result.get('text', result.get('content', '')),
                metadata=result.get('metadata', {}),
                score=result.get('score', 0.0),
                distance=result.get('distance', 1.0)
            ))

        return SummaryResponse(
            query=request.query,
            total_results=summary_data.get('total_results', 0),
            severity_distribution=summary_data.get('severities', {}),
            top_vendors=summary_data.get('top_vendors', []),
            top_products=summary_data.get('top_products', []),
            common_weaknesses=summary_data.get('common_weaknesses', []),
            sample_results=pydantic_samples
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Summary failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Summary failed: {str(e)}")


@router.get("/stats")
async def get_system_stats():
    """Get system statistics"""
    try:
        rag_system = get_rag_system()
        stats = rag_system.get_collection_stats()

        return {
            "status": "operational",
            "total_documents": stats.get("total_documents", 0),
            "collection_name": stats.get("collection_name", "unknown"),
            "api_version": "2.0.0-simplified"
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Stats error: {str(e)}")