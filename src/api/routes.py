# src/api/optimized_routes.py

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
import asyncio
import time
import logging
from datetime import datetime
import re
import traceback

logger = logging.getLogger(__name__)

# Global app state (will be set by main.py)
app_state = {}

router = APIRouter()

# Import models with fallback
try:
    from .models import QueryRequest, QueryResponse, SearchResult, QueryType
except ImportError:
    from pydantic import BaseModel
    from enum import Enum


    class QueryType(str, Enum):
        SEARCH = "search"
        CVE_LOOKUP = "cve_lookup"
        GENERAL = "general"


    class QueryRequest(BaseModel):
        query: str
        top_k: int = 10
        years: Optional[List[str]] = None
        max_context_docs: int = 5
        use_large_model: bool = False
        stream: bool = False
        severity_filter: Optional[str] = None
        vendor_filter: Optional[str] = None


    class SearchResult(BaseModel):
        id: str
        text: str
        metadata: Dict[str, Any]
        score: float
        distance: float


    class QueryResponse(BaseModel):
        query: str
        response: str
        search_results: List[SearchResult]
        query_type: QueryType
        processing_time: float
        model_used: str


def get_rag_system():
    """Get RAG system from app state"""
    if 'rag_system' not in app_state:
        raise HTTPException(status_code=503, detail="RAG system not initialized")
    return app_state['rag_system']


def get_llm_client():
    """Get LLM client from app state (optional)"""
    return app_state.get('llm_client', None)


def get_enhanced_processor():
    """Get enhanced processor from app state (optional)"""
    return app_state.get('enhanced_processor', None)


@router.get("/health")
async def health_check():
    """Fast health check endpoint"""
    try:
        # Quick health check with timeout
        rag_system = get_rag_system()

        # Get basic stats quickly
        stats = await asyncio.wait_for(
            asyncio.to_thread(rag_system.get_collection_stats),
            timeout=5.0  # 5 second timeout for health check
        )

        llm_client = get_llm_client()
        llm_status = llm_client.available if llm_client else False

        return {
            "status": "healthy",
            "documents": stats.get("total_documents", 0),
            "llm_available": llm_status,
            "timestamp": datetime.now().isoformat()
        }

    except asyncio.TimeoutError:
        return {
            "status": "slow",
            "message": "System responding slowly",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"System unhealthy: {str(e)}")


@router.post("/search")
async def optimized_search(request: QueryRequest):
    """Optimized search endpoint with better performance"""
    start_time = time.time()

    try:
        # Validate input
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        # Limit parameters for performance
        top_k = min(request.top_k, 20)  # Reduced from 50
        query = request.query.strip()[:500]  # Limit query length

        rag_system = get_rag_system()

        # Determine timeout based on query complexity
        search_timeout = 15.0  # Default timeout
        if len(query) > 100 or top_k > 10:
            search_timeout = 20.0

        # Execute search with timeout
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.search_cves, query, top_k),
                timeout=search_timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Search timeout for query: {query[:50]}...")
            raise HTTPException(
                status_code=408,
                detail=f"Search timed out after {search_timeout}s. Try a more specific query."
            )

        # Convert results
        formatted_results = []
        for result in search_results:
            formatted_results.append(SearchResult(
                id=result.get('id', ''),
                text=result.get('text', result.get('content', '')),
                metadata=result.get('metadata', {}),
                score=result.get('score', 0.0),
                distance=result.get('distance', 1.0)
            ))

        processing_time = time.time() - start_time

        return {
            "results": formatted_results,
            "query": query,
            "total_results": len(formatted_results),
            "processing_time": processing_time,
            "status": "success"
        }

    except HTTPException:
        raise
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Search failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed after {processing_time:.2f}s: {str(e)}"
        )


@router.post("/query")
async def optimized_query(request: QueryRequest):
    """Optimized query endpoint with LLM integration"""
    start_time = time.time()

    try:
        # Validate input
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        # Limit parameters
        top_k = min(request.top_k, 15)
        query = request.query.strip()[:500]

        # Get components
        rag_system = get_rag_system()
        enhanced_processor = get_enhanced_processor()

        # Use enhanced processor if available, otherwise fallback
        if enhanced_processor:
            try:
                # Enhanced processing with timeout
                result = await asyncio.wait_for(
                    asyncio.to_thread(
                        enhanced_processor.process_query,
                        query,
                        top_k,
                        request.years,
                        True  # use_llm
                    ),
                    timeout=25.0  # Longer timeout for LLM processing
                )

                # Convert search results
                formatted_results = []
                for search_result in result.get('search_results', []):
                    formatted_results.append(SearchResult(
                        id=search_result.get('id', ''),
                        text=search_result.get('text', search_result.get('content', '')),
                        metadata=search_result.get('metadata', {}),
                        score=search_result.get('score', 0.0),
                        distance=search_result.get('distance', 1.0)
                    ))

                processing_time = time.time() - start_time

                return QueryResponse(
                    query=query,
                    response=result.get('llm_response', 'No response generated'),
                    search_results=formatted_results,
                    query_type=QueryType.GENERAL,
                    processing_time=processing_time,
                    model_used="enhanced_processor"
                )

            except asyncio.TimeoutError:
                logger.warning(f"Enhanced query timeout: {query[:50]}...")
                # Fallback to basic search
                pass

        # Fallback to basic search + simple response
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.search_cves, query, top_k),
                timeout=15.0
            )

            # Generate simple response
            if search_results:
                cve_count = len(search_results)
                top_cve = search_results[0]['metadata'].get('cve_id', 'Unknown')
                simple_response = f"Found {cve_count} relevant vulnerabilities. Top result: {top_cve}. LLM processing unavailable - using basic search."
            else:
                simple_response = f"No vulnerabilities found for: {query}"

            # Convert results
            formatted_results = []
            for result in search_results:
                formatted_results.append(SearchResult(
                    id=result.get('id', ''),
                    text=result.get('text', result.get('content', '')),
                    metadata=result.get('metadata', {}),
                    score=result.get('score', 0.0),
                    distance=result.get('distance', 1.0)
                ))

            processing_time = time.time() - start_time

            return QueryResponse(
                query=query,
                response=simple_response,
                search_results=formatted_results,
                query_type=QueryType.SEARCH,
                processing_time=processing_time,
                model_used="basic_search"
            )

        except asyncio.TimeoutError:
            raise HTTPException(status_code=408, detail="Query processing timed out")

    except HTTPException:
        raise
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Query processing failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Query failed after {processing_time:.2f}s: {str(e)}"
        )


@router.post("/summary")
async def optimized_summary(request: QueryRequest):
    """Optimized summary endpoint"""
    start_time = time.time()

    try:
        query = request.query.strip()
        if not query:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        rag_system = get_rag_system()

        # Get more results for summary
        max_results = min(request.max_context_docs * 10, 50)

        search_results = await asyncio.wait_for(
            asyncio.to_thread(rag_system.search_cves, query, max_results),
            timeout=20.0
        )

        # Analyze results
        severities = {}
        vendors = []
        total_results = len(search_results)

        for result in search_results:
            metadata = result.get('metadata', {})

            # Count severities
            severity = metadata.get('severity', 'Unknown')
            severities[severity] = severities.get(severity, 0) + 1

            # Collect vendors (simplified)
            affected_products = metadata.get('affected_products', [])
            if affected_products:
                vendors.extend(affected_products[:2])  # Limit to avoid performance issues

        # Get top vendors
        from collections import Counter
        vendor_counts = Counter(vendors)
        top_vendors = [vendor for vendor, count in vendor_counts.most_common(5)]

        processing_time = time.time() - start_time

        return {
            "query": query,
            "total_results": total_results,
            "severity_distribution": severities,
            "top_vendors": top_vendors,
            "processing_time": processing_time,
            "sample_results": search_results[:5]  # Return top 5 as samples
        }

    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Summary generation timed out")
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Summary failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Summary failed after {processing_time:.2f}s: {str(e)}"
        )


@router.get("/stats")
async def get_stats():
    """Fast stats endpoint"""
    try:
        rag_system = get_rag_system()
        llm_client = get_llm_client()

        # Get basic stats with timeout
        stats = await asyncio.wait_for(
            asyncio.to_thread(rag_system.get_collection_stats),
            timeout=5.0
        )

        return {
            "status": "operational",
            "total_documents": stats.get("total_documents", 0),
            "collection_name": stats.get("collection_name", "unknown"),
            "llm_available": llm_client.available if llm_client else False,
            "llm_model": llm_client.config.model if llm_client and llm_client.available else None,
            "version": "2.0.0-optimized"
        }

    except asyncio.TimeoutError:
        return {
            "status": "slow",
            "message": "Stats loading slowly",
            "version": "2.0.0-optimized"
        }
    except Exception as e:
        logger.error(f"Stats failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats unavailable: {str(e)}")


# Health endpoint that doesn't require authentication
@router.get("/ping")
async def ping():
    """Ultra-fast ping endpoint"""
    return {"status": "alive", "timestamp": datetime.now().isoformat()}