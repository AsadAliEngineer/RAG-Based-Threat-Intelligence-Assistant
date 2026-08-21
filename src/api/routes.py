"""
API routes for the RAG system
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import asyncio
import time
import logging
from .models import (
    QueryRequest, QueryResponse, StreamResponse, HealthResponse,
    SummaryRequest, SummaryResponse, QueryType, SearchResult
)
import traceback
import re

logger = logging.getLogger(__name__)

# Global app state (will be set by main.py)
app_state = {}

router = APIRouter()

def get_rag_system():
    """Get RAG system from app state"""
    if 'rag_system' not in app_state:
        raise HTTPException(status_code=503, detail="RAG system not initialized")
    return app_state['rag_system']

def get_llm_client():
    """Get LLM client from app state"""
    if 'llm_client' not in app_state:
        raise HTTPException(status_code=503, detail="LLM client not initialized")
    return app_state['llm_client']

def get_query_router():
    """Get query router from app state"""
    if 'query_router' not in app_state:
        raise HTTPException(status_code=503, detail="Query router not initialized")
    return app_state['query_router']

@router.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest) -> QueryResponse:
    """Process a RAG query with timeout and performance optimizations"""
    import re
    start_time = time.time()
    
    try:
        # Validate request parameters
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        if request.top_k > 50:
            request.top_k = 50  # Cap at reasonable limit
        if request.max_context_docs > 20:
            request.max_context_docs = 20  # Cap at reasonable limit
        
        # Get components
        rag_system = get_rag_system()
        llm_client = get_llm_client()
        query_router = get_query_router()
        
        # --- PATCH: Extract CVE IDs, years, vendors, products ---
        def extract_cve_ids(text):
            return re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        cve_ids = extract_cve_ids(request.query)
        # Use query_router to extract entities
        entities = query_router.extract_entities(request.query)
        years = entities.get('years', [])
        vendor_terms = entities.get('vendors', [])
        product_terms = entities.get('technologies', [])  # Use 'technologies' as product terms
        if cve_ids:
            search_query = cve_ids[0]
        else:
            search_query = request.query
        # --- END PATCH ---
        
        # Route query with timeout
        try:
            query_type, metadata = await asyncio.wait_for(
                asyncio.to_thread(query_router.analyze_query, request.query),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"Query routing timeout for: {request.query[:50]}...")
            query_type, metadata = QueryType.GENERAL, {}
        
        # Build filters
        filter_dict = {}
        if request.severity_filter:
            filter_dict["severity"] = request.severity_filter
        if request.vendor_filter:
            filter_dict["vendors"] = {"$contains": request.vendor_filter}
        
        # Search for relevant documents with timeout using year-based search
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(
                    rag_system.search_cves_by_year,
                    search_query,
                    years if years else ['2021', '2022', '2023', '2024'],
                    request.top_k,
                    vendor_terms,
                    product_terms
                ),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Search timeout for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail="Search operation timed out")
        
        if not search_results:
            return QueryResponse(
                query=request.query,
                response="No relevant vulnerabilities found for your query. Please try a different search term.",
                search_results=[],
                query_type=query_type,
                processing_time=time.time() - start_time,
                model_used='none'
            )
        
        # Convert to Pydantic models
        pydantic_results = []
        for result in search_results[:request.max_context_docs]:
            pydantic_results.append(SearchResult(
                id=result['id'],
                text=result['text'],
                metadata=result['metadata'],
                score=result['score'],
                distance=result['distance']
            ))
        
        # Build context for LLM (limit context size)
        context_parts = []
        total_context_length = 0
        max_context_length = 8000  # Limit context to prevent token overflow
        
        for result in search_results[:request.max_context_docs]:
            text = result['text']
            if total_context_length + len(text) > max_context_length:
                break
            context_parts.append(text)
            total_context_length += len(text)
        
        context = "\n\n".join(context_parts)
        
        # Generate response using LLM with timeout
        model_type = 'primary' if request.use_large_model else 'fast'
        prompt = f"""Based on the following CVE vulnerability information, answer the user's question:

Context:
{context}

User Question: {request.query}

Please provide a comprehensive answer based on the vulnerability information above. Include relevant CVE IDs, severity levels, affected products, and any important details. Keep the response concise and focused."""

        response_text = ""
        try:
            async def generate_response():
                response = ""
                async for chunk in llm_client.generate(prompt, model_type=model_type):
                    response += chunk
                    if len(response) > 2000:
                        response = response[:2000] + "..."
                        break
                return response
            response_text = await asyncio.wait_for(generate_response(), timeout=30.0)
        except asyncio.TimeoutError:
            logger.error(f"LLM generation timeout for query: {request.query[:50]}...")
            response_text = "I found relevant vulnerabilities but the response generation timed out. Here are the search results instead."
        except Exception as e:
            logger.error(f"LLM generation error: {e}")
            response_text = f"Error generating response: {str(e)}"
        
        processing_time = time.time() - start_time
        
        return QueryResponse(
            query=request.query,
            response=response_text,
            search_results=pydantic_results,
            query_type=query_type,
            processing_time=processing_time,
            model_used=model_type
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")

@router.post("/search", response_model=List[SearchResult])
async def search_only(request: QueryRequest) -> List[SearchResult]:
    """Search for documents without LLM generation"""
    try:
        # Validate request
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        if request.top_k > 50:
            request.top_k = 50
        
        rag_system = get_rag_system()
        
        # Build filters
        filter_dict = {}
        if request.severity_filter:
            filter_dict["severity"] = request.severity_filter
        if request.vendor_filter:
            filter_dict["vendors"] = {"$contains": request.vendor_filter}
        
        # Search for relevant documents with timeout using year-based search
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.search_cves_by_year, request.query, ['2021', '2022', '2023', '2024'], request.top_k),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Search timeout for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail="Search operation timed out")
        
        # Convert to Pydantic models
        pydantic_results = []
        for result in search_results:
            pydantic_results.append(SearchResult(
                id=result['id'],
                text=result['text'],
                metadata=result['metadata'],
                score=result['score'],
                distance=result['distance']
            ))
        
        return pydantic_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in search: {e}")
        raise HTTPException(status_code=500, detail=f"Error in search: {str(e)}")

@router.post("/search/year", response_model=List[SearchResult])
async def search_cves_by_year(request: QueryRequest) -> List[SearchResult]:
    """Search for CVEs in specific years"""
    try:
        logger.info(f"Year search request: {request.query} in years {request.years}")
        
        rag_system = get_rag_system()
        
        # Build filters
        filter_dict = {}
        if request.severity_filter:
            filter_dict["severity"] = request.severity_filter
        if request.vendor_filter:
            filter_dict["vendors"] = {"$contains": request.vendor_filter}
        
        # Search for relevant documents with timeout
        try:
            search_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.search_cves_by_year, request.query, request.years, request.top_k),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Year search timeout for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail="Year search operation timed out")
        
        # Convert to Pydantic models
        pydantic_results = []
        for result in search_results:
            pydantic_results.append(SearchResult(
                id=result['id'],
                text=result['text'],
                metadata=result['metadata'],
                score=result['score'],
                distance=result['distance']
            ))
        
        return pydantic_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in year search: {e}")
        raise HTTPException(status_code=500, detail=f"Error in year search: {str(e)}")

@router.post("/summary", response_model=SummaryResponse)
async def get_summary(request: SummaryRequest) -> SummaryResponse:
    """Get vulnerability summary with timeout"""
    try:
        # Validate request
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        if request.max_results > 100:
            request.max_results = 100
        
        rag_system = get_rag_system()
        
        # Get summary with timeout
        try:
            summary = await asyncio.wait_for(
                asyncio.to_thread(rag_system.get_vulnerability_summary, request.query),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Summary timeout for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail="Summary operation timed out")
        
        # Convert sample results to Pydantic models
        sample_results = []
        for result in summary.get('sample_results', []):
            sample_results.append(SearchResult(
                id=result['id'],
                text=result['text'],
                metadata=result['metadata'],
                score=result['score'],
                distance=result['distance']
            ))
        
        return SummaryResponse(
            query=summary['query'],
            total_results=summary['total_results'],
            severity_distribution=summary['severity_distribution'],
            top_vendors=summary['top_vendors'],
            top_products=summary['top_products'],
            common_weaknesses=summary['common_weaknesses'],
            sample_results=sample_results
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting summary: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting summary: {str(e)}")

@router.get("/similar/{cve_id}", response_model=List[SearchResult])
async def get_similar_cves(cve_id: str, n_results: int = 5) -> List[SearchResult]:
    """Find CVEs similar to a given CVE with timeout"""
    try:
        # Validate parameters
        if not cve_id or len(cve_id.strip()) == 0:
            raise HTTPException(status_code=400, detail="CVE ID cannot be empty")
        
        if n_results > 20:
            n_results = 20
        
        rag_system = get_rag_system()
        
        # Get similar CVEs with timeout
        try:
            similar_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.get_similar_cves, cve_id, n_results),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Similar CVEs timeout for: {cve_id}")
            raise HTTPException(status_code=408, detail="Similar CVEs operation timed out")
        
        # Convert to Pydantic models
        pydantic_results = []
        for result in similar_results:
            pydantic_results.append(SearchResult(
                id=result['id'],
                text=result['text'],
                metadata=result['metadata'],
                score=result['score'],
                distance=result['distance']
            ))
        
        return pydantic_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error finding similar CVEs: {e}")
        raise HTTPException(status_code=500, detail=f"Error finding similar CVEs: {str(e)}")

@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint"""
    import torch
    
    try:
        rag_system = get_rag_system()
        stats = rag_system.search_engine.get_collection_stats()
        
        return HealthResponse(
            status="healthy",
            gpu_available=torch.cuda.is_available(),
            gpu_name=torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
            vector_db_documents=stats["total_documents"],
            model_loaded='llm_client' in app_state
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            gpu_available=torch.cuda.is_available(),
            gpu_name=torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
            vector_db_documents=0,
            model_loaded=False
        ) 

@router.get("/debug/vector-db")
async def debug_vector_db():
    """Debug endpoint to check vector database status"""
    try:
        rag_system = get_rag_system()
        
        # Check if collection exists and has data
        collection = rag_system.search_engine.collection
        if not collection:
            return {"error": "Collection not found"}
        
        count = collection.count()
        
        # Try to get a sample document
        sample_results = collection.query(
            query_embeddings=[[0.1] * 384],  # Dummy embedding
            n_results=1
        )
        
        return {
            "collection_name": collection.name,
            "document_count": count,
            "sample_results_keys": list(sample_results.keys()) if sample_results else None,
            "sample_ids": sample_results.get('ids', []) if sample_results else None,
            "sample_documents": sample_results.get('documents', []) if sample_results else None,
            "status": "healthy" if count > 0 else "empty"
        }
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()} 

@router.get("/debug/cve-data")
async def debug_cve_data():
    """Debug endpoint to check CVE data availability"""
    try:
        rag_system = get_rag_system()
        
        # Check if CVE data files exist
        cve_data_path = rag_system.cve_data_path
        import os
        from pathlib import Path
        
        cve_path = Path(cve_data_path)
        files = []
        if cve_path.exists():
            for file in cve_path.glob("*.json"):
                files.append({
                    "name": file.name,
                    "size": file.stat().st_size,
                    "path": str(file)
                })
        
        # Try to load a sample CVE file
        sample_data = None
        if files:
            sample_file = files[0]
            try:
                with open(sample_file["path"], 'r', encoding='utf-8') as f:
                    import json
                    data = json.load(f)
                    if isinstance(data, list):
                        sample_data = data[:2] if len(data) > 2 else data
                    else:
                        sample_data = str(data)[:500] + "..." if len(str(data)) > 500 else str(data)
            except Exception as e:
                sample_data = f"Error loading file: {e}"
        
        return {
            "cve_data_path": str(cve_path),
            "path_exists": cve_path.exists(),
            "files_found": len(files),
            "files": files[:5],  # Show first 5 files
            "sample_data": sample_data
        }
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()} 