# src/api/routes.py
"""
Updated API routes for Enhanced RAG System with 2002-2025 dataset support
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import asyncio
from datetime import datetime
import logging
import time
import os

# Import the enhanced system
from src.generators.enhanced_rag_system import EnhancedRAGSystem

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# Global RAG system instance
rag_system = None


class SearchRequest(BaseModel):
    query: str
    top_k: int = 10
    search_type: Optional[str] = "auto"  # auto, exact, mitre, semantic
    year_filter: Optional[int] = None  # Optional year filter


class SearchResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]
    count: int
    search_time_ms: float
    search_metadata: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: Dict[str, str]
    stats: Optional[Dict[str, Any]] = None


class YearSearchRequest(BaseModel):
    query: str
    top_k: int = 10


def initialize_rag_system():
    """Initialize the enhanced RAG system with support for all years"""
    global rag_system

    config = {
        'base_path': 'data/knowledge_base',
        'start_year': 2002,  # Your data starts from 2002
        'end_year': 2025,  # Your data goes to 2025
        'max_cache_years': 3,  # Cache recent 3 years in memory
        'use_embeddings': False,  # Disabled for 23 years of data
        'cache_ttl': 7200  # 2 hour cache for historical queries
    }

    logger.info("Initializing Enhanced RAG System...")
    logger.info(
        f"Configuration: {config['start_year']}-{config['end_year']} ({config['end_year'] - config['start_year'] + 1} years)")
    start_time = time.time()
    
    rag_system = EnhancedRAGSystem(config)

    init_time = time.time() - start_time
    logger.info(f"Enhanced RAG System initialized in {init_time:.2f} seconds")

    # Log system stats
    stats = rag_system.get_stats()
    logger.info(f"System ready with {stats['total_cves_indexed']:,} CVEs indexed")
    logger.info(f"Years available: {stats['year_range']}")


@router.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    initialize_rag_system()


@router.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Enhanced RAG System...")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Lightweight health check
    """
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {}
        }

        # Check if RAG system is initialized
        if rag_system is not None:
            health_status["components"]["rag_system"] = "initialized"

            # Get lightweight stats
            try:
                stats = rag_system.get_stats()
                health_status["stats"] = {
                    "total_cves": stats.get('total_cves_indexed', 0),
                    "keywords_indexed": stats.get('keywords_indexed', 0),
                    "year_range": stats.get('year_range', 'N/A'),
                    "years_available": len(stats.get('years_available', [])),
                    "mitre_tactics": stats.get('mitre_tactics', 0),
                    "cache_entries": stats.get('cache_size', 0),
                    "embeddings_enabled": stats.get('embeddings_enabled', False)
                }
                health_status["components"]["indexes"] = "ready"
            except Exception as e:
                health_status["components"]["indexes"] = f"error: {str(e)}"
        else:
            health_status["components"]["rag_system"] = "not initialized"
            health_status["status"] = "unhealthy"

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/search", response_model=SearchResponse)
async def search_cves(request: SearchRequest):
    """
    Enhanced search with MITRE ATT&CK support and year filtering
    """
    try:
        # Validate request
        if not request.query:
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        # Add year filter to query if specified
        query = request.query
        if request.year_filter:
            # Validate year
            stats = rag_system.get_stats()
            available_years = stats.get('years_available', [])
            if request.year_filter not in available_years:
                raise HTTPException(
                    status_code=400,
                    detail=f"Year {request.year_filter} not available. Available years: {available_years}"
                )
            query = f"{query} {request.year_filter}"

        # Log search request
        logger.info(f"Search request: '{query}' (top_k={request.top_k})")

        # Perform search with timing
        start_time = time.time()

        # Run search in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            rag_system.search,
            query,
            request.top_k
        )

        search_time_ms = (time.time() - start_time) * 1000

        # If year filter was specified, ensure results are from that year
        if request.year_filter:
            results = [r for r in results if r.get('year') == request.year_filter]

        # Prepare search metadata
        search_metadata = {
            "index_stats": {
                "total_cves": rag_system.get_stats().get('total_cves_indexed', 0),
                "years_covered": rag_system.get_stats().get('year_range', 'N/A'),
                "used_embeddings": any(r.get('match_type') == 'semantic' for r in results)
            }
        }

        # Check if MITRE data was used
        if any(r.get('mitre_tactics') or r.get('mitre_techniques') for r in results):
            search_metadata["mitre_data_available"] = True

        logger.info(f"Search completed in {search_time_ms:.2f}ms, found {len(results)} results")

        return SearchResponse(
            query=request.query,
            results=results,
            count=len(results),
            search_time_ms=search_time_ms,
            search_metadata=search_metadata
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search/year/{year}")
async def search_by_year(
        year: int,
        query: str = Query(..., description="Search query"),
        top_k: int = Query(10, description="Number of results")
):
    """Search within a specific year"""
    try:
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        # Validate year
        stats = rag_system.get_stats()
        available_years = stats.get('years_available', [])

        if year not in available_years:
            raise HTTPException(
                status_code=400,
                detail=f"Year {year} not available. Available years: {available_years}"
            )

        # Modify query to include year
        year_query = f"{query} {year}"

        # Search
        start_time = time.time()
        results = rag_system.search(year_query, top_k=top_k * 2)  # Get more results to filter
        search_time_ms = (time.time() - start_time) * 1000

        # Filter results to only the specified year
        year_results = [r for r in results if r.get('year') == year][:top_k]

        return {
            "year": year,
            "query": query,
            "results": year_results,
            "count": len(year_results),
            "search_time_ms": search_time_ms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Year search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/{cve_id}")
async def get_cve_by_id(cve_id: str):
    """
    Get specific CVE by ID with full context
    """
    try:
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Validate CVE ID format
        import re
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise HTTPException(status_code=400, detail="Invalid CVE ID format")

        # Use exact search
        results = rag_system.search(cve_id, top_k=1)

        if results and results[0].get('id', '').upper() == cve_id:
            result = results[0]

            # Add additional context if available
            if result.get('cwe_ids'):
                result['vulnerability_types'] = f"CWE: {', '.join(map(str, result['cwe_ids']))}"

            if result.get('mitre_tactics'):
                result['attack_context'] = {
                    'tactics': result['mitre_tactics'],
                    'techniques': result.get('mitre_techniques', [])
                }

            return result
        else:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE lookup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search/mitre")
async def search_by_mitre(
        tactic: Optional[str] = Query(None, description="MITRE ATT&CK tactic"),
        technique: Optional[str] = Query(None, description="MITRE ATT&CK technique"),
        year: Optional[int] = Query(None, description="Filter by year"),
        top_k: int = Query(10, description="Number of results")
):
    """
    Search CVEs by MITRE ATT&CK tactics or techniques
    """
    try:
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        if not tactic and not technique:
            raise HTTPException(
                status_code=400,
                detail="Either tactic or technique parameter is required"
            )

        # Build query
        query_parts = []
        if tactic:
            query_parts.append(f"mitre tactic {tactic}")
        if technique:
            query_parts.append(f"mitre technique {technique}")
        if year:
            query_parts.append(str(year))

        query = " ".join(query_parts)

        # Search
        start_time = time.time()
        results = rag_system.search(query, top_k=top_k * 2)
        search_time_ms = (time.time() - start_time) * 1000

        # Filter to ensure MITRE relevance
        filtered_results = []
        for result in results:
            has_tactic = tactic and any(
                tactic.lower() in t.lower()
                for t in result.get('mitre_tactics', [])
            )
            has_technique = technique and any(
                technique.lower() in t.lower()
                for t in result.get('mitre_techniques', [])
            )

            year_matches = not year or result.get('year') == year

            if (has_tactic or has_technique) and year_matches:
                filtered_results.append(result)

        # Limit results
        filtered_results = filtered_results[:top_k]

        return {
            "query": {
                "tactic": tactic,
                "technique": technique,
                "year": year
            },
            "results": filtered_results,
            "count": len(filtered_results),
            "search_time_ms": search_time_ms
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MITRE search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_statistics():
    """
    Get enhanced system statistics
    """
    try:
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        stats = rag_system.get_stats()

        # Add year-specific statistics if available
        if 'years_available' in stats and stats['years_available']:
            year_stats = {}
            total_by_year = 0

            for year in stats['years_available']:
                if year in rag_system.year_index:
                    count = len(rag_system.year_index[year])
                    year_stats[str(year)] = count
                    total_by_year += count

            stats['cves_per_year'] = year_stats
            stats['total_cves_by_year_count'] = total_by_year

        # Add API-level stats
        stats["api"] = {
            "version": "2.0",
            "dataset_years": f"{stats.get('year_range', 'N/A')}",
            "features": [
                "keyword_search",
                "semantic_search_disabled",  # Disabled for large dataset
                "mitre_attack_integration",
                "cwe_capec_relationships",
                "intelligent_caching",
                "multi_year_support",
                "year_based_filtering"
            ],
            "endpoints": [
                {"path": "/health", "method": "GET", "description": "Health check"},
                {"path": "/search", "method": "POST", "description": "General search"},
                {"path": "/search/year/{year}", "method": "GET", "description": "Year-specific search"},
                {"path": "/search/mitre", "method": "GET", "description": "MITRE ATT&CK search"},
                {"path": "/cve/{cve_id}", "method": "GET", "description": "Get specific CVE"},
                {"path": "/stats", "method": "GET", "description": "System statistics"},
                {"path": "/years", "method": "GET", "description": "List available years"}
            ]
        }

        # Add index information
        if os.path.exists(os.path.join(rag_system.base_path, 'master_index_full.pkl')):
            stats['index_info'] = {
                'type': 'pre_built',
                'status': 'optimized'
            }
        else:
            stats['index_info'] = {
                'type': 'dynamic',
                'status': 'limited',
                'recommendation': 'Run scripts/build_indexes.py for better performance'
            }

        return stats

    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/years")
async def get_available_years():
    """
    Get list of available years with CVE counts
    """
    try:
        if not rag_system:
            raise HTTPException(status_code=503, detail="RAG system not initialized")

        stats = rag_system.get_stats()
        years_available = stats.get('years_available', [])

        year_info = []
        for year in sorted(years_available):
            info = {
                "year": year,
                "cve_count": len(rag_system.year_index.get(year, [])),
                "indexed": year in rag_system._year_loaded
            }
            year_info.append(info)

        return {
            "total_years": len(years_available),
            "year_range": stats.get('year_range', 'N/A'),
            "years": year_info
        }
        
    except Exception as e:
        logger.error(f"Failed to get years: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/")
async def root():
    """Root endpoint with API information"""
    try:
        stats = rag_system.get_stats() if rag_system else {}
        
        return {
            "service": "Enhanced CVE RAG System API",
            "version": "2.0",
            "status": "running",
            "dataset": {
                "years": stats.get('year_range', 'Unknown'),
                "total_cves": stats.get('total_cves_indexed', 0),
                "keywords_indexed": stats.get('keywords_indexed', 0),
                "years_available": len(stats.get('years_available', []))
            },
            "features": [
                "Fast keyword-based search with inverted indexes",
                f"Multi-year support ({stats.get('year_range', 'N/A')})",
                "MITRE ATT&CK integration",
                "CWE and CAPEC relationship mapping",
                "Intelligent result caching",
                "Year-specific search endpoints",
                "Lazy loading for large dataset"
            ],
            "performance_tips": [
                "For best performance, run 'python scripts/build_indexes.py' first",
                "Use year filters when possible to narrow search scope",
                "Recent years (2020+) have better search performance"
            ],
            "endpoints": {
                "health": "/health",
                "search": "/search",
                "search_by_year": "/search/year/{year}",
                "get_cve": "/cve/{cve_id}",
                "search_mitre": "/search/mitre",
                "stats": "/stats",
                "years": "/years"
            },
            "example_queries": [
                {"description": "Exact CVE lookup", "example": "/cve/CVE-2021-44228"},
                {"description": "General search", "example": "POST /search {\"query\": \"log4j vulnerabilities\"}"},
                {"description": "Year-specific search", "example": "/search/year/2021?query=remote%20code%20execution"},
                {"description": "MITRE tactic search", "example": "/search/mitre?tactic=persistence"},
                {"description": "Combined search",
                 "example": "POST /search {\"query\": \"5G vulnerabilities\", \"year_filter\": 2023}"}
            ]
        }
    except Exception as e:
        logger.error(f"Root endpoint error: {e}")
        return {
            "service": "Enhanced CVE RAG System API",
            "version": "2.0",
            "status": "error",
            "error": str(e)
        }


# Optional: Add background task to build indexes if not present
@router.post("/admin/build-indexes")
async def trigger_index_build(background_tasks: BackgroundTasks):
    """
    Admin endpoint to trigger index building in background
    """
    try:
        # Check if already built
        index_path = os.path.join(rag_system.base_path, 'master_index_full.pkl')
        if os.path.exists(index_path):
            return {
                "status": "already_exists",
                "message": "Indexes already built",
                "path": index_path
            }

        # Add background task to build indexes
        background_tasks.add_task(build_indexes_background)
        
        return {
            "status": "started",
            "message": "Index building started in background. This will take 10-30 minutes.",
            "check_progress": "/admin/index-status"
        }

    except Exception as e:
        logger.error(f"Failed to start index building: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admin/index-status")
async def get_index_build_status():
    """
    Check the status of index building
    """
    try:
        index_path = os.path.join(rag_system.base_path, 'master_index_full.pkl')

        if os.path.exists(index_path):
            # Get file stats
            file_stats = os.stat(index_path)
            file_size_mb = file_stats.st_size / (1024 * 1024)

            return {
                "status": "completed",
                "index_path": index_path,
                "size_mb": round(file_size_mb, 2),
                "created": datetime.fromtimestamp(file_stats.st_ctime).isoformat()
            }
        else:
            # Check if building is in progress
            temp_files = [f for f in os.listdir(rag_system.base_path) if f.endswith('.pkl.tmp')]

            if temp_files:
                return {
                    "status": "in_progress",
                    "message": "Index building is in progress..."
                }
            else:
                return {
                    "status": "not_started",
                    "message": "No index found. Use /admin/build-indexes to start building."
                }

    except Exception as e:
        logger.error(f"Failed to check index status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def build_indexes_background():
    """
    Background task to build indexes
    """
    try:
        logger.info("Starting background index building...")

        # Import the index builder
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from scripts.build_indexes import IndexBuilder

        # Build indexes
        builder = IndexBuilder(base_path=rag_system.base_path)
        builder.build_all_indexes()

        logger.info("Background index building completed!")

        # Reload indexes in the RAG system
        rag_system._build_indexes()

    except Exception as e:
        logger.error(f"Background index building failed: {e}")


# Note: Exception handlers should be added to the main FastAPI app, not the router