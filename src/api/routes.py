"""
Enhanced API routes for the RAG system with dynamic critical years and flexible technology detection
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from typing import Dict, Any, List, Optional, Union
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

# Import models - handle missing models gracefully
try:
    from .models import (
        QueryRequest, QueryResponse, StreamResponse, HealthResponse,
        SummaryRequest, SummaryResponse, QueryType, SearchResult
    )
except ImportError:
    # Define basic models if not available
    from pydantic import BaseModel
    from enum import Enum


    class QueryType(Enum):
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
        response: str
        sources: List[SearchResult]
        metadata: Dict[str, Any]


def get_rag_system():
    """Get RAG system from app state"""
    if 'rag_system' not in app_state:
        raise HTTPException(status_code=503, detail="RAG system not initialized")
    return app_state['rag_system']


def get_llm_client():
    """Get LLM client from app state"""
    if 'llm_client' not in app_state:
        # Return None if not available, handle gracefully
        return None
    return app_state['llm_client']


def get_query_router():
    """Get query router from app state"""
    if 'query_router' not in app_state:
        # Return None if not available, handle gracefully
        return None
    return app_state['query_router']


class TechnologyDetector:
    """Advanced technology detection for determining critical years dynamically"""

    # Technology patterns with their typical emergence/critical periods
    TECHNOLOGY_PATTERNS = {
        # Network Technologies
        '5g': {'critical_years': [2019, 2020, 2021, 2022, 2023, 2024, 2025], 'priority': 'high'},
        '6g': {'critical_years': [2023, 2024, 2025], 'priority': 'emerging'},
        '4g': {'critical_years': [2010, 2011, 2012, 2013, 2014, 2015, 2016], 'priority': 'medium'},
        'lte': {'critical_years': [2010, 2011, 2012, 2013, 2014, 2015], 'priority': 'medium'},
        'wifi': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'bluetooth': {'critical_years': [2017, 2018, 2019, 2020, 2021, 2022, 2023], 'priority': 'medium'},

        # Security & Malware
        'ransomware': {'critical_years': [2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024],
                       'priority': 'critical'},
        'wannacry': {'critical_years': [2017, 2018], 'priority': 'critical'},
        'emotet': {'critical_years': [2018, 2019, 2020, 2021], 'priority': 'high'},
        'apt': {'critical_years': [2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'critical'},

        # Popular Libraries/Frameworks
        'log4j': {'critical_years': [2021, 2022, 2023], 'priority': 'critical'},
        'log4shell': {'critical_years': [2021, 2022], 'priority': 'critical'},
        'spring': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'struts': {'critical_years': [2017, 2018, 2019], 'priority': 'high'},
        'apache': {'critical_years': [2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},

        # Cloud & Container Technologies
        'docker': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'kubernetes': {'critical_years': [2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'k8s': {'critical_years': [2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'aws': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'azure': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},

        # IoT & Industrial
        'iot': {'critical_years': [2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'scada': {'critical_years': [2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022], 'priority': 'critical'},
        'plc': {'critical_years': [2016, 2017, 2018, 2019, 2020, 2021, 2022], 'priority': 'high'},

        # Web Technologies
        'wordpress': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'drupal': {'critical_years': [2018, 2019, 2020, 2021, 2022], 'priority': 'medium'},
        'nodejs': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'react': {'critical_years': [2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'medium'},

        # AI/ML Technologies
        'tensorflow': {'critical_years': [2020, 2021, 2022, 2023, 2024], 'priority': 'emerging'},
        'pytorch': {'critical_years': [2020, 2021, 2022, 2023, 2024], 'priority': 'emerging'},
        'llm': {'critical_years': [2022, 2023, 2024, 2025], 'priority': 'emerging'},
        'chatgpt': {'critical_years': [2022, 2023, 2024], 'priority': 'emerging'},

        # Generic vulnerability types (use recent years by default)
        'remote code execution': {'critical_years': [2020, 2021, 2022, 2023, 2024], 'priority': 'critical'},
        'sql injection': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'cross-site scripting': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
        'buffer overflow': {'critical_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024], 'priority': 'high'},
    }

    @classmethod
    def detect_technologies(cls, query: str) -> Dict[str, Any]:
        """Detect technologies and determine critical years from query"""
        query_lower = query.lower()
        detected_technologies = []
        critical_years = set()
        max_priority_level = 0

        priority_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'emerging': 5}

        for tech, info in cls.TECHNOLOGY_PATTERNS.items():
            if tech in query_lower:
                detected_technologies.append({
                    'technology': tech,
                    'priority': info['priority'],
                    'critical_years': info['critical_years']
                })
                critical_years.update(info['critical_years'])
                max_priority_level = max(max_priority_level, priority_levels.get(info['priority'], 0))

        # If no specific technologies detected, use recent years for general queries
        if not critical_years:
            current_year = datetime.now().year
            critical_years = set(range(max(2018, current_year - 6), current_year + 1))

        # Expand search years based on priority
        if max_priority_level >= 4:  # Critical or emerging
            # For critical technologies, expand to include more recent years
            current_year = datetime.now().year
            critical_years.update(range(current_year - 3, current_year + 1))

        return {
            'detected_technologies': detected_technologies,
            'critical_years': sorted(list(critical_years)),
            'priority_level': max_priority_level,
            'search_strategy': cls._determine_search_strategy(detected_technologies, max_priority_level)
        }

    @classmethod
    def _determine_search_strategy(cls, technologies: List[Dict], priority_level: int) -> Dict[str, Any]:
        """Determine optimal search strategy based on detected technologies"""
        if priority_level >= 4:  # Critical or emerging
            return {
                'search_type': 'comprehensive',
                'year_expansion': 'aggressive',
                'result_limit': 50,
                'include_related': True
            }
        elif priority_level >= 3:  # High priority
            return {
                'search_type': 'focused',
                'year_expansion': 'moderate',
                'result_limit': 30,
                'include_related': True
            }
        else:  # Medium/Low priority
            return {
                'search_type': 'standard',
                'year_expansion': 'conservative',
                'result_limit': 20,
                'include_related': False
            }


@router.post("/query")
async def process_query(request: QueryRequest):
    """Enhanced query processing with dynamic technology detection and critical years"""
    start_time = time.time()

    try:
        # Validate request parameters
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        if request.top_k > 50:
            request.top_k = 50
        if hasattr(request, 'max_context_docs') and request.max_context_docs > 20:
            request.max_context_docs = 20

        # Get components
        rag_system = get_rag_system()
        llm_client = get_llm_client()
        query_router = get_query_router()

        # Enhanced technology detection and critical year determination
        tech_analysis = TechnologyDetector.detect_technologies(request.query)
        logger.info(f"Technology analysis: {tech_analysis}")

        # Extract entities and enhance with technology analysis
        entities = {}
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', request.query, re.IGNORECASE)

        if query_router:
            entities = query_router.extract_entities(request.query)

        # Determine optimal years to search (limit to most relevant years)
        if hasattr(request, 'years') and request.years:
            search_years = request.years
        elif tech_analysis['critical_years']:
            # Limit to most recent/relevant years for performance
            all_critical_years = tech_analysis['critical_years']
            if tech_analysis['priority_level'] >= 4:  # Critical/Emerging tech
                # For critical tech like log4shell, focus on the core critical years
                search_years = [str(year) for year in all_critical_years[-4:]]  # Last 4 years max
            else:
                # For normal tech, limit to recent years
                search_years = [str(year) for year in all_critical_years[-3:]]  # Last 3 years max
        else:
            # Default to recent years if no specific technology detected
            current_year = datetime.now().year
            search_years = [str(year) for year in range(current_year - 3, current_year + 1)]

        # Adjust top_k based on search strategy
        strategy = tech_analysis['search_strategy']
        adjusted_top_k = min(request.top_k, strategy['result_limit'])

        # Route query with timeout and enhanced parameters
        query_type = QueryType.SEARCH
        metadata = {}

        if query_router:
            try:
                query_type, metadata = await asyncio.wait_for(
                    asyncio.to_thread(query_router.analyze_query, request.query),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                query_type = QueryType.SEARCH
                metadata = {}

        # Perform search with timeout (increased for critical technologies)
        search_timeout = 30.0 if tech_analysis['priority_level'] >= 4 else 15.0
        
        try:
            if cve_ids:
                # Direct CVE lookup
                search_results = await asyncio.wait_for(
                    asyncio.to_thread(rag_system.search, cve_ids[0], adjusted_top_k),
                    timeout=search_timeout
                )
            else:
                # Technology-aware search
                if hasattr(rag_system, 'search_cves_by_year'):
                    search_results = await asyncio.wait_for(
                        asyncio.to_thread(
                            rag_system.search_cves_by_year, 
                            request.query, 
                            search_years, 
                            adjusted_top_k,
                            entities.get('vendors', []),
                            entities.get('technologies', [])
                        ),
                        timeout=search_timeout
                    )
                else:
                    # Fallback to basic search
                    search_results = await asyncio.wait_for(
                        asyncio.to_thread(rag_system.search, request.query, adjusted_top_k),
                        timeout=search_timeout
                    )
        except asyncio.TimeoutError:
            logger.error(f"Search timeout ({search_timeout}s) for query: {request.query[:50]}...")
            raise HTTPException(status_code=408, detail=f"Search operation timed out after {search_timeout}s. Try a more specific query or fewer years.")

        # Generate LLM response if available
        llm_response = "Search completed successfully. LLM response generation not available."

        if llm_client and hasattr(request, 'stream') and not request.stream:
            try:
                # Generate comprehensive response
                context_docs = search_results[:getattr(request, 'max_context_docs', 5)]
                context_text = "\n\n".join([
                    f"CVE: {doc.get('id', 'Unknown')}\n"
                    f"Description: {doc.get('text', doc.get('content', ''))[:500]}..."
                    for doc in context_docs
                ])

                # Enhanced prompt with technology context
                tech_context = ""
                if tech_analysis['detected_technologies']:
                    tech_names = [t['technology'] for t in tech_analysis['detected_technologies']]
                    tech_context = f"\n\nDetected technologies: {', '.join(tech_names)}"
                    tech_context += f"\nCritical years for analysis: {', '.join(search_years)}"

                prompt = f"""Based on the following cybersecurity information, provide a comprehensive answer to the user's question.

Question: {request.query}{tech_context}

Relevant CVE Information:
{context_text}

Please provide a detailed, accurate response that addresses the question directly. Focus on:
1. Direct answers to the specific query
2. Relevant vulnerability details and impacts
3. Timeline and affected technologies
4. Recommended mitigations or actions

Response:"""

                llm_response = await asyncio.wait_for(
                    asyncio.to_thread(
                        llm_client.generate_response,
                        prompt,
                        use_large_model=getattr(request, 'use_large_model', False)
                    ),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                logger.error(f"LLM timeout for query: {request.query[:50]}...")
                llm_response = "Response generation timed out. Please try a more specific query."
            except Exception as e:
                logger.error(f"LLM error: {e}")
                llm_response = f"Response generation error: {str(e)}"

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

        return QueryResponse(
            query=request.query,
            response=llm_response,
            search_results=pydantic_results,
            query_type=query_type,
            processing_time=processing_time,
            model_used="enhanced_rag"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Query processing failed: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Query processing failed: {str(e)}")


@router.post("/search")
async def search_cves(request: QueryRequest):
    """Enhanced search with technology-aware critical year detection"""
    try:
        if not request.query or len(request.query.strip()) == 0:
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        rag_system = get_rag_system()
        
        # Detect technologies and determine critical years
        tech_analysis = TechnologyDetector.detect_technologies(request.query)
        
        # Determine search years (optimized for performance)
        if hasattr(request, 'years') and request.years:
            search_years = request.years
        elif tech_analysis['critical_years']:
            # Limit years for better performance
            all_critical_years = tech_analysis['critical_years']
            if tech_analysis['priority_level'] >= 4:  # Critical tech
                search_years = [str(year) for year in all_critical_years[-4:]]  # Last 4 years
            else:
                search_years = [str(year) for year in all_critical_years[-3:]]  # Last 3 years
        else:
            current_year = datetime.now().year
            search_years = [str(year) for year in range(current_year - 3, current_year + 1)]
        
        # Perform enhanced search with performance optimization
        search_timeout = 30.0 if tech_analysis['priority_level'] >= 4 else 20.0
        
        if hasattr(rag_system, 'search_cves_by_year'):
            search_results = await asyncio.wait_for(
                asyncio.to_thread(
                    rag_system.search_cves_by_year,
                    request.query,
                    search_years,
                    request.top_k
                ),
                timeout=search_timeout
            )
        else:
            # Fallback to basic search
            search_results = await asyncio.wait_for(
                asyncio.to_thread(rag_system.search, request.query, request.top_k),
                timeout=search_timeout
            )
        
        # Convert to response format
        pydantic_results = []
        for result in search_results:
            pydantic_results.append(SearchResult(
                id=result.get('id', ''),
                text=result.get('text', result.get('content', '')),
                metadata={
                    **result.get('metadata', {}),
                    'technology_analysis': tech_analysis,
                    'search_years': search_years
                },
                score=result.get('score', 0.0),
                distance=result.get('distance', 1.0)
            ))
        
        return pydantic_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enhanced search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced search failed: {str(e)}")


@router.get("/technologies")
async def get_supported_technologies():
    """Get list of supported technologies and their critical years"""
    return {
        "supported_technologies": TechnologyDetector.TECHNOLOGY_PATTERNS,
        "detection_info": {
            "total_technologies": len(TechnologyDetector.TECHNOLOGY_PATTERNS),
            "categories": {
                "network": ["5g", "6g", "4g", "lte", "wifi", "bluetooth"],
                "security": ["ransomware", "wannacry", "emotet", "apt"],
                "frameworks": ["log4j", "spring", "struts", "apache"],
                "cloud": ["docker", "kubernetes", "aws", "azure"],
                "iot": ["iot", "scada", "plc"],
                "web": ["wordpress", "drupal", "nodejs", "react"],
                "ai_ml": ["tensorflow", "pytorch", "llm", "chatgpt"]
            }
        }
    }


@router.get("/analyze/{query}")
async def analyze_query_technologies(query: str):
    """Analyze a query to detect technologies and suggest critical years"""
    tech_analysis = TechnologyDetector.detect_technologies(query)

    return {
        "query": query,
        "analysis": tech_analysis,
        "recommendations": {
            "suggested_years": tech_analysis['critical_years'],
            "search_strategy": tech_analysis['search_strategy'],
            "priority_explanation": f"Priority level {tech_analysis['priority_level']}/5 based on detected technologies"
        }
    }


# Keep existing health endpoint
@router.get("/health")
async def health_check():
    """Enhanced health check with technology detection capabilities"""
    try:
        rag_system = get_rag_system()
        if hasattr(rag_system, 'get_stats'):
            stats = rag_system.get_stats()
        else:
            stats = {"status": "unknown"}

        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "stats": {
                **stats,
                "features": [
                    "Dynamic critical year detection",
                    "Technology-aware search",
                    f"Support for {len(TechnologyDetector.TECHNOLOGY_PATTERNS)} technologies",
                    "Multi-year intelligent filtering",
                    "Adaptive search strategies"
                ]
            }
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


# Add a simple endpoint to test the new functionality
@router.get("/test-tech-detection")
async def test_technology_detection():
    """Test endpoint for technology detection"""
    test_queries = [
        "5G vulnerabilities",
        "ransomware attacks 2023",
        "log4j remote code execution",
        "6G security risks",
        "IoT device vulnerabilities"
    ]

    results = {}
    for query in test_queries:
        analysis = TechnologyDetector.detect_technologies(query)
        results[query] = {
            "detected_technologies": [t['technology'] for t in analysis['detected_technologies']],
            "critical_years": analysis['critical_years'],
            "priority_level": analysis['priority_level']
        }

    return {
        "message": "Technology detection test results",
        "results": results,
        "total_supported_technologies": len(TechnologyDetector.TECHNOLOGY_PATTERNS)
    }