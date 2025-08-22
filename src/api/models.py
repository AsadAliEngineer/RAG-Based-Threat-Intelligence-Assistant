"""
Pydantic models for the RAG API
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from enum import Enum

class QueryType(str, Enum):
    SEARCH = "search"
    CVE_LOOKUP = "cve_lookup"
    VENDOR_ANALYSIS = "vendor_analysis"
    SIMILARITY_SEARCH = "similarity_search"
    TEMPORAL_QUERY = "temporal_query"
    GENERAL = "general"

class QueryRequest(BaseModel):
    """Request model for RAG queries"""
    model_config = ConfigDict(protected_namespaces=())
    
    query: str = Field(..., description="The search query")
    top_k: int = Field(default=10, ge=1, le=50, description="Number of results to return")
    max_context_docs: int = Field(default=5, ge=1, le=20, description="Maximum context documents for LLM")
    use_large_model: bool = Field(default=False, description="Use 70B model instead of 8B")
    severity_filter: Optional[str] = Field(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
    vendor_filter: Optional[str] = Field(None, description="Filter by vendor name")

class SearchResult(BaseModel):
    """Search result model"""
    model_config = ConfigDict(protected_namespaces=())
    
    id: str
    text: str
    metadata: Dict[str, Any]
    score: float
    distance: float

class QueryResponse(BaseModel):
    """Response model for RAG queries"""
    model_config = ConfigDict(protected_namespaces=())
    
    query: str
    response: str
    search_results: List[SearchResult]
    query_type: QueryType
    processing_time: float
    model_used: str

class StreamResponse(BaseModel):
    """Streaming response model"""
    model_config = ConfigDict(protected_namespaces=())
    
    chunk: str
    done: bool = False

class SummaryRequest(BaseModel):
    """Request model for vulnerability summaries"""
    model_config = ConfigDict(protected_namespaces=())
    
    query: str = Field(..., description="The summary query")
    max_results: int = Field(default=50, ge=10, le=100, description="Maximum results to analyze")

class SummaryResponse(BaseModel):
    """Response model for vulnerability summaries"""
    model_config = ConfigDict(protected_namespaces=())
    
    query: str
    total_results: int
    severity_distribution: Dict[str, int]
    top_vendors: List[str]
    top_products: List[str]
    common_weaknesses: List[str]
    sample_results: List[SearchResult]

class HealthResponse(BaseModel):
    """Health check response model"""
    model_config = ConfigDict(protected_namespaces=())
    
    status: str
    gpu_available: bool
    gpu_name: Optional[str] = None
    vector_db_documents: int
    model_loaded: bool 

class YearSearchRequest(BaseModel):
    query: str
    years: List[str] = ['2021', '2022', '2023', '2024','2025']  # Default to recent years
    n_results: int = 10
    severity_filter: Optional[str] = None
    vendor_filter: Optional[str] = None 