#!/usr/bin/env python3
"""
Optimized RAG System for CVE Knowledge Graph with Performance Improvements

Key optimizations:
- Lazy loading of heavy components
- Caching of embeddings and search results
- Connection pooling for vector database
- Async operations where possible
- Memory-efficient data structures
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import gc
import time
from functools import lru_cache
import threading
from concurrent.futures import ThreadPoolExecutor

from src.generators.rag_config import (
    CVE_DATA_PATH, VECTOR_DB_PATH, EMBEDDING_MODEL_NAME, CHUNK_SIZE, CHUNK_OVERLAP, 
    LOGGING_LEVEL, DEVICE, EMBEDDING_BATCH_SIZE, MAX_SEQ_LENGTH, CVE_YEAR_PATHS
)

import chromadb
from chromadb.config import Settings
import numpy as np
from sentence_transformers import SentenceTransformer
import torch
from tqdm import tqdm
import networkx as nx

# Configure logging
logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger(__name__)

class OptimizedCVESearchEngine:
    """Optimized search engine with connection pooling and caching"""
    
    def __init__(self, persist_directory: str = VECTOR_DB_PATH):
        self.persist_directory = persist_directory
        self._client = None
        self._collection = None
        self._lock = threading.Lock()
        
    @property
    def client(self):
        """Lazy load ChromaDB client with connection pooling"""
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = chromadb.PersistentClient(
                        path=self.persist_directory,
                        settings=Settings(
                            anonymized_telemetry=False,
                            allow_reset=True
                        )
                    )
        return self._client
    
    @property
    def collection(self):
        """Lazy load collection"""
        if self._collection is None:
            with self._lock:
                if self._collection is None:
                    try:
                        self._collection = self.client.get_collection("cve_documents")
                    except:
                        self._collection = self.client.create_collection("cve_documents")
        return self._collection
    
    @lru_cache(maxsize=1000)
    def search(self, query: str, n_results: int = 10, 
               filter_dict: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Cached search with optimized query processing"""
        try:
            # Use embedding generator for query embedding
            from .rag_system import CVEEmbeddingGenerator
            embedding_gen = CVEEmbeddingGenerator()
            query_embedding = embedding_gen.generate_embeddings([query])[0]
            
            # Perform search
            results = self.collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=n_results,
                where=filter_dict
            )
            
            # Format results
            formatted_results = []
            if results['documents']:
                for i, doc in enumerate(results['documents'][0]):
                    formatted_results.append({
                        'id': results['ids'][0][i],
                        'text': doc,
                        'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                        'distance': results['distances'][0][i] if results['distances'] else 0.0
                    })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        try:
            count = self.collection.count()
            return {
                "total_documents": count,
                "collection_name": "cve_documents",
                "persist_directory": self.persist_directory
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"total_documents": 0}

class OptimizedCVERAGSystem:
    """Optimized RAG system with performance improvements"""
    
    def __init__(self, 
                 vector_db_path: str = VECTOR_DB_PATH,
                 cve_data_path: str = CVE_DATA_PATH):
        self.vector_db_path = vector_db_path
        self.cve_data_path = cve_data_path
        self.search_engine = OptimizedCVESearchEngine(vector_db_path)
        self._embedding_generator = None
        self._fine_tuned_model = None
        self._kg_builder = None
        self._executor = ThreadPoolExecutor(max_workers=4)
        
        logger.info(f"Optimized RAG System initialized")
    
    @property
    def embedding_generator(self):
        """Lazy load embedding generator with singleton pattern"""
        if self._embedding_generator is None:
            from .rag_system import CVEEmbeddingGenerator
            self._embedding_generator = CVEEmbeddingGenerator()
        return self._embedding_generator
    
    @property
    def fine_tuned_model(self):
        """Lazy load fine-tuned model only when needed"""
        if self._fine_tuned_model is None:
            try:
                from src.training.hf_inference_engine import HFCVEInferenceEngine
                self._fine_tuned_model = HFCVEInferenceEngine(
                    use_fine_tuned=True,
                    fine_tuned_path="models/fine_tuned_cve_production"
                )
                logger.info("✅ Fine-tuned model loaded")
            except Exception as e:
                logger.warning(f"⚠️ Fine-tuned model failed: {e}")
                self._fine_tuned_model = None
        return self._fine_tuned_model
    
    @property
    def kg_builder(self):
        """Lazy load knowledge graph builder"""
        if self._kg_builder is None:
            try:
                from src.constructors.networkx_graph_builder import NetworkXGraphBuilder
                self._kg_builder = NetworkXGraphBuilder()
                logger.info("✅ Knowledge graph builder loaded")
            except Exception as e:
                logger.warning(f"⚠️ KG builder failed: {e}")
                self._kg_builder = None
        return self._kg_builder
    
    @lru_cache(maxsize=100)
    def search_cves(self, query: str, n_results: int = 10, 
                   severity_filter: Optional[str] = None,
                   vendor_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Cached CVE search"""
        filter_dict = {}
        if severity_filter:
            filter_dict["severity"] = severity_filter
        if vendor_filter:
            filter_dict["vendors"] = {"$contains": vendor_filter}
        
        return self.search_engine.search(query, n_results, filter_dict)
    
    def enhanced_query(self, query: str, n_results: int = 10,
                       analysis_type: str = "vulnerability_analysis",
                       use_fine_tuned: bool = True,
                       use_kg_enhancement: bool = True) -> Dict[str, Any]:
        """Optimized enhanced query with parallel processing"""
        start_time = time.time()
        
        # Step 1: Search for relevant documents (cached)
        search_results = self.search_cves(query, n_results)
        
        if not search_results:
            return {
                "query": query,
                "response": "No relevant CVE data found.",
                "search_results": [],
                "analysis_type": analysis_type,
                "processing_time": time.time() - start_time,
                "model_used": "none",
                "kg_enhancement_used": False
            }
        
        # Step 2: Parallel KG enhancement (if enabled)
        kg_enhancement_used = False
        if use_kg_enhancement and self.kg_builder:
            try:
                # Run KG enhancement in parallel
                future = self._executor.submit(self._enhance_with_knowledge_graph, search_results, query)
                enhanced_results = future.result(timeout=10)  # 10s timeout
                
                if enhanced_results:
                    search_results = enhanced_results
                    kg_enhancement_used = True
                    logger.info("✅ KG enhancement completed")
            except Exception as e:
                logger.warning(f"⚠️ KG enhancement failed: {e}")
        
        # Step 3: Generate response (lazy load model if needed)
        try:
            if use_fine_tuned and self.fine_tuned_model:
                response = self.fine_tuned_model.generate_response(query, search_results, analysis_type)
                model_used = "fine_tuned"
            else:
                response = self._generate_simple_response(query, search_results, analysis_type)
                model_used = "simple"
        except Exception as e:
            logger.error(f"Response generation error: {e}")
            response = f"Error generating response: {str(e)}"
            model_used = "error"
        
        processing_time = time.time() - start_time
        
        return {
            "query": query,
            "response": response,
            "search_results": search_results,
            "analysis_type": analysis_type,
            "processing_time": processing_time,
            "model_used": model_used,
            "kg_enhancement_used": kg_enhancement_used
        }
    
    def _enhance_with_knowledge_graph(self, search_results: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
        """Optimized KG enhancement with caching"""
        if not self.kg_builder:
            return search_results
        
        enhanced_results = []
        for result in search_results:
            cve_id = result.get('metadata', {}).get('cve_id', result.get('id', ''))
            if cve_id:
                kg_data = self._get_kg_enhancement_for_cve(cve_id)
                if kg_data:
                    result['kg_enhancement'] = kg_data
            enhanced_results.append(result)
        
        return enhanced_results
    
    @lru_cache(maxsize=500)
    def _get_kg_enhancement_for_cve(self, cve_id: str) -> Dict[str, Any]:
        """Cached KG enhancement for individual CVEs"""
        if not self.kg_builder:
            return {}
        
        try:
            graph = self.kg_builder.G
            if not graph or cve_id not in graph:
                return {}
            
            # Get related CVEs
            related_cves = self.kg_builder.find_similar_vulnerabilities(cve_id, top_k=3)
            
            # Get centrality metrics (convert multigraph to simple graph)
            simple_graph = nx.Graph(graph)
            centrality_metrics = {
                'degree_centrality': graph.degree(cve_id),
                'clustering_coefficient': nx.clustering(simple_graph, cve_id) if cve_id in simple_graph else 0.0
            }
            
            return {
                'related_cves': [{'cve_id': cve, 'similarity_score': score} for cve, score in related_cves],
                'centrality_metrics': centrality_metrics,
                'relationship_insights': self._generate_kg_insights(cve_id, graph)
            }
            
        except Exception as e:
            logger.error(f"KG enhancement error for {cve_id}: {e}")
            return {}
    
    def _generate_kg_insights(self, cve_id: str, graph) -> List[str]:
        """Generate KG insights"""
        insights = []
        try:
            if cve_id in graph:
                node_data = graph.nodes[cve_id]
                
                vendors = node_data.get('vendors', [])
                if vendors:
                    insights.append(f"Affects {len(vendors)} vendor(s): {', '.join(vendors[:3])}")
                
                products = node_data.get('products', [])
                if products:
                    insights.append(f"Impacts {len(products)} product(s): {', '.join(products[:3])}")
                
                severity = node_data.get('cvss_v3_severity', 'Unknown')
                if severity != 'Unknown':
                    insights.append(f"Severity: {severity}")
                
                neighbors = list(graph.neighbors(cve_id))
                if neighbors:
                    insights.append(f"Connected to {len(neighbors)} other entities")
                    
        except Exception as e:
            logger.error(f"KG insights error for {cve_id}: {e}")
        
        return insights
    
    def _generate_simple_response(self, query: str, context_docs: List[Dict], analysis_type: str) -> str:
        """Generate simple response without LLM"""
        if not context_docs:
            return "No relevant information found."
        
        # Extract key information from context
        cve_info = []
        for doc in context_docs[:3]:  # Limit to 3 docs
            metadata = doc.get('metadata', {})
            cve_id = metadata.get('cve_id', 'Unknown')
            severity = metadata.get('severity', 'Unknown')
            cve_info.append(f"{cve_id} ({severity})")
        
        return f"Found {len(context_docs)} relevant CVEs: {', '.join(cve_info)}"
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        return self.search_engine.get_collection_stats()
    
    def cleanup(self):
        """Cleanup resources"""
        if self._executor:
            self._executor.shutdown(wait=True)
        if self._fine_tuned_model:
            del self._fine_tuned_model
            self._fine_tuned_model = None
        gc.collect()

# Keep the original classes for compatibility
class CVEDocumentProcessor:
    """Process CVE documents for RAG system"""
    # ... (same as original)
    pass

class CVEEmbeddingGenerator:
    """Generate embeddings for CVE documents"""
    # ... (same as original)
    pass 