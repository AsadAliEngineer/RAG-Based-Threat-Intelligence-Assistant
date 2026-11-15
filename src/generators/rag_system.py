#!/usr/bin/env python3
"""
Enhanced RAG System for CVE Knowledge Graph with GPU Optimization

Usage examples:
  Build vector DB (default):
    python -m src.generators.rag_system --build
  Search for a query:
    python -m src.generators.rag_system --search "SQL injection vulnerabilities"
  Get vulnerability summary:
    python -m src.generators.rag_system --summary "SQL injection"

Configuration is centralized in rag_config.py. Do not hardcode paths or model names here.
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import gc

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

# Configure logging
logging.basicConfig(level=LOGGING_LEVEL)
logger = logging.getLogger(__name__)

class CVEDocumentProcessor:
    """Process CVE documents for RAG system"""
    
    def __init__(self, chunk_size: int = CHUNK_SIZE, chunk_overlap: int = CHUNK_OVERLAP):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
    
    def load_cve_documents(self, file_path: str) -> List[Dict[str, Any]]:
        """Load CVE documents from exported JSON file"""
        logger.info(f"Loading CVE documents from {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            logger.info("Please run export_kg_for_rag_direct.py first to create RAG-ready data")
            return []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            documents = json.load(f)
        
        logger.info(f"Loaded {len(documents)} CVE documents")
        return documents
    
    def chunk_document(self, doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Split a CVE document into smaller chunks for better retrieval"""
        chunks = []
        
        # Get the main text for chunking
        text = doc.get('text_for_embedding', '')
        if not text:
            # Fallback to description if embedding text is not available
            text = doc.get('description', '')
        
        if not text:
            # If no text available, create a minimal chunk
            chunks.append({
                'id': f"{doc['id']}_chunk_0",
                'cve_id': doc['id'],
                'text': f"CVE ID: {doc['id']} | Severity: {doc.get('cvss_v3', {}).get('base_severity', 'Unknown')}",
                'metadata': {
                    'cve_id': doc['id'],
                    'chunk_index': 0,
                    'severity': doc.get('cvss_v3', {}).get('base_severity'),
                    'cvss_score': doc.get('cvss_v3', {}).get('base_score'),
                    'products': doc.get('affected_products', []),
                    'vendors': doc.get('affected_vendors', []),
                    'cwe_refs': doc.get('cwe_refs', []),
                    'capec_entries': doc.get('capec_entries', []),
                    'mitre_techniques': doc.get('mitre_techniques', [])
                }
            })
            return chunks
        
        # Simple text chunking (can be enhanced with more sophisticated methods)
        words = text.split()
        
        if len(words) <= self.chunk_size:
            # Document is small enough, no need to chunk
            chunks.append({
                'id': f"{doc['id']}_chunk_0",
                'cve_id': doc['id'],
                'text': text,
                'metadata': {
                    'cve_id': doc['id'],
                    'chunk_index': 0,
                    'severity': doc.get('cvss_v3', {}).get('base_severity'),
                    'cvss_score': doc.get('cvss_v3', {}).get('base_score'),
                    'products': doc.get('affected_products', []),
                    'vendors': doc.get('affected_vendors', []),
                    'cwe_refs': doc.get('cwe_refs', []),
                    'capec_entries': doc.get('capec_entries', []),
                    'mitre_techniques': doc.get('mitre_techniques', [])
                }
            })
        else:
            # Split into overlapping chunks
            for i in range(0, len(words), self.chunk_size - self.chunk_overlap):
                chunk_words = words[i:i + self.chunk_size]
                chunk_text = ' '.join(chunk_words)
                
                chunks.append({
                    'id': f"{doc['id']}_chunk_{i//(self.chunk_size - self.chunk_overlap)}",
                    'cve_id': doc['id'],
                    'text': chunk_text,
                    'metadata': {
                        'cve_id': doc['id'],
                        'chunk_index': i//(self.chunk_size - self.chunk_overlap),
                        'severity': doc.get('cvss_v3', {}).get('base_severity'),
                        'cvss_score': doc.get('cvss_v3', {}).get('base_score'),
                        'products': doc.get('affected_products', []),
                        'vendors': doc.get('affected_vendors', []),
                        'cwe_refs': doc.get('cwe_refs', []),
                        'capec_entries': doc.get('capec_entries', []),
                        'mitre_techniques': doc.get('mitre_techniques', [])
                    }
                })
        
        return chunks
    
    def process_documents(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process all CVE documents into chunks"""
        logger.info("Processing CVE documents into chunks...")
        
        all_chunks = []
        for doc in tqdm(documents, desc="Chunking documents"):
            chunks = self.chunk_document(doc)
            all_chunks.extend(chunks)
        
        logger.info(f"Created {len(all_chunks)} chunks from {len(documents)} documents")
        return all_chunks

class CVEEmbeddingGenerator:
    """Generate embeddings for CVE documents with GPU optimization"""
    
    def __init__(self, model_name: str = EMBEDDING_MODEL_NAME):
        self.model_name = model_name
        self.device = DEVICE
        
        # Load model with GPU optimization
        logger.info(f"Loading embedding model: {model_name} on {self.device}")
        self.model = SentenceTransformer(model_name)
        self.model.to(self.device)
        self.model.max_seq_length = MAX_SEQ_LENGTH
        
        logger.info(f"Initialized embedding model: {model_name} on {self.device}")
    
    def generate_embeddings(self, texts: List[str], batch_size: int = EMBEDDING_BATCH_SIZE) -> np.ndarray:
        """Generate embeddings for a list of texts with GPU optimization"""
        logger.info(f"Generating embeddings for {len(texts)} texts with batch size {batch_size}...")
        
        embeddings = []
        
        # Process in batches to optimize GPU memory usage
        for i in tqdm(range(0, len(texts), batch_size), desc="Generating embeddings"):
            batch_texts = texts[i:i + batch_size]
            
            # Use mixed precision for faster computation
            with torch.cuda.amp.autocast() if self.device == "cuda" else torch.no_grad():
                batch_embeddings = self.model.encode(
                    batch_texts,
                    convert_to_tensor=True,
                    show_progress_bar=False,
                    normalize_embeddings=True
                )
            
            # Move to CPU and convert to numpy
            embeddings.append(batch_embeddings.cpu().numpy())
            
            # Clear GPU cache periodically
            if self.device == "cuda" and i % (batch_size * 10) == 0:
                torch.cuda.empty_cache()
                gc.collect()
        
        result = np.vstack(embeddings)
        logger.info(f"Generated embeddings with shape: {result.shape}")
        return result

class CVESearchEngine:
    """Vector search engine for CVE data"""
    
    def __init__(self, persist_directory: str = VECTOR_DB_PATH):
        self.persist_directory = persist_directory
        os.makedirs(persist_directory, exist_ok=True)
        
        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Create or get collection
        self.collection = self.client.get_or_create_collection(
            name="cve_documents",
            metadata={"description": "CVE vulnerability documents for semantic search"}
        )
        
        logger.info(f"Initialized search engine with collection: {self.collection.name}")
    
    def add_documents(self, chunks: List[Dict[str, Any]], embeddings: np.ndarray, batch_size: int = 5000):
        """Add documents and embeddings to the vector database in batches"""
        logger.info("Adding documents to vector database in batches...")
        logger.info(f"Collection name: {self.collection.name}")
        logger.info(f"Collection count before adding: {self.collection.count()}")
        
        total = len(chunks)
        for start in tqdm(range(0, total, batch_size), desc="Adding to vector store"):
            end = min(start + batch_size, total)
            batch_chunks = chunks[start:end]
            batch_embeddings = embeddings[start:end]
            ids = [chunk['id'] for chunk in batch_chunks]
            texts = [chunk['text'] for chunk in batch_chunks]
            
            # Debug: Check for any issues with the first batch
            if start == 0:
                logger.info(f"First batch - IDs count: {len(ids)}")
                logger.info(f"First batch - Texts count: {len(texts)}")
                logger.info(f"First batch - Embeddings shape: {batch_embeddings.shape}")
                logger.info(f"Sample ID: {ids[0] if ids else 'None'}")
                logger.info(f"Sample text length: {len(texts[0]) if texts else 0}")
                # Debug metadata
                if batch_chunks:
                    sample_metadata = batch_chunks[0]['metadata']
                    logger.info(f"Sample metadata keys: {list(sample_metadata.keys())}")
                    logger.info(f"Sample CWE refs: {sample_metadata.get('cwe_refs', 'N/A')}")
                    logger.info(f"Sample CAPEC entries: {sample_metadata.get('capec_entries', 'N/A')}")
                    logger.info(f"Sample MITRE techniques: {sample_metadata.get('mitre_techniques', 'N/A')}")
            
            # Convert metadata lists to strings for ChromaDB compatibility
            metadatas = []
            for chunk in batch_chunks:
                metadata = {}
                for key, value in chunk['metadata'].items():
                    if value is not None:  # Skip None values
                        if isinstance(value, list):
                            metadata[key] = ', '.join(str(item) for item in value)
                        else:
                            metadata[key] = str(value)  # Convert all values to strings
                metadatas.append(metadata)
            
            embeddings_list = batch_embeddings.tolist()
            
            try:
                self.collection.add(
                    ids=ids,
                    embeddings=embeddings_list,
                    documents=texts,
                    metadatas=metadatas
                )
                logger.info(f"Added batch {start} to {end} ({end-start} documents)")
            except Exception as e:
                logger.error(f"Error adding batch {start} to {end}: {e}")
                logger.error(f"Batch details - IDs: {ids[:3]}..., Texts: {len(texts)} items, Embeddings: {len(embeddings_list)} items")
                raise
                
        logger.info(f"Added {total} documents to vector database in total")
        logger.info(f"Collection count after adding: {self.collection.count()}")
    
    def search(self, query: str, n_results: int = 10, 
               filter_dict: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search for relevant CVE documents with performance optimizations"""
        logger.info(f"Searching for: '{query}' (n_results={n_results})")
        
        try:
            # Limit query length to prevent performance issues
            if len(query) > 1000:
                query = query[:1000]
                logger.warning("Query truncated to 1000 characters for performance")
            
            # Limit results to prevent memory issues
            if n_results > 50:
                n_results = 50
                logger.warning("Results limited to 50 for performance")
            
            logger.info(f"Query after processing: '{query}'")
            
            # Generate query embedding using the same model
            logger.info("Loading embedding model...")
            embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
            embedding_model.to(DEVICE)
            logger.info(f"Embedding model loaded on {DEVICE}")
            
            try:
                logger.info("Generating query embedding...")
                # Use a more efficient encoding approach
                query_embedding = embedding_model.encode([query], convert_to_tensor=False, show_progress_bar=False).tolist()
                logger.info(f"Query embedding generated, shape: {len(query_embedding[0])}")
            except Exception as e:
                logger.error(f"Error generating embedding: {e}")
                return []
            
            # Prepare query arguments with performance optimizations
            query_args = {
                "query_embeddings": query_embedding,
                "n_results": n_results,
                "include": ["documents", "metadatas", "distances"]  # Only get what we need
            }
            if filter_dict:
                query_args["where"] = filter_dict
            
            logger.info(f"Query args: {query_args}")
            logger.info(f"Collection name: {self.collection.name}")
            logger.info(f"Collection count: {self.collection.count()}")
            
            # Perform search with performance monitoring
            try:
                logger.info("Performing vector search...")
                results = self.collection.query(**query_args)
                logger.info(f"Raw search results keys: {list(results.keys()) if results else 'None'}")
            except Exception as e:
                logger.error(f"Error in vector search: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                return []
            
            # Format results efficiently
            formatted_results = []
            ids = results.get('ids', [[]]) or [[]]
            documents = results.get('documents', [[]]) or [[]]
            metadatas = results.get('metadatas', [[]]) or [[]]
            distances = results.get('distances', [[]]) or [[]]
            
            logger.info(f"Results arrays - IDs: {len(ids[0]) if ids and ids[0] else 0}, Documents: {len(documents[0]) if documents and documents[0] else 0}")
            logger.info(f"Results arrays - Metadatas: {len(metadatas[0]) if metadatas and metadatas[0] else 0}")
            
            # Debug: Check what metadata is actually being retrieved
            if metadatas and metadatas[0] and len(metadatas[0]) > 0:
                sample_metadata = metadatas[0][0]
                logger.info(f"Sample retrieved metadata keys: {list(sample_metadata.keys()) if sample_metadata else 'None'}")
                logger.info(f"Sample retrieved CWE refs: {sample_metadata.get('cwe_refs', 'N/A') if sample_metadata else 'N/A'}")
                logger.info(f"Sample retrieved CAPEC entries: {sample_metadata.get('capec_entries', 'N/A') if sample_metadata else 'N/A'}")
                logger.info(f"Sample retrieved MITRE techniques: {sample_metadata.get('mitre_techniques', 'N/A') if sample_metadata else 'N/A'}")
                logger.info(f"Sample retrieved severity: {sample_metadata.get('severity', 'N/A') if sample_metadata else 'N/A'}")
                logger.info(f"Sample retrieved products: {sample_metadata.get('products', 'N/A') if sample_metadata else 'N/A'}")
                # Show all metadata for debugging
                logger.info(f"Full sample metadata: {sample_metadata}")
            
            if (ids and ids[0] and documents and documents[0] and metadatas and metadatas[0] and distances and distances[0]):
                for i in range(min(len(ids[0]), n_results)):
                    # Limit text length to prevent memory issues
                    text = documents[0][i]
                    if len(text) > 2000:
                        text = text[:2000] + "..."
                    
                    result = {
                        'id': ids[0][i],
                        'text': text,
                        'metadata': metadatas[0][i],
                        'distance': distances[0][i],
                        'score': 1 - distances[0][i]  # Convert distance to similarity score
                    }
                    formatted_results.append(result)
            
            logger.info(f"Found {len(formatted_results)} results")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error in search: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the vector database"""
        count = self.collection.count()
        return {
            "total_documents": count,
            "collection_name": self.collection.name,
            "persist_directory": self.persist_directory
        }

class CVERAGSystem:
    """Main RAG system for CVE analysis"""
    
    def __init__(self, 
                 vector_db_path: str = VECTOR_DB_PATH,
                 cve_data_path: str = CVE_DATA_PATH):
        self.vector_db_path = vector_db_path
        self.cve_data_path = cve_data_path
        
        # Initialize components (lazy loading for heavy components)
        self.processor = CVEDocumentProcessor()
        self._embedding_generator = None  # Lazy load
        self.search_engine = CVESearchEngine(vector_db_path)
        
        logger.info("Initialized Enhanced CVE RAG System (lazy loading enabled)")
    
    @property
    def embedding_generator(self):
        """Lazy load embedding generator"""
        if self._embedding_generator is None:
            logger.info("Loading embedding model (this may take a moment)...")
            self._embedding_generator = CVEEmbeddingGenerator()
            logger.info("Embedding model loaded successfully")
        return self._embedding_generator
    
    def build_vector_database(self, force_rebuild: bool = False):
        """Build the vector database from CVE documents"""
        logger.info("Building vector database...")
        
        # Check if database already exists and has data
        if not force_rebuild:
            stats = self.search_engine.get_collection_stats()
            if stats["total_documents"] > 0:
                logger.info(f"Vector database already exists with {stats['total_documents']} documents")
                return
        
        # Clear existing collection if rebuilding
        if force_rebuild:
            logger.info("Force rebuild requested - using fresh vector database directory...")
            
            # Ensure the directory exists with proper permissions
            os.makedirs(self.vector_db_path, exist_ok=True)
            # Set directory permissions to ensure it's writable
            os.chmod(self.vector_db_path, 0o755)
            logger.info(f"Using fresh vector database directory: {self.vector_db_path}")
            
            # Recreate the search engine to ensure fresh collection
            logger.info("Recreating search engine with fresh collection...")
            self.search_engine = CVESearchEngine(self.vector_db_path)
        
        # Load and process documents
        documents = self.processor.load_cve_documents(self.cve_data_path)
        if not documents:
            logger.error("No documents loaded. Please run export_kg_for_rag_direct.py first.")
            return
            
        chunks = self.processor.process_documents(documents)
        
        # Remove duplicates before generating embeddings to save time
        seen_ids = set()
        unique_chunks = []
        duplicate_count = 0
        
        for chunk in chunks:
            chunk_id = chunk['id']
            if chunk_id in seen_ids:
                duplicate_count += 1
                continue
            seen_ids.add(chunk_id)
            unique_chunks.append(chunk)
        
        if duplicate_count > 0:
            logger.warning(f"Removed {duplicate_count} duplicate chunks before embedding generation.")
            logger.info(f"Processing {len(unique_chunks)} unique chunks.")
        
        # Generate embeddings for unique chunks only
        texts = [chunk['text'] for chunk in unique_chunks]
        embeddings = self.embedding_generator.generate_embeddings(texts)
        
        # Add to vector database
        self.search_engine.add_documents(unique_chunks, embeddings)
        
        logger.info("Vector database build complete!")
    
    def search_cves(self, query: str, n_results: int = 10, 
                   severity_filter: Optional[str] = None,
                   vendor_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for CVEs based on query and filters"""
        
        # Build filter dictionary
        filter_dict = {}
        if severity_filter:
            filter_dict["severity"] = severity_filter
        if vendor_filter:
            filter_dict["vendors"] = {"$contains": vendor_filter}
        
        # Perform search
        results = self.search_engine.search(query, n_results, filter_dict)
        
        return results
    
    def get_similar_cves(self, cve_id: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find CVEs similar to a given CVE"""
        # First, find the CVE document
        cve_results = self.search_engine.search(f"CVE ID: {cve_id}", n_results=1)
        
        if not cve_results:
            logger.warning(f"CVE {cve_id} not found in database")
            return []
        
        # Use the first result's text to find similar CVEs
        cve_text = cve_results[0]['text']
        similar_results = self.search_engine.search(cve_text, n_results=n_results)
        
        # Filter out the original CVE
        filtered_results = [r for r in similar_results if r['metadata']['cve_id'] != cve_id]
        
        return filtered_results[:n_results]
    
    def get_vulnerability_summary(self, query: str) -> Dict[str, Any]:
        """Get a summary of vulnerabilities matching a query"""
        results = self.search_cves(query, n_results=50)
        
        if not results:
            return {"error": "No vulnerabilities found"}
        
        # Analyze results
        severities = {}
        vendors = set()
        products = set()
        weaknesses = set()
        
        for result in results:
            metadata = result['metadata']
            
            # Count severities
            severity = metadata.get('severity', 'Unknown')
            severities[severity] = severities.get(severity, 0) + 1
            
            # Collect vendors and products (handle both string and list formats)
            vendors_data = metadata.get('vendors', '')
            if isinstance(vendors_data, str) and vendors_data:
                vendors.add(vendors_data)
            elif isinstance(vendors_data, list):
                vendors.update(vendors_data)
            
            products_data = metadata.get('products', '')
            if isinstance(products_data, str) and products_data:
                products.add(products_data)
            elif isinstance(products_data, list):
                products.update(products_data)
            
            weaknesses_data = metadata.get('weaknesses', '')
            if isinstance(weaknesses_data, str) and weaknesses_data:
                weaknesses.add(weaknesses_data)
            elif isinstance(weaknesses_data, list):
                weaknesses.update(weaknesses_data)
        
        return {
            "query": query,
            "total_results": len(results),
            "severity_distribution": severities,
            "top_vendors": list(vendors)[:10],
            "top_products": list(products)[:10],
            "common_weaknesses": list(weaknesses)[:10],
            "sample_results": results[:5]
        }

    def search_cves_by_year(self, query: str, years: List[str] = None, n_results: int = 10, vendor_terms: list = None, product_terms: list = None) -> List[Dict[str, Any]]:
        """Search for CVEs across specific years with better performance and flexible vendor/product matching"""
        import re
        if years is None or not years:
            years = ['2021', '2022', '2023', '2024']
        logger.info(f"Searching for '{query}' across years: {years}")
        all_results = []
        query_lower = query.lower()
        vendor_terms = vendor_terms or []
        product_terms = product_terms or []
        for year in years:
            try:
                year_data_path = CVE_YEAR_PATHS.get(year)
                if not year_data_path or not os.path.exists(year_data_path):
                    logger.warning(f"Year {year} data not found: {year_data_path}")
                    continue
                logger.info(f"Searching year {year}...")
                with open(year_data_path, 'r', encoding='utf-8') as f:
                    year_docs = json.load(f)
                year_results = []
                for doc in year_docs:
                    content = doc.get('content', '').lower()
                    # Flexible vendor/product matching
                    vendor_match = False
                    product_match = False
                    doc_vendors = doc.get('metadata', {}).get('vendors', []) or doc.get('vendors', [])
                    doc_products = doc.get('metadata', {}).get('products', []) or doc.get('affected_products', [])
                    # Normalize to list
                    if isinstance(doc_vendors, str):
                        doc_vendors = [doc_vendors]
                    if isinstance(doc_products, str):
                        doc_products = [doc_products]
                    # Vendor match
                    for vterm in vendor_terms:
                        for v in doc_vendors:
                            if vterm.lower() in v.lower():
                                vendor_match = True
                                break
                        if vendor_match:
                            break
                    # Product match
                    for pterm in product_terms:
                        for p in doc_products:
                            if pterm.lower() in p.lower():
                                product_match = True
                                break
                        if product_match:
                            break
                    # If vendor/product terms are provided, require at least one match
                    if (vendor_terms or product_terms):
                        if not (vendor_match or product_match):
                            continue
                    # Otherwise, fallback to content search
                    if not (vendor_terms or product_terms):
                        if query_lower not in content:
                            continue
                    score = content.count(query_lower) / max(1, len(content))
                    year_results.append({
                        'id': doc.get('id'),
                        'text': doc.get('content', '')[:1000],
                        'metadata': {
                            'cve_id': doc.get('id'),
                            'year': year,
                            'source': doc.get('source'),
                            'severity': doc.get('cvss_v3', {}).get('base_severity', 'Unknown'),
                            'cvss_score': doc.get('cvss_v3', {}).get('base_score'),
                            'affected_products': doc.get('affected_products', []),
                            'cwe_refs': doc.get('cwe_refs', []),
                            'mitre_techniques': doc.get('mitre_techniques', []),
                            'is_in_kev': doc.get('is_in_kev', False)
                        },
                        'score': score,
                        'distance': 1 - score
                    })
                year_results.sort(key=lambda x: x['score'], reverse=True)
                all_results.extend(year_results[:n_results])
                logger.info(f"Found {len(year_results)} results in {year}")
            except Exception as e:
                logger.error(f"Error searching year {year}: {e}")
                continue
        all_results.sort(key=lambda x: x['score'], reverse=True)
        final_results = all_results[:n_results]
        logger.info(f"Total results found: {len(final_results)}")
        return final_results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Enhanced RAG System for CVE Knowledge Graph")
    parser.add_argument('--build', action='store_true', help='Build the vector database from CVE documents')
    parser.add_argument('--search', type=str, help='Search for CVEs matching the query')
    parser.add_argument('--summary', type=str, help='Get a vulnerability summary for the query')
    parser.add_argument('--n_results', type=int, default=3, help='Number of results to return for search')
    parser.add_argument('--force_rebuild', action='store_true', help='Force rebuild of vector database')
    args = parser.parse_args()

    rag_system = CVERAGSystem()

    if args.build:
        rag_system.build_vector_database(force_rebuild=args.force_rebuild)
    elif args.search:
        results = rag_system.search_cves(args.search, n_results=args.n_results)
        for i, result in enumerate(results, 1):
            metadata = result['metadata']
            print(f"{i}. {metadata['cve_id']} ({metadata.get('severity', 'Unknown')})")
            
            # Format products for better readability
            products = metadata.get('products', '')
            if products:
                # Take first 5 products and show count if more
                product_list = products.split(', ')
                if len(product_list) > 5:
                    display_products = ', '.join(product_list[:5]) + f" (+{len(product_list)-5} more)"
                else:
                    display_products = products
                print(f"   Products: {display_products}")
            else:
                print(f"   Products: None")
            
            print(f"   Vendors: {metadata.get('vendors', 'None')}")
            print(f"   CWE: {metadata.get('weaknesses', metadata.get('cwe_refs', 'None'))}")
            print(f"   CAPEC: {metadata.get('attack_patterns', metadata.get('capec_entries', 'None'))}")
            print(f"   MITRE: {metadata.get('mitre_techniques', 'None')}")
            print(f"   Score: {result['score']:.4f}\n")
    elif args.summary:
        summary = rag_system.get_vulnerability_summary(args.summary)
        print(f"Vulnerability Summary for '{args.summary}':")
        print(f"  Total results: {summary['total_results']}")
        print(f"  Severity distribution: {summary['severity_distribution']}")
        print(f"  Top vendors: {summary['top_vendors']}")
        print(f"  Top products: {summary['top_products']}")
        print(f"  Common weaknesses: {summary['common_weaknesses']}")
    else:
        parser.print_help() 
