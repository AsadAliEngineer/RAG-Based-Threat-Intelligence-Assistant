#!/usr/bin/env python3
"""
RAG System for CVE Knowledge Graph

This module implements a Retrieval-Augmented Generation (RAG) system
for querying and analyzing CVE data using vector embeddings and semantic search.
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import chromadb
from chromadb.config import Settings
import numpy as np
from sentence_transformers import SentenceTransformer
import torch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CVEDocumentProcessor:
    """Process CVE documents for RAG system"""
    
    def __init__(self, chunk_size: int = 512, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
    
    def load_cve_documents(self, file_path: str) -> List[Dict[str, Any]]:
        """Load CVE documents from exported JSON file"""
        logger.info(f"Loading CVE documents from {file_path}")
        
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
                'text': f"CVE ID: {doc['id']} | Severity: {doc.get('cvss_v3_severity', 'Unknown')}",
                'metadata': {
                    'cve_id': doc['id'],
                    'chunk_index': 0,
                    'severity': doc.get('cvss_v3_severity'),
                    'cvss_score': doc.get('cvss_v3_base_score'),
                    'products': doc.get('affected_products', []),
                    'vendors': doc.get('affected_vendors', []),
                    'weaknesses': doc.get('weaknesses', []),
                    'attack_patterns': doc.get('attack_patterns', [])
                }
            })
            return chunks
        
        # Simple text chunking (can be enhanced with more sophisticated methods)
        words = text.split()
        current_chunk = []
        chunk_index = 0
        
        for word in words:
            current_chunk.append(word)
            
            if len(current_chunk) >= self.chunk_size:
                chunk_text = ' '.join(current_chunk)
                chunks.append({
                    'id': f"{doc['id']}_chunk_{chunk_index}",
                    'cve_id': doc['id'],
                    'text': chunk_text,
                    'metadata': {
                        'cve_id': doc['id'],
                        'chunk_index': chunk_index,
                        'severity': doc.get('cvss_v3_severity'),
                        'cvss_score': doc.get('cvss_v3_base_score'),
                        'products': doc.get('affected_products', []),
                        'vendors': doc.get('affected_vendors', []),
                        'weaknesses': doc.get('weaknesses', []),
                        'attack_patterns': doc.get('attack_patterns', [])
                    }
                })
                
                # Keep overlap for next chunk
                current_chunk = current_chunk[-self.chunk_overlap:] if self.chunk_overlap > 0 else []
                chunk_index += 1
        
        # Add remaining text as final chunk
        if current_chunk:
            chunk_text = ' '.join(current_chunk)
            chunks.append({
                'id': f"{doc['id']}_chunk_{chunk_index}",
                'cve_id': doc['id'],
                'text': chunk_text,
                'metadata': {
                    'cve_id': doc['id'],
                    'chunk_index': chunk_index,
                    'severity': doc.get('cvss_v3_severity'),
                    'cvss_score': doc.get('cvss_v3_base_score'),
                    'products': doc.get('affected_products', []),
                    'vendors': doc.get('affected_vendors', []),
                    'weaknesses': doc.get('weaknesses', []),
                    'attack_patterns': doc.get('attack_patterns', [])
                }
            })
        
        return chunks
    
    def process_documents(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process all CVE documents into chunks"""
        logger.info("Processing CVE documents into chunks...")
        
        all_chunks = []
        for doc in documents:
            chunks = self.chunk_document(doc)
            all_chunks.extend(chunks)
        
        logger.info(f"Created {len(all_chunks)} chunks from {len(documents)} documents")
        return all_chunks

class CVEEmbeddingGenerator:
    """Generate embeddings for CVE documents"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        logger.info(f"Initialized embedding model: {model_name}")
    
    def generate_embeddings(self, texts: List[str]) -> np.ndarray:
        """Generate embeddings for a list of texts"""
        logger.info(f"Generating embeddings for {len(texts)} texts...")
        
        embeddings = self.model.encode(texts, show_progress_bar=True)
        logger.info(f"Generated embeddings with shape: {embeddings.shape}")
        
        return embeddings

class CVESearchEngine:
    """Vector search engine for CVE data"""
    
    def __init__(self, persist_directory: str = "../../data/knowledge_graph/vector_db"):
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
        
        total = len(chunks)
        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            batch_chunks = chunks[start:end]
            batch_embeddings = embeddings[start:end]
            ids = [chunk['id'] for chunk in batch_chunks]
            texts = [chunk['text'] for chunk in batch_chunks]
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
            self.collection.add(
                ids=ids,
                embeddings=embeddings_list,
                documents=texts,
                metadatas=metadatas
            )
            logger.info(f"Added batch {start} to {end} ({end-start} documents)")
        logger.info(f"Added {total} documents to vector database in total")
    
    def search(self, query: str, n_results: int = 10, 
               filter_dict: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search for relevant CVE documents"""
        logger.info(f"Searching for: '{query}' (n_results={n_results})")
        
        # Generate query embedding
        embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        query_embedding = embedding_model.encode([query]).tolist()
        
        # Prepare query arguments
        query_args = {
            "query_embeddings": query_embedding,
            "n_results": n_results
        }
        if filter_dict:
            query_args["where"] = filter_dict
        
        # Perform search
        results = self.collection.query(**query_args)
        
        # Format results
        formatted_results = []
        if (results and results.get('ids') and results['ids'][0] and 
            results.get('documents') and results['documents'][0] and
            results.get('metadatas') and results['metadatas'][0] and
            results.get('distances') and results['distances'][0]):
            
            for i in range(len(results['ids'][0])):
                result = {
                    'id': results['ids'][0][i],
                    'text': results['documents'][0][i],
                    'metadata': results['metadatas'][0][i],
                    'distance': results['distances'][0][i]
                }
                formatted_results.append(result)
        
        logger.info(f"Found {len(formatted_results)} results")
        return formatted_results
    
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
                 vector_db_path: str = "../../data/knowledge_graph/vector_db",
                 cve_data_path: str = "../../data/knowledge_graph/exports/cve_documents_for_rag.json"):
        self.vector_db_path = vector_db_path
        self.cve_data_path = cve_data_path
        
        # Initialize components
        self.processor = CVEDocumentProcessor()
        self.embedding_generator = CVEEmbeddingGenerator()
        self.search_engine = CVESearchEngine(vector_db_path)
        
        logger.info("Initialized CVE RAG System")
    
    def build_vector_database(self, force_rebuild: bool = False):
        """Build the vector database from CVE documents"""
        logger.info("Building vector database...")
        
        # Check if database already exists and has data
        if not force_rebuild:
            stats = self.search_engine.get_collection_stats()
            if stats["total_documents"] > 0:
                logger.info(f"Vector database already exists with {stats['total_documents']} documents")
                return
        
        # Load and process documents
        documents = self.processor.load_cve_documents(self.cve_data_path)
        chunks = self.processor.process_documents(documents)
        
        # Generate embeddings
        texts = [chunk['text'] for chunk in chunks]
        embeddings = self.embedding_generator.generate_embeddings(texts)
        
        # Add to vector database
        self.search_engine.add_documents(chunks, embeddings)
        
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

def main():
    """Demo the RAG system"""
    print("🚀 CVE RAG System Demo")
    print("=" * 50)
    
    # Initialize RAG system
    rag_system = CVERAGSystem()
    
    # Build vector database (if needed)
    rag_system.build_vector_database()
    
    # Demo searches
    queries = [
        "SQL injection vulnerabilities",
        "Microsoft Windows remote code execution",
        "Cross-site scripting XSS",
        "Buffer overflow in network services"
    ]
    
    for query in queries:
        print(f"\n🔍 Searching for: '{query}'")
        results = rag_system.search_cves(query, n_results=3)
        
        for i, result in enumerate(results, 1):
            metadata = result['metadata']
            print(f"  {i}. {metadata['cve_id']} ({metadata.get('severity', 'Unknown')})")
            
            # Handle products (could be string or list)
            products = metadata.get('products', '')
            if products is None:
                products_display = ''
            elif isinstance(products, str):
                products_display = products
            elif isinstance(products, list):
                products_display = ', '.join(products[:3]) if products else ''
            else:
                products_display = str(products)
            print(f"     Products: {products_display}")
            
            # Handle vendors (could be string or list)
            vendors = metadata.get('vendors', '')
            if vendors is None:
                vendors_display = ''
            elif isinstance(vendors, str):
                vendors_display = vendors
            elif isinstance(vendors, list):
                vendors_display = ', '.join(vendors[:3]) if vendors else ''
            else:
                vendors_display = str(vendors)
            print(f"     Vendors: {vendors_display}")

            # CWE
            cwes = metadata.get('weaknesses', '')
            if cwes:
                if isinstance(cwes, str) and cwes.strip():
                    print(f"     CWE: {cwes}")
                elif isinstance(cwes, list) and cwes:
                    cwe_display = ', '.join(cwes)
                    if cwe_display.strip():
                        print(f"     CWE: {cwe_display}")

            # CAPEC
            capecs = metadata.get('attack_patterns', '')
            if capecs:
                if isinstance(capecs, str) and capecs.strip():
                    print(f"     CAPEC: {capecs}")
                elif isinstance(capecs, list) and capecs:
                    capec_display = ', '.join(capecs)
                    if capec_display.strip():
                        print(f"     CAPEC: {capec_display}")

            # MITRE ATT&CK
            mitre = metadata.get('mitre_attack', '') or metadata.get('mitre_techniques', '') or metadata.get('attack_techniques', '')
            if mitre:
                if isinstance(mitre, str) and mitre.strip():
                    print(f"     MITRE ATT&CK: {mitre}")
                elif isinstance(mitre, list) and mitre:
                    mitre_display = ', '.join(mitre)
                    if mitre_display.strip():
                        print(f"     MITRE ATT&CK: {mitre_display}")

            print(f"     Distance: {result['distance']:.4f}")
    
    # Demo vulnerability summary
    print(f"\n📊 Vulnerability Summary for 'SQL injection'")
    summary = rag_system.get_vulnerability_summary("SQL injection")
    print(f"  Total results: {summary['total_results']}")
    print(f"  Severity distribution: {summary['severity_distribution']}")
    print(f"  Top vendors: {summary['top_vendors'][:5]}")

if __name__ == "__main__":
    main() 