"""
Gradio UI for the CVE RAG System
"""

import gradio as gr
import asyncio
import aiohttp
import json
import logging
from typing import Tuple, List, Dict, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RAGInterface:
    """Gradio interface for the RAG system"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = None
        
    async def _get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def query_api(self, query: str, use_large_model: bool, max_results: int) -> Tuple[str, List[Dict]]:
        """Query the RAG API"""
        try:
            session = await self._get_session()
            
            payload = {
                "query": query,
                "top_k": max_results,
                "max_context_docs": 5,
                "use_large_model": use_large_model
            }
            
            async with session.post(f"{self.api_url}/api/v1/query", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['response'], data['search_results']
                else:
                    error_text = await response.text()
                    return f"Error: {response.status} - {error_text}", []
                    
        except Exception as e:
            logger.error(f"Error querying API: {e}")
            return f"Error: {str(e)}", []
    
    async def search_api(self, query: str, max_results: int) -> List[Dict]:
        """Search the API without LLM generation"""
        try:
            session = await self._get_session()
            
            payload = {
                "query": query,
                "top_k": max_results
            }
            
            async with session.post(f"{self.api_url}/api/v1/search", json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    logger.error(f"Search API error: {response.status} - {error_text}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error in search API: {e}")
            return []
    
    async def summary_api(self, query: str, max_results: int) -> Dict:
        """Get summary from API"""
        try:
            session = await self._get_session()
            
            payload = {
                "query": query,
                "max_results": max_results
            }
            
            async with session.post(f"{self.api_url}/api/v1/summary", json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    logger.error(f"Summary API error: {response.status} - {error_text}")
                    return {"error": f"API Error: {response.status}"}
                    
        except Exception as e:
            logger.error(f"Error in summary API: {e}")
            return {"error": str(e)}
    
    async def health_check(self) -> Dict:
        """Check API health"""
        try:
            session = await self._get_session()
            
            async with session.get(f"{self.api_url}/api/v1/health") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return {"status": "unhealthy", "error": f"HTTP {response.status}"}
                    
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def format_search_results(self, results: List[Dict]) -> str:
        """Format search results for display"""
        if not results:
            return "No results found."
        
        formatted = []
        for i, result in enumerate(results, 1):
            metadata = result.get('metadata', {})
            cve_id = metadata.get('cve_id', 'Unknown')
            severity = metadata.get('severity', 'Unknown')
            score = result.get('score', 0)
            # Try all possible keys for products, vendors, cwe
            products = metadata.get('products') or metadata.get('affected_products') or 'N/A'
            vendors = metadata.get('vendors') or 'N/A'
            cwe = metadata.get('cwe_refs') or metadata.get('weaknesses') or 'N/A'
            
            formatted.append(f"**{i}. {cve_id}** ({severity}) - Score: {score:.3f}")
            formatted.append(f"   Products: {products}")
            formatted.append(f"   Vendors: {vendors}")
            formatted.append(f"   CWE: {cwe}")
            formatted.append("")
        
        return "\n".join(formatted)
    
    def format_summary(self, summary: Dict) -> str:
        """Format summary for display"""
        if "error" in summary:
            return f"Error: {summary['error']}"
        
        formatted = []
        formatted.append(f"**Summary for: {summary['query']}**")
        formatted.append(f"Total results: {summary['total_results']}")
        formatted.append("")
        
        # Severity distribution
        formatted.append("**Severity Distribution:**")
        for severity, count in summary['severity_distribution'].items():
            formatted.append(f"  {severity}: {count}")
        formatted.append("")
        
        # Top vendors
        if summary['top_vendors']:
            formatted.append("**Top Vendors:**")
            for vendor in summary['top_vendors'][:5]:
                formatted.append(f"  • {vendor}")
            formatted.append("")
        
        # Top products
        if summary['top_products']:
            formatted.append("**Top Products:**")
            for product in summary['top_products'][:5]:
                formatted.append(f"  • {product}")
            formatted.append("")
        
        # Common weaknesses
        if summary['common_weaknesses']:
            formatted.append("**Common Weaknesses:**")
            for weakness in summary['common_weaknesses'][:5]:
                formatted.append(f"  • {weakness}")
        
        return "\n".join(formatted)
    
    def create_interface(self):
        """Create the Gradio interface"""
        with gr.Blocks(title="CVE RAG System", theme=gr.themes.Soft()) as interface:
            gr.Markdown("# 🔍 CVE RAG System")
            gr.Markdown("Retrieval-Augmented Generation for Cybersecurity Vulnerability Analysis")
            
            # Health status
            with gr.Row():
                status_box = gr.Textbox(label="System Status", interactive=False)
                refresh_btn = gr.Button("🔄 Refresh Status", size="sm")
            
            # Main query interface
            with gr.Tab("🔍 Query"):
                with gr.Row():
                    with gr.Column(scale=1):
                        query_input = gr.Textbox(
                            label="Query",
                            placeholder="e.g., Tell me about CVE-2024-12345 or What are the latest Microsoft vulnerabilities?",
                            lines=3
                        )
                        
                        with gr.Row():
                            model_choice = gr.Radio(
                                ["Fast (8B)", "Accurate (70B)"],
                                label="Model",
                                value="Fast (8B)"
                            )
                            max_results = gr.Slider(
                                minimum=5,
                                maximum=20,
                                value=10,
                                step=5,
                                label="Max Results"
                            )
                        
                        submit_btn = gr.Button("🔍 Search", variant="primary")
                    
                    with gr.Column(scale=2):
                        response_output = gr.Markdown(label="Response")
                        sources_output = gr.JSON(label="Sources")
                
                # Example queries
                gr.Examples(
                    examples=[
                        "What is CVE-2021-44228 (Log4Shell)?",
                        "Show me recent Microsoft Exchange vulnerabilities",
                        "Find vulnerabilities similar to CVE-2021-44228",
                        "What are the most critical web application vulnerabilities from 2024?",
                        "Explain SQL injection attacks and related CVEs",
                        "Summarize all 5G related vulnerabilities",
                        "What are the latest Apache vulnerabilities?",
                        "Find critical vulnerabilities affecting industrial control systems",
                        "Show me vulnerabilities in OpenSSL",
                        "What are the most exploited vulnerabilities in 2024?"
                    ],
                    inputs=query_input
                )
            
            # Search only tab
            with gr.Tab("📋 Search Only"):
                with gr.Row():
                    search_input = gr.Textbox(
                        label="Search Query",
                        placeholder="e.g., SQL injection vulnerabilities",
                        lines=2
                    )
                    search_results_count = gr.Slider(
                        minimum=5,
                        maximum=50,
                        value=10,
                        step=5,
                        label="Results Count"
                    )
                
                search_btn = gr.Button("🔍 Search", variant="secondary")
                search_output = gr.Markdown(label="Search Results")
            
            # Summary tab
            with gr.Tab("📊 Summary"):
                with gr.Row():
                    summary_input = gr.Textbox(
                        label="Summary Query",
                        placeholder="e.g., Microsoft vulnerabilities",
                        lines=2
                    )
                    summary_results_count = gr.Slider(
                        minimum=10,
                        maximum=100,
                        value=50,
                        step=10,
                        label="Analysis Count"
                    )
                
                summary_btn = gr.Button("📊 Generate Summary", variant="secondary")
                summary_output = gr.Markdown(label="Summary")
            
            # Similar CVEs tab
            with gr.Tab("🔗 Similar CVEs"):
                with gr.Row():
                    cve_input = gr.Textbox(
                        label="CVE ID",
                        placeholder="e.g., CVE-2024-12345",
                        lines=1
                    )
                    similar_count = gr.Slider(
                        minimum=3,
                        maximum=10,
                        value=5,
                        step=1,
                        label="Similar Count"
                    )
                
                similar_btn = gr.Button("🔗 Find Similar", variant="secondary")
                similar_output = gr.Markdown(label="Similar CVEs")
            
            # Event handlers
            async def process_query(query, model_choice, max_results):
                use_large_model = "70B" in model_choice
                response, sources = await self.query_api(query, use_large_model, max_results)
                return response, sources
            
            async def process_search(query, max_results):
                results = await self.search_api(query, max_results)
                return self.format_search_results(results)
            
            async def process_summary(query, max_results):
                summary = await self.summary_api(query, max_results)
                return self.format_summary(summary)
            
            async def process_similar(cve_id, count):
                results = await self.search_api(f"similar to {cve_id}", count)
                return self.format_search_results(results)
            
            async def check_health():
                health = await self.health_check()
                if health.get('status') == 'healthy':
                    status_text = f"✅ System Healthy | GPU: {health.get('gpu_name', 'N/A')} | Documents: {health.get('vector_db_documents', 0)}"
                else:
                    status_text = f"❌ System Unhealthy | Error: {health.get('error', 'Unknown')}"
                return status_text
            
            # Wire up the interface
            submit_btn.click(
                fn=process_query,
                inputs=[query_input, model_choice, max_results],
                outputs=[response_output, sources_output]
            )
            
            search_btn.click(
                fn=process_search,
                inputs=[search_input, search_results_count],
                outputs=[search_output]
            )
            
            summary_btn.click(
                fn=process_summary,
                inputs=[summary_input, summary_results_count],
                outputs=[summary_output]
            )
            
            similar_btn.click(
                fn=process_similar,
                inputs=[cve_input, similar_count],
                outputs=[similar_output]
            )
            
            refresh_btn.click(
                fn=check_health,
                outputs=[status_box]
            )
            
            # Initial health check
            interface.load(check_health, outputs=[status_box])
        
        return interface

def main():
    """Main function to launch the Gradio interface"""
    interface = RAGInterface()
    app = interface.create_interface()
    
    print("🚀 Starting CVE RAG System UI...")
    print("📊 API: http://localhost:8000")
    print("🌐 UI: http://localhost:7860")
    print("📚 Docs: http://localhost:8000/docs")
    
    app.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        show_error=True
    )

if __name__ == "__main__":
    main() 