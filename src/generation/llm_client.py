# src/generation/llm_client_fixed.py

import json
import logging
import requests
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Configuration for LLM client"""
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1:8b-instruct-fp16"  # Fixed: Match your actual model
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 30  # Reduced timeout
    stream: bool = False


class LLMClient:
    """Fixed LLM client for local Ollama integration"""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()

        # Test connection and auto-detect model
        self.available = self._test_connection_and_detect_model()
        if not self.available:
            logger.warning("LLM service not available, running in search-only mode")

    def _test_connection_and_detect_model(self) -> bool:
        """Test connection and auto-detect correct model name"""
        try:
            response = requests.get(
                f"{self.config.base_url}/api/tags",
                timeout=5
            )

            if response.status_code == 200:
                models_data = response.json()
                available_models = [m.get('name', '') for m in models_data.get('models', [])]
                logger.info(f"Available Ollama models: {available_models}")

                # Try to find the correct model
                if self.config.model in available_models:
                    logger.info(f"✅ Using specified model: {self.config.model}")
                    return True

                # Auto-detect Llama 3 models
                llama3_models = [name for name in available_models if 'llama3' in name.lower()]
                if llama3_models:
                    self.config.model = llama3_models[0]
                    logger.info(f"✅ Auto-detected model: {self.config.model}")
                    return True
                else:
                    logger.error("❌ No Llama 3 models found")
                    logger.info("Available models: " + ", ".join(available_models))
                    return False
            else:
                logger.error(f"Ollama API returned {response.status_code}")
                return False

        except Exception as e:
            logger.warning(f"Ollama connection test failed: {e}")
            return False

    def generate_response(
            self,
            query: str,
            context: List[Dict[str, Any]],
            query_type: str = "general"
    ) -> str:
        """Generate response using LLM with context"""

        if not self.available:
            return self._generate_fallback_response(query, context)

        try:
            # Format context for LLM
            context_text = self._format_context(context)

            # Create prompt based on query type
            if query_type == "cve_analysis":
                prompt = f"""You are a cybersecurity expert analyzing CVE vulnerabilities.

Context Information:
{context_text}

User Question: {query}

Provide a comprehensive analysis including:
1. Summary of the vulnerability
2. Technical details and affected systems  
3. Risk assessment and CVSS score interpretation
4. Remediation steps and patches

Keep response concise but informative."""
            else:
                prompt = f"""You are a cybersecurity assistant helping with vulnerability research.

Search Results:
{context_text}

User Query: {query}

Based on the search results above, provide a helpful response that:
1. Directly answers the user's question
2. Synthesizes information from multiple sources
3. Highlights the most relevant findings

Keep the response concise but informative."""

            # Call Ollama API
            response = self._call_ollama(prompt)
            return response

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._generate_fallback_response(query, context)

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API with proper error handling"""
        try:
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens
                }
            }

            logger.info(f"Calling Ollama with model: {self.config.model}")

            response = requests.post(
                f"{self.config.base_url}/api/generate",
                json=payload,
                timeout=self.config.timeout
            )

            logger.info(f"Ollama response status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                generated_text = result.get('response', '').strip()
                if generated_text:
                    return generated_text
                else:
                    return "No response generated by LLM"
            elif response.status_code == 404:
                available_models = self._get_available_models()
                return f"Model '{self.config.model}' not found. Available models: {', '.join(available_models)}"
            else:
                return f"Ollama API error: {response.status_code} - {response.text}"

        except requests.exceptions.Timeout:
            return "LLM request timed out - try a shorter query"
        except Exception as e:
            return f"Error calling LLM service: {str(e)}"

    def _get_available_models(self) -> List[str]:
        """Get list of available models"""
        try:
            response = requests.get(f"{self.config.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models_data = response.json()
                return [m.get('name', '') for m in models_data.get('models', [])]
        except:
            pass
        return []

    def _format_context(self, context: List[Dict[str, Any]]) -> str:
        """Format search results into context for LLM"""
        if not context:
            return "No relevant context found."

        formatted_parts = []
        for i, item in enumerate(context[:3], 1):  # Limit to top 3 for better performance
            text = item.get('text', item.get('content', ''))
            metadata = item.get('metadata', {})

            cve_id = metadata.get('cve_id', 'Unknown')
            severity = metadata.get('severity', 'Unknown')
            score = item.get('score', 0.0)

            # Keep context concise
            formatted_parts.append(
                f"[Result {i}] CVE: {cve_id} | Severity: {severity} | Score: {score:.3f}\n"
                f"{text[:500]}{'...' if len(text) > 500 else ''}\n"
            )

        return "\n".join(formatted_parts)

    def _generate_fallback_response(self, query: str, context: List[Dict]) -> str:
        """Generate structured response when LLM is not available"""
        if not context:
            return f"No relevant information found for query: {query}"

        # Extract key information
        cve_ids = []
        severities = []

        for item in context[:3]:
            metadata = item.get('metadata', {})
            cve_ids.append(metadata.get('cve_id', 'Unknown'))
            severities.append(metadata.get('severity', 'Unknown'))

        # Generate structured summary
        summary_parts = [
            f"Search Results for: {query}",
            f"Found {len(context)} relevant vulnerabilities",
            f"Top CVEs: {', '.join(cve_ids)}",
            f"Severity levels: {', '.join(set(severities))}",
            "\nFor detailed analysis, refer to the search results below."
        ]

        return "\n".join(summary_parts)

    def expand_query(self, query: str, technologies: List[str] = None) -> List[str]:
        """Simple query expansion"""
        expanded = [query]

        # Basic expansions for common terms
        expansions = {
            'rce': 'remote code execution',
            'xss': 'cross-site scripting',
            'sqli': 'sql injection',
            'lfi': 'local file inclusion',
            'rfi': 'remote file inclusion'
        }

        query_lower = query.lower()
        for term, expansion in expansions.items():
            if term in query_lower and expansion not in query_lower:
                expanded.append(f"{query} {expansion}")
                break  # Only add one expansion

        return expanded[:2]  # Limit to original + 1 expansion

    def rerank_results(self, query: str, results: List[Dict], top_k: int = 10) -> List[Dict]:
        """Simple reranking based on keyword overlap"""
        if not results or len(results) <= top_k:
            return results

        try:
            query_words = set(query.lower().split())

            for result in results:
                text = result.get('text', '').lower()
                text_words = set(text.split())

                # Calculate keyword overlap score
                overlap = len(query_words.intersection(text_words))
                keyword_score = overlap / len(query_words) if query_words else 0

                # Combine with original score
                original_score = result.get('score', 0.0)
                result['combined_score'] = original_score * 0.7 + keyword_score * 0.3

            # Sort by combined score
            results.sort(key=lambda x: x.get('combined_score', 0), reverse=True)
            return results[:top_k]

        except Exception as e:
            logger.warning(f"Reranking failed: {e}")
            return results[:top_k]


# Technology Detection (separate from main LLM client)
class TechnologyDetector:
    """Detect technologies and suggest relevant time periods"""

    TECHNOLOGY_PATTERNS = {
        'log4j': {'years': [2021, 2022, 2023], 'priority': 5},
        'apache': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4},
        'nginx': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 3},
        'mysql': {'years': [2019, 2020, 2021, 2022, 2023], 'priority': 3},
        'java': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4},
        'spring': {'years': [2021, 2022, 2023, 2024], 'priority': 4},
        'wordpress': {'years': [2020, 2021, 2022, 2023, 2024], 'priority': 4},
    }

    @classmethod
    def detect_technologies(cls, query: str) -> Dict[str, Any]:
        """Detect technologies in query"""
        query_lower = query.lower()
        detected = []
        all_years = set()
        max_priority = 0

        for tech, info in cls.TECHNOLOGY_PATTERNS.items():
            if tech in query_lower:
                detected.append(tech)
                all_years.update(info['years'])
                max_priority = max(max_priority, info['priority'])

        return {
            'technologies': detected,
            'critical_years': sorted(list(all_years)),
            'priority_level': max_priority,
            'search_strategy': {
                'strategy': 'focused' if max_priority >= 4 else 'general',
                'result_limit': 20 if max_priority >= 4 else 10,
                'expand_query': max_priority >= 4
            }
        }


if __name__ == "__main__":
    # Simple test
    client = LLMClient()
    print(f"LLM Client available: {client.available}")
    if client.available:
        print(f"Using model: {client.config.model}")

        # Test simple generation
        test_context = [{'text': 'SQL injection vulnerability in web application',
                         'metadata': {'cve_id': 'CVE-2023-1234', 'severity': 'High'}, 'score': 0.9}]
        response = client.generate_response("What is SQL injection?", test_context)
        print(f"Test response: {response[:100]}...")