"""
LLM client for the RAG system - Supports both Ollama and direct Hugging Face models
"""

import aiohttp
import json
import logging
from typing import AsyncGenerator, Dict, Any, Optional
import asyncio
from src.generators.rag_config import (
    OLLAMA_HOST, OLLAMA_MODEL_PRIMARY, OLLAMA_MODEL_FAST,
    HF_TOKEN, HF_MODEL_PRIMARY, HF_MODEL_FAST
)

logger = logging.getLogger(__name__)

class LLMClient:
    """Client for interacting with LLM services (Ollama or Hugging Face)"""
    
    def __init__(self, use_ollama: bool = True, host: str = OLLAMA_HOST):
        self.use_ollama = use_ollama
        self.host = host
        
        if use_ollama:
            self.primary_model = OLLAMA_MODEL_PRIMARY
            self.fast_model = OLLAMA_MODEL_FAST
            logger.info(f"Initialized Ollama client with host: {host}")
            logger.info(f"Primary model: {self.primary_model}")
            logger.info(f"Fast model: {self.fast_model}")
        else:
            self.primary_model = HF_MODEL_PRIMARY
            self.fast_model = HF_MODEL_FAST
            logger.info("Initialized Hugging Face client")
            logger.info(f"Primary model: {self.primary_model}")
            logger.info(f"Fast model: {self.fast_model}")
            if HF_TOKEN:
                logger.info("✅ Hugging Face token loaded")
            else:
                logger.warning("⚠️ No Hugging Face token found")
    
    async def check_models(self) -> Dict[str, bool]:
        """Check if required models are available"""
        if self.use_ollama:
            return await self._check_ollama_models()
        else:
            return await self._check_hf_models()
    
    async def _check_ollama_models(self) -> Dict[str, bool]:
        """Check if Ollama models are available"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.host}/api/tags") as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model['name'] for model in data.get('models', [])]
                        
                        return {
                            'primary': self.primary_model in models,
                            'fast': self.fast_model in models,
                            'available_models': models
                        }
                    else:
                        logger.error(f"Failed to check Ollama models: {response.status}")
                        return {'primary': False, 'fast': False, 'available_models': []}
        except Exception as e:
            logger.error(f"Error checking Ollama models: {e}")
            return {'primary': False, 'fast': False, 'available_models': []}
    
    async def _check_hf_models(self) -> Dict[str, bool]:
        """Check if Hugging Face models are accessible"""
        try:
            headers = {"Authorization": f"Bearer {HF_TOKEN}"} if HF_TOKEN else {}
            
            async with aiohttp.ClientSession() as session:
                # Check primary model
                primary_url = f"https://huggingface.co/api/models/{self.primary_model}"
                async with session.get(primary_url, headers=headers) as response:
                    primary_available = response.status == 200
                
                # Check fast model
                fast_url = f"https://huggingface.co/api/models/{self.fast_model}"
                async with session.get(fast_url, headers=headers) as response:
                    fast_available = response.status == 200
                
                return {
                    'primary': primary_available,
                    'fast': fast_available,
                    'available_models': [self.primary_model, self.fast_model] if primary_available and fast_available else []
                }
        except Exception as e:
            logger.error(f"Error checking Hugging Face models: {e}")
            return {'primary': False, 'fast': False, 'available_models': []}
    
    async def generate(self, prompt: str, model_type: str = 'fast') -> AsyncGenerator[str, None]:
        """Generate text using LLM service"""
        if self.use_ollama:
            async for chunk in self._generate_ollama(prompt, model_type):
                yield chunk
        else:
            async for chunk in self._generate_hf(prompt, model_type):
                yield chunk
    
    async def _generate_ollama(self, prompt: str, model_type: str = 'fast') -> AsyncGenerator[str, None]:
        """Generate text using Ollama with timeout"""
        model = self.primary_model if model_type == 'primary' else self.fast_model
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2048
            }
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)  # 30 second timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        chunk_count = 0
                        max_chunks = 1000  # Prevent infinite loops
                        
                        async for line in response.content:
                            if chunk_count >= max_chunks:
                                logger.warning("Reached maximum chunk limit, stopping generation")
                                break
                                
                            if line:
                                try:
                                    data = json.loads(line.decode('utf-8'))
                                    if 'response' in data:
                                        yield data['response']
                                        chunk_count += 1
                                    if data.get('done', False):
                                        break
                                except json.JSONDecodeError:
                                    continue
                    else:
                        error_text = await response.text()
                        logger.error(f"Ollama API error: {response.status} - {error_text}")
                        yield f"Error: Failed to generate response (Status: {response.status})"
                        
        except asyncio.TimeoutError:
            logger.error("Ollama generation timeout")
            yield "Error: Generation timed out. Please try a shorter query."
        except Exception as e:
            logger.error(f"Error generating text with Ollama: {e}")
            yield f"Error: {str(e)}"
    
    async def _generate_hf(self, prompt: str, model_type: str = 'fast') -> AsyncGenerator[str, None]:
        """Generate text using Hugging Face Inference API with timeout"""
        model = self.primary_model if model_type == 'primary' else self.fast_model
        
        # Format prompt for Llama
        formatted_prompt = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\nYou are a helpful cybersecurity expert assistant. Answer questions about vulnerabilities and security issues based on the provided context.<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
        
        payload = {
            "inputs": formatted_prompt,
            "parameters": {
                "max_new_tokens": 2048,
                "temperature": 0.7,
                "top_p": 0.9,
                "do_sample": True,
                "return_full_text": False
            },
            "stream": True
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {HF_TOKEN}"
        } if HF_TOKEN else {"Content-Type": "application/json"}
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)  # 30 second timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"https://api-inference.huggingface.co/models/{model}",
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        chunk_count = 0
                        max_chunks = 1000  # Prevent infinite loops
                        
                        async for line in response.content:
                            if chunk_count >= max_chunks:
                                logger.warning("Reached maximum chunk limit, stopping generation")
                                break
                                
                            if line:
                                try:
                                    data = json.loads(line.decode('utf-8'))
                                    if 'token' in data:
                                        yield data['token']['text']
                                        chunk_count += 1
                                    if data.get('generated_text'):
                                        break
                                except json.JSONDecodeError:
                                    continue
                    else:
                        error_text = await response.text()
                        logger.error(f"Hugging Face API error: {response.status} - {error_text}")
                        yield f"Error: Failed to generate response (Status: {response.status})"
                        
        except asyncio.TimeoutError:
            logger.error("Hugging Face generation timeout")
            yield "Error: Generation timed out. Please try a shorter query."
        except Exception as e:
            logger.error(f"Error generating text with Hugging Face: {e}")
            yield f"Error: {str(e)}"
    
    async def generate_sync(self, prompt: str, model_type: str = 'fast') -> str:
        """Generate text synchronously (for testing)"""
        response_text = ""
        async for chunk in self.generate(prompt, model_type):
            response_text += chunk
        return response_text
    
    async def health_check(self) -> Dict[str, Any]:
        """Check LLM service health"""
        if self.use_ollama:
            return await self._health_check_ollama()
        else:
            return await self._health_check_hf()
    
    async def _health_check_ollama(self) -> Dict[str, Any]:
        """Check Ollama service health"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.host}/api/tags") as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "status": "healthy",
                            "service": "ollama",
                            "models_available": len(data.get('models', [])),
                            "models": [model['name'] for model in data.get('models', [])]
                        }
                    else:
                        return {
                            "status": "unhealthy",
                            "service": "ollama",
                            "error": f"HTTP {response.status}"
                        }
        except Exception as e:
            return {
                "status": "unhealthy",
                "service": "ollama",
                "error": str(e)
            }
    
    async def _health_check_hf(self) -> Dict[str, Any]:
        """Check Hugging Face service health"""
        try:
            headers = {"Authorization": f"Bearer {HF_TOKEN}"} if HF_TOKEN else {}
            
            async with aiohttp.ClientSession() as session:
                # Test with a simple model check
                test_url = f"https://huggingface.co/api/models/{self.fast_model}"
                async with session.get(test_url, headers=headers) as response:
                    if response.status == 200:
                        return {
                            "status": "healthy",
                            "service": "huggingface",
                            "token_available": bool(HF_TOKEN),
                            "models_available": 2 if HF_TOKEN else 0
                        }
                    else:
                        return {
                            "status": "unhealthy",
                            "service": "huggingface",
                            "error": f"HTTP {response.status}"
                        }
        except Exception as e:
            return {
                "status": "unhealthy",
                "service": "huggingface",
                "error": str(e)
            }

# Backward compatibility - alias for OllamaClient
OllamaClient = LLMClient 