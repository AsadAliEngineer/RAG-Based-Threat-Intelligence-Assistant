#!/usr/bin/env python3
"""
Model Validation Script for CVE Cybersecurity LLM
Tests the trained model and generates sample responses.
"""

import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel, PeftConfig

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModelValidator:
    """Validate and test the trained CVE cybersecurity model"""
    
    def __init__(self, adapter_path: str = "models/fine_tuned_cve"):
        self.adapter_path = Path(adapter_path)
        self.tokenizer = None
        self.model = None
        
    def load_model(self):
        """Load the trained model and tokenizer"""
        logger.info(f"Loading model from {self.adapter_path}")
        
        if not self.adapter_path.exists():
            raise FileNotFoundError(f"Model path not found: {self.adapter_path}")
        
        try:
            # Load configuration
            config = PeftConfig.from_pretrained(self.adapter_path)
            logger.info(f"Base model: {config.base_model_name_or_path}")
            logger.info(f"Adapter type: {config.peft_type}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.adapter_path)
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load base model
            logger.info("Loading base model...")
            base_model = AutoModelForCausalLM.from_pretrained(
                config.base_model_name_or_path,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
            )
            
            # Load LoRA adapter
            logger.info("Loading LoRA adapter...")
            self.model = PeftModel.from_pretrained(base_model, self.adapter_path)
            
            logger.info("✅ Model loaded successfully!")
            
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            raise
    
    def format_query(self, query: str) -> str:
        """Format query for the model"""
        return f"""### Instruction:
Analyze this cybersecurity query and provide a comprehensive response.

### Input:
{query}

### Response:
"""
    
    def generate_response(self, query: str, max_length: int = 512, temperature: float = 0.3) -> str:
        """Generate response for a given query"""
        try:
            # Format query
            formatted_query = self.format_query(query)
            
            # Tokenize
            inputs = self.tokenizer(
                formatted_query,
                return_tensors="pt",
                truncation=True,
                max_length=512
            )
            
            # Move to device
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}
            
            # Generate response
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_length=max_length,
                    temperature=temperature,
                    do_sample=True,
                    top_p=0.9,
                    top_k=50,
                    pad_token_id=self.tokenizer.eos_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1,
                    no_repeat_ngram_size=3,
                )
            
            # Decode response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract only the response part
            response_text = response.split("### Response:")[-1].strip()
            
            return response_text
            
        except Exception as e:
            logger.error(f"❌ Generation failed for query '{query}': {e}")
            return f"Error generating response: {e}"
    
    def test_queries(self, queries: List[str]) -> List[Dict[str, str]]:
        """Test multiple queries and return results"""
        logger.info(f"Testing {len(queries)} queries...")
        
        results = []
        for i, query in enumerate(queries):
            logger.info(f"Query {i+1}/{len(queries)}: {query}")
            
            response = self.generate_response(query)
            
            result = {
                'query': query,
                'response': response,
                'response_length': len(response)
            }
            
            results.append(result)
            
            logger.info(f"Response length: {len(response)} chars")
            logger.info(f"Response preview: {response[:200]}...")
            logger.info("-" * 50)
        
        return results
    
    def save_results(self, results: List[Dict[str, str]], output_file: str = "validation_results.json"):
        """Save validation results to file"""
        output_path = self.adapter_path / output_file
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Validation results saved to {output_path}")
    
    def analyze_results(self, results: List[Dict[str, str]]):
        """Analyze validation results"""
        logger.info("📊 Analyzing validation results...")
        
        total_queries = len(results)
        successful_responses = sum(1 for r in results if not r['response'].startswith("Error"))
        avg_response_length = sum(r['response_length'] for r in results) / total_queries
        
        logger.info(f"  - Total queries: {total_queries}")
        logger.info(f"  - Successful responses: {successful_responses}/{total_queries}")
        logger.info(f"  - Success rate: {successful_responses/total_queries*100:.1f}%")
        logger.info(f"  - Average response length: {avg_response_length:.1f} characters")
        
        # Check for cybersecurity-specific content
        cybersecurity_keywords = [
            'cve', 'vulnerability', 'security', 'attack', 'exploit', 'mitigation',
            'buffer overflow', 'sql injection', 'xss', 'authentication', 'authorization'
        ]
        
        keyword_counts = {}
        for keyword in cybersecurity_keywords:
            count = sum(1 for r in results if keyword.lower() in r['response'].lower())
            keyword_counts[keyword] = count
        
        logger.info("  - Cybersecurity keyword frequency:")
        for keyword, count in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                logger.info(f"    * {keyword}: {count}/{total_queries} responses")

def main():
    """Main function to run model validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE LLM Model Validation")
    parser.add_argument("--model_path", default="models/fine_tuned_cve", 
                       help="Path to trained model")
    parser.add_argument("--output", default="validation_results.json",
                       help="Output file for results")
    
    args = parser.parse_args()
    
    # Test queries
    test_queries = [
        "Analyze the CVE-2021-44228 Log4j vulnerability",
        "What are the most critical vulnerabilities in Apache products?",
        "Explain the impact of SQL injection vulnerabilities",
        "How can I remediate buffer overflow vulnerabilities?",
        "What are the common attack patterns for web applications?",
        "Describe the MITRE ATT&CK framework and its relevance to CVE analysis",
        "What is the difference between CVE and CWE?",
        "How do I assess the severity of a vulnerability?",
        "What are the best practices for vulnerability management?",
        "Explain the concept of zero-day vulnerabilities"
    ]
    
    try:
        # Initialize validator
        validator = ModelValidator(args.model_path)
        
        # Load model
        validator.load_model()
        
        # Test queries
        results = validator.test_queries(test_queries)
        
        # Save results
        validator.save_results(results, args.output)
        
        # Analyze results
        validator.analyze_results(results)
        
        logger.info("✅ Model validation completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Model validation failed: {e}")
        raise

if __name__ == "__main__":
    main() 