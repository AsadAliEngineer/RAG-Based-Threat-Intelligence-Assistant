#!/usr/bin/env python3
"""
Hugging Face Inference Engine for CVE Cybersecurity LLM
Uses Llama 3.1 8B model for CVE analysis and security recommendations.
Supports both base model and fine-tuned models.
"""

import json
import logging
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config

# Import transformers
try:
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel, PeftConfig
    import torch
    from torch.nn import functional as F
    from huggingface_hub import login
except ImportError as e:
    print(f"Error importing transformers: {e}")
    print("Please install: pip install transformers torch accelerate peft")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HFCVEInferenceEngine:
    """Hugging Face inference engine for CVE cybersecurity analysis"""
    
    def __init__(self, model_name: str = "meta-llama/Meta-Llama-3-8B", use_fine_tuned: bool = False, fine_tuned_path: str = "models/fine_tuned_cve_production"):
        self.config = Config()
        self.model_name = model_name
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.use_fine_tuned = use_fine_tuned
        self.fine_tuned_path = Path(fine_tuned_path)
        
        # Load and authenticate with token
        self.token = self._load_token()
        self._authenticate()
        
        # Initialize model and tokenizer
        self.tokenizer = None
        self.model = None
        
        # System prompts for different analysis types
        self.system_prompts = {
            'vulnerability_analysis': """You are a cybersecurity expert. Analyze the CVE and provide:
- Severity assessment (Critical/High/Medium/Low)
- Key technical details
- Impact analysis
- Brief remediation steps

Keep responses concise and actionable.""",
            
            'remediation': """You are a cybersecurity specialist. Provide specific remediation steps:
- Immediate actions
- Patch information
- Workarounds
- Verification steps

Focus on practical solutions.""",
            
            'technical_analysis': """You are a technical security analyst. Provide:
- Root cause analysis
- Attack mechanism
- Technical impact
- Detection recommendations

Use technical depth for security professionals.""",
            
            'product_analysis': """You are a product security analyst. Analyze:
- Vulnerability trends
- Risk assessment
- Security recommendations
- Vendor practices

Provide actionable insights."""
        }
        
        logger.info(f"Initializing HF inference engine on {self.device}")
        if self.use_fine_tuned:
            logger.info(f"Using fine-tuned model from: {self.fine_tuned_path}")
        else:
            logger.info(f"Using base model: {self.model_name}")
        
        self._load_model()
    
    def _load_token(self) -> str:
        """Load Hugging Face token from file"""
        token_file = Path("llama_token.txt")
        if token_file.exists():
            with open(token_file, 'r') as f:
                token = f.read().strip()
            logger.info("✅ Hugging Face token loaded")
            return token
        else:
            raise FileNotFoundError("llama_token.txt not found. Please create this file with your Hugging Face token.")
    
    def _authenticate(self):
        """Authenticate with Hugging Face"""
        try:
            # Set environment variable for token
            os.environ["HF_TOKEN"] = self.token
            login(token=self.token)
            logger.info("✅ Successfully authenticated with Hugging Face")
        except Exception as e:
            logger.error(f"❌ Authentication failed: {e}")
            raise
    
    def _load_model(self):
        """Load the model and tokenizer"""
        try:
            if self.use_fine_tuned:
                self._load_fine_tuned_model()
            else:
                self._load_base_model()
                
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def _load_fine_tuned_model(self):
        """Load fine-tuned model with LoRA adapter"""
        if not self.fine_tuned_path.exists():
            logger.error(f"Fine-tuned model not found at {self.fine_tuned_path}")
            logger.info("Falling back to base model...")
            self.use_fine_tuned = False
            self._load_base_model()
            return
        
        logger.info(f"Loading fine-tuned model from {self.fine_tuned_path}")
        
        try:
            # Load LoRA configuration
            config = PeftConfig.from_pretrained(self.fine_tuned_path)
            logger.info(f"Base model: {config.base_model_name_or_path}")
            logger.info(f"Adapter type: {config.peft_type}")
            
            # Load tokenizer from fine-tuned model
            logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.fine_tuned_path)
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load base model
            logger.info("Loading base model...")
            base_model = AutoModelForCausalLM.from_pretrained(
                config.base_model_name_or_path,
                token=self.token,
                torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
                device_map="auto" if self.device == "cuda" else None,
                trust_remote_code=True
            )
            
            # Load LoRA adapter
            logger.info("Loading LoRA adapter...")
            self.model = PeftModel.from_pretrained(base_model, self.fine_tuned_path)
            
            if self.device == "cpu":
                self.model = self.model.to(self.device)
            
            logger.info("✅ Fine-tuned model loaded successfully!")
            
        except Exception as e:
            logger.error(f"Failed to load fine-tuned model: {e}")
            logger.info("Falling back to base model...")
            self.use_fine_tuned = False
            self._load_base_model()
    
    def _load_base_model(self):
        """Load base model"""
        logger.info(f"Loading tokenizer for {self.model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            token=self.token,
            trust_remote_code=True
        )
        
        logger.info(f"Loading model for {self.model_name}...")
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_name,
            token=self.token,
            torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
            device_map="auto" if self.device == "cuda" else None,
            trust_remote_code=True
        )
        
        if self.device == "cpu":
            self.model = self.model.to(self.device)
        
        logger.info("✅ Base model and tokenizer loaded successfully")
    
    def generate_response(self, query: str, context: List[Dict[str, Any]], 
                         analysis_type: str = 'vulnerability_analysis') -> str:
        """Generate response using the loaded model"""
        if not self.model or not self.tokenizer:
            return "Error: Model not loaded"
        
        try:
            # Build context text
            context_text = self._build_context_text(context)
            
            # Choose prompt format based on model type
            if self.use_fine_tuned:
                # Use instruction format for fine-tuned model
                full_prompt = self._format_prompt_for_fine_tuned(query, context_text, analysis_type)
            else:
                # Use system prompt format for base model
                full_prompt = self._format_prompt_for_base_model(query, context_text, analysis_type)
            
            # Tokenize
            inputs = self.tokenizer(full_prompt, return_tensors="pt", truncation=True, max_length=2048)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=512,
                    temperature=0.3,
                    top_p=0.9,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode response and clean up
            response = self.tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)
            
            # Clean up any artifacts from the model output
            response = response.replace('<|eot_id|>', '').replace('ocausticassist', '').strip()
            return response
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return f"Error: {str(e)}"
    
    def _format_prompt_for_fine_tuned(self, query: str, context_text: str, analysis_type: str) -> str:
        """Format prompt for fine-tuned model using instruction format"""
        # Map analysis type to instruction
        instruction_map = {
            'vulnerability_analysis': "Analyze this CVE vulnerability and provide a comprehensive security assessment.",
            'remediation': "Provide comprehensive remediation guidance with MITRE ATT&CK mitigations for this CVE vulnerability.",
            'technical_analysis': "Provide a detailed technical analysis with MITRE ATT&CK context for this CVE vulnerability.",
            'detection': "Create comprehensive detection strategies for this CVE vulnerability.",
            'mitigation': "Develop a comprehensive mitigation strategy for this CVE vulnerability."
        }
        
        instruction = instruction_map.get(analysis_type, "Analyze this cybersecurity query and provide a comprehensive response.")
        
        return f"""### Instruction:
{instruction}

### Input:
CVE Information:
{context_text}

Question: {query}

### Response:
"""
    
    def _format_prompt_for_base_model(self, query: str, context_text: str, analysis_type: str) -> str:
        """Format prompt for base model using system prompt format"""
        # Get system prompt
        system_prompt = self.system_prompts.get(analysis_type, self.system_prompts['vulnerability_analysis'])
        
        # Build full prompt for Llama 3
        return f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

{system_prompt}<|eot_id|><|start_header_id|>user<|end_header_id|>

CVE Information:
{context_text}

Question: {query}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""
    
    def _build_context_text(self, context: List[Dict[str, Any]]) -> str:
        """Build context text from CVE data"""
        if not context:
            return "No CVE data provided."
        
        context_parts = []
        for item in context:
            if isinstance(item, dict):
                if 'cve_id' in item:
                    context_parts.append(f"CVE ID: {item['cve_id']}")
                if 'description' in item:
                    context_parts.append(f"Description: {item['description']}")
                if 'cvss_v3' in item and 'base_score' in item['cvss_v3']:
                    context_parts.append(f"CVSS Score: {item['cvss_v3']['base_score']}")
                if 'products' in item:
                    products = ", ".join(item['products'][:5])  # Limit to 5 products
                    context_parts.append(f"Affected Products: {products}")
        
        return "\n".join(context_parts)
    
    def analyze_cve(self, cve_id: str, cve_data: Dict[str, Any]) -> str:
        """Analyze a specific CVE"""
        context = [cve_data]
        return self.generate_response(f"Analyze CVE {cve_id}", context, 'vulnerability_analysis')
    
    def get_remediation_plan(self, cve_id: str, cve_data: Dict[str, Any]) -> str:
        """Get remediation plan for a CVE"""
        context = [cve_data]
        return self.generate_response(f"Provide remediation plan for CVE {cve_id}", context, 'remediation')
    
    def analyze_product_security(self, product_name: str, cve_list: List[Dict[str, Any]]) -> str:
        """Analyze security for a specific product"""
        context = cve_list[:5]  # Limit to top 5 CVEs
        return self.generate_response(f"Analyze security for {product_name}", context, 'product_analysis')

def main():
    """Main function to test the inference engine"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE LLM Inference Engine")
    parser.add_argument("--use_fine_tuned", action="store_true", 
                       help="Use fine-tuned model instead of base model")
    parser.add_argument("--fine_tuned_path", default="models/fine_tuned_cve_production",
                       help="Path to fine-tuned model")
    parser.add_argument("--query", default="Analyze CVE-2021-44228 Log4j vulnerability",
                       help="Test query to run")
    
    args = parser.parse_args()
    
    try:
        # Initialize inference engine
        engine = HFCVEInferenceEngine(
            use_fine_tuned=args.use_fine_tuned,
            fine_tuned_path=args.fine_tuned_path
        )
        
        # Test with sample CVE data
        sample_cve = {
            'cve_id': 'CVE-2021-44228',
            'description': 'Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
            'cvss_v3': {'base_score': 10.0, 'base_severity': 'CRITICAL'},
            'products': ['Apache Log4j2']
        }
        
        # Test different analysis types
        print("\n" + "="*60)
        print("TESTING CVE ANALYSIS")
        print("="*60)
        
        # Vulnerability analysis
        print("\n1. VULNERABILITY ANALYSIS:")
        print("-" * 40)
        response = engine.analyze_cve('CVE-2021-44228', sample_cve)
        print(response)
        
        # Remediation plan
        print("\n2. REMEDIATION PLAN:")
        print("-" * 40)
        response = engine.get_remediation_plan('CVE-2021-44228', sample_cve)
        print(response)
        
        # Custom query
        print("\n3. CUSTOM QUERY:")
        print("-" * 40)
        response = engine.generate_response(args.query, [sample_cve], 'vulnerability_analysis')
        print(response)
        
        print(f"\n✅ Inference engine test completed successfully!")
        print(f"Model type: {'Fine-tuned' if args.use_fine_tuned else 'Base'}")
        
    except Exception as e:
        logger.error(f"❌ Inference engine test failed: {e}")
        raise

if __name__ == "__main__":
    main() 