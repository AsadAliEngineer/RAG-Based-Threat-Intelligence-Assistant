import json
import logging
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
import zipfile
import tempfile

logger = logging.getLogger(__name__)

# Try to import numpy
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    logger.warning("NumPy not available, TIE inference will be disabled")
    NUMPY_AVAILABLE = False


class SimpleTIEInference:
    """Simplified TIE inference using pre-trained embeddings without full TensorFlow dependencies."""
    
    def __init__(self, model_path: Path, enrichment_path: Path):
        """Initialize simple TIE inference.
        
        Args:
            model_path: Path to the trained model (.zip file)
            enrichment_path: Path to enrichment JSON file
        """
        self.model_path = model_path
        self.enrichment_path = enrichment_path
        self.model_loaded = False
        self.technique_names = {}
        self.technique_ids = []
        
        if NUMPY_AVAILABLE:
            self._load_model()
            self._load_technique_metadata()
    
    def _load_model(self):
        """Load the pre-trained TIE model embeddings."""
        try:
            # Extract and load model components
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(self.model_path, 'r') as zf:
                    zf.extractall(tmpdir)
                
                # Load embeddings and metadata
                self.U = np.load(Path(tmpdir) / "U.npy")  # Report embeddings
                self.V = np.load(Path(tmpdir) / "V.npy")  # Technique embeddings
                
                # Load technique IDs
                technique_ids = np.load(Path(tmpdir) / "technique_ids.npy", allow_pickle=True)
                if isinstance(technique_ids[0], bytes):
                    self.technique_ids = [t.decode('utf-8') for t in technique_ids]
                else:
                    self.technique_ids = technique_ids.tolist()
                
                # Load hyperparameters
                try:
                    hp = np.load(Path(tmpdir) / "hyperparameters.npy", allow_pickle=True)
                    if len(hp) > 0:
                        self.hyperparameters = {
                            'c': float(hp[0][0]) if len(hp[0]) > 0 else 0.001,
                            'epochs': int(hp[0][1]) if len(hp[0]) > 1 else 25,
                            'regularization_coefficient': float(hp[0][2]) if len(hp[0]) > 2 else 0.00001
                        }
                    else:
                        self.hyperparameters = {'c': 0.001, 'epochs': 25, 'regularization_coefficient': 0.00001}
                except:
                    self.hyperparameters = {'c': 0.001, 'epochs': 25, 'regularization_coefficient': 0.00001}
            
            self.model_loaded = True
            self.m, self.k = self.U.shape  # Number of reports, embedding dimension
            self.n = self.V.shape[0]  # Number of techniques
            
            logger.info(f"Loaded TIE embeddings: {self.m} reports, {self.n} techniques, {self.k}-dim")
            
        except Exception as e:
            logger.error(f"Failed to load TIE model: {e}")
            self.model_loaded = False
    
    def _load_technique_metadata(self):
        """Load technique names and descriptions from enrichment data."""
        try:
            with open(self.enrichment_path, 'r', encoding='utf-8') as f:
                enrichment_data = json.load(f)
            
            # Extract technique names - the structure is {"techniques": {"T1234": {...}}}
            techniques_dict = enrichment_data.get('techniques', {})
            for tech_id, technique_data in techniques_dict.items():
                if isinstance(technique_data, dict):
                    self.technique_names[tech_id] = technique_data.get('name', tech_id)
                
        except Exception as e:
            logger.error(f"Failed to load enrichment data: {e}")
    
    def extract_keywords_from_cve(self, cve_description: str) -> Set[str]:
        """Extract relevant keywords from CVE description for TTP inference."""
        keyword_mappings = {
            # Exploitation techniques
            'remote code execution': ['T1203', 'T1210'],
            'rce': ['T1203', 'T1210'],
            'arbitrary code': ['T1203', 'T1055'],
            'code execution': ['T1203', 'T1059'],
            
            # Privilege escalation
            'privilege escalation': ['T1068', 'T1078', 'T1548'],
            'elevation of privilege': ['T1068', 'T1548'],
            'root access': ['T1068', 'T1548.001'],
            'admin access': ['T1078', 'T1098'],
            
            # Injection attacks
            'sql injection': ['T1190'],
            'command injection': ['T1059', 'T1190'],
            'code injection': ['T1055', 'T1055.001'],
            'ldap injection': ['T1190'],
            
            # Web attacks
            'cross-site scripting': ['T1059.007', 'T1189'],
            'xss': ['T1059.007', 'T1189'],
            'csrf': ['T1185'],
            'xxe': ['T1190'],
            'ssrf': ['T1190', 'T1090'],
            
            # Memory corruption
            'buffer overflow': ['T1203', 'T1055'],
            'heap overflow': ['T1203', 'T1055'],
            'stack overflow': ['T1203', 'T1055'],
            'use after free': ['T1055', 'T1203'],
            'memory corruption': ['T1055', 'T1203'],
            
            # Authentication/Access
            'authentication bypass': ['T1078', 'T1110'],
            'access control': ['T1078', 'T1548'],
            'unauthorized access': ['T1078', 'T1190'],
            
            # DoS attacks
            'denial of service': ['T1499', 'T1498'],
            'dos': ['T1499', 'T1498'],
            'resource exhaustion': ['T1499', 'T1496'],
            
            # Information disclosure
            'information disclosure': ['T1005', 'T1083', 'T1057'],
            'data exposure': ['T1005', 'T1530'],
            'sensitive information': ['T1005', 'T1552'],
            
            # File/Path issues
            'directory traversal': ['T1083', 'T1570'],
            'path traversal': ['T1083', 'T1570'],
            'file inclusion': ['T1055', 'T1574'],
        }
        
        description_lower = cve_description.lower()
        found_ttps = set()
        
        for keyword, ttps in keyword_mappings.items():
            if keyword in description_lower:
                found_ttps.update(ttps)
        
        return found_ttps
    
    def infer_ttps_from_description(self, cve_description: str, confidence_threshold: float = 0.1) -> Tuple[List[str], Dict]:
        """Infer TTPs from CVE description using simplified TIE approach."""
        
        # First, extract keywords
        keyword_ttps = self.extract_keywords_from_cve(cve_description)
        
        if not self.model_loaded or not NUMPY_AVAILABLE:
            return list(keyword_ttps), {"method": "keyword_extraction", "reason": "TIE model not available"}
        
        if not keyword_ttps:
            return [], {"method": "simple_tie", "message": "No techniques identified in description"}
        
        try:
            # Find indices of observed techniques in our model
            observed_indices = []
            for tech in keyword_ttps:
                if tech in self.technique_ids:
                    idx = self.technique_ids.index(tech)
                    observed_indices.append(idx)
            
            if not observed_indices:
                return list(keyword_ttps), {"method": "keyword_extraction", "message": "No known techniques found in model"}
            
            # Use technique embeddings to find similar techniques
            # Get embeddings of observed techniques
            observed_embeddings = self.V[observed_indices]
            
            # Compute average embedding of observed techniques
            avg_embedding = np.mean(observed_embeddings, axis=0)
            
            # Compute similarity with all techniques using cosine similarity
            # Handle zero division for techniques with zero embeddings
            v_norms = np.linalg.norm(self.V, axis=1)
            avg_norm = np.linalg.norm(avg_embedding)
            
            # Avoid division by zero
            v_norms = np.where(v_norms == 0, 1e-8, v_norms)
            avg_norm = max(avg_norm, 1e-8)
            
            similarities = np.dot(self.V, avg_embedding) / (v_norms * avg_norm)
            
            # Get predictions above threshold, excluding already observed
            predictions = []
            observed_set = set(observed_indices)
            
            for idx, similarity in enumerate(similarities):
                if similarity > confidence_threshold and idx not in observed_set:
                    tech_id = self.technique_ids[idx]
                    predictions.append({
                        "technique": tech_id,
                        "confidence": float(similarity),
                        "name": self.technique_names.get(tech_id, tech_id)
                    })
            
            # Sort by confidence
            predictions.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Combine original keywords with top predictions
            all_ttps = list(keyword_ttps)
            for pred in predictions[:10]:  # Top 10 predictions
                all_ttps.append(pred['technique'])
            
            return all_ttps, {
                "method": "simple_tie",
                "keyword_ttps": list(keyword_ttps),
                "inferred_ttps": [p['technique'] for p in predictions[:10]],
                "confidence_scores": {p['technique']: p['confidence'] for p in predictions[:10]},
                "observed_techniques_count": len(observed_indices)
            }
            
        except Exception as e:
            logger.error(f"TIE inference failed: {e}")
            return list(keyword_ttps), {"method": "keyword_extraction", "error": str(e)}
    
    def batch_infer_ttps(self, cve_list: List[Dict], confidence_threshold: float = 0.1) -> Dict[str, Dict]:
        """Infer TTPs for multiple CVEs."""
        results = {}
        
        for cve in cve_list:
            cve_id = cve.get('id', '')
            description = cve.get('description', '')
            
            if cve_id and description:
                ttps, details = self.infer_ttps_from_description(description, confidence_threshold)
                results[cve_id] = {
                    "ttps": ttps,
                    "inference_details": details
                }
        
        return results