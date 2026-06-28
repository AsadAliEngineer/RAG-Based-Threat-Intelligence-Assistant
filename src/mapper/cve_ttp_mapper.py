import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime

from .mapper_config import MapperConfig
from .cve_cwe_mapper import CVEtoCWEtoTTPMapper
from .simple_tie_inference import SimpleTIEInference

logger = logging.getLogger(__name__)


class CVEtoTTPMapper:
    """Main mapper that combines CWE-based mapping and TIE inference for CVE-to-TTP mapping."""
    
    def __init__(self, config: Optional[MapperConfig] = None):
        """Initialize the CVE-to-TTP mapper.
        
        Args:
            config: MapperConfig instance, creates new one if not provided
        """
        self.config = config or MapperConfig()
        
        # Initialize CWE-based mapper
        self.cwe_mapper = CVEtoCWEtoTTPMapper(self.config.cwe_capec_mitre_mapping_path)
        
        # Initialize simplified TIE for inference
        try:
            self.tie_inference = SimpleTIEInference(
                model_path=self.config.tie_model_path,
                enrichment_path=self.config.tie_enrichment_path
            )
            self.tie_available = self.tie_inference.model_loaded
        except Exception as e:
            logger.warning(f"TIE initialization failed: {e}. Will use CWE mapping only.")
            self.tie_inference = None
            self.tie_available = False
    
    def map_cve_to_ttps(self, cve_data: Dict) -> Dict:
        """Map a CVE to TTPs using both CWE mapping and TIE inference.
        
        Args:
            cve_data: Dictionary containing CVE information
            
        Returns:
            Dictionary containing combined TTP mappings and details
        """
        cve_id = cve_data.get("id", "Unknown")
        result = {
            "cve_id": cve_id,
            "ttps": [],
            "methods_used": [],
            "details": {}
        }
        
        # Method 1: CWE-based mapping
        cwe_ttps, cwe_details = self.cwe_mapper.map_cve_to_ttps(cve_data)
        if cwe_ttps:
            result["ttps"].extend(cwe_ttps)
            result["methods_used"].append("CWE-to-CAPEC-to-TTP")
            result["details"]["cwe_mapping"] = cwe_details
        
        # Method 2: TIE inference from description
        if self.tie_available:
            description = cve_data.get("description", "")
            if not description and "descriptions" in cve_data:
                # Handle NVD format
                desc_list = cve_data.get("descriptions", [])
                if desc_list and isinstance(desc_list[0], dict):
                    description = desc_list[0].get("value", "")
            
            if description:
                tie_ttps, tie_details = self.tie_inference.infer_ttps_from_description(
                    description, 
                    self.config.tie_confidence_threshold
                )
                
                # Add TTPs not already found via CWE
                new_ttps = [ttp for ttp in tie_ttps if ttp not in result["ttps"]]
                if new_ttps:
                    result["ttps"].extend(new_ttps)
                    result["methods_used"].append("TIE-inference")
                    result["details"]["tie_inference"] = tie_details
        
        # Remove duplicates while preserving order
        seen = set()
        unique_ttps = []
        for ttp in result["ttps"]:
            if ttp not in seen:
                seen.add(ttp)
                unique_ttps.append(ttp)
        result["ttps"] = unique_ttps
        
        # Add metadata
        result["mapping_timestamp"] = datetime.now().isoformat()
        result["total_ttps_found"] = len(result["ttps"])
        
        return result
    
    def process_cve_file(self, cve_file_path: Path) -> List[Dict]:
        """Process a file containing CVE data.
        
        Args:
            cve_file_path: Path to JSON file containing CVE data
            
        Returns:
            List of CVE-to-TTP mapping results
        """
        try:
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Handle different file formats
            if isinstance(cve_data, dict):
                if "CVE_Items" in cve_data:  # NVD format
                    cve_list = cve_data["CVE_Items"]
                elif "vulnerabilities" in cve_data:  # NVD API v2 format
                    cve_list = cve_data["vulnerabilities"]
                else:
                    cve_list = [cve_data]  # Single CVE
            else:
                cve_list = cve_data  # List of CVEs
            
            results = []
            for cve_item in cve_list:
                # Extract CVE data based on format
                if "cve" in cve_item:  # NVD API v2
                    cve_data = cve_item["cve"]
                elif "configurations" in cve_item:  # NVD v1
                    cve_data = cve_item
                else:
                    cve_data = cve_item
                
                mapping_result = self.map_cve_to_ttps(cve_data)
                results.append(mapping_result)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to process CVE file {cve_file_path}: {e}")
            return []
    
    def save_mappings(self, mappings: List[Dict], output_path: Optional[Path] = None):
        """Save CVE-to-TTP mappings to file.
        
        Args:
            mappings: List of mapping results
            output_path: Path to save mappings (uses config default if not provided)
        """
        output_path = output_path or self.config.cve_ttp_mappings_path
        
        try:
            # Create summary statistics
            summary = {
                "total_cves": len(mappings),
                "cves_with_ttps": len([m for m in mappings if m["ttps"]]),
                "total_unique_ttps": len(set(ttp for m in mappings for ttp in m["ttps"])),
                "mapping_date": datetime.now().isoformat(),
                "methods_available": {
                    "cwe_mapping": bool(self.cwe_to_ttp_mapping),
                    "tie_inference": self.tie_available
                }
            }
            
            output_data = {
                "summary": summary,
                "mappings": mappings
            }
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            logger.info(f"Saved {len(mappings)} CVE-to-TTP mappings to {output_path}")
            logger.info(f"Summary: {summary['cves_with_ttps']} CVEs mapped to {summary['total_unique_ttps']} unique TTPs")
            
        except Exception as e:
            logger.error(f"Failed to save mappings: {e}")