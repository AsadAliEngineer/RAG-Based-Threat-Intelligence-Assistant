import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from config import Config

class MapperConfig(Config):
    """Configuration for CVE-to-TTP mapper module."""
    
    def __init__(self):
        super().__init__()
        
        # Mapper specific paths
        self.mapper_dir = Path(__file__).parent
        
        # TIE model and data paths - cleaned structure
        self.tie_models_dir = self.mapper_dir / "tie_models"
        self.tie_model_path = self.tie_models_dir / "app.trained.model.zip"
        self.tie_enrichment_path = self.tie_models_dir / "app.enrichment.json"
        self.tie_attack_data_path = self.tie_models_dir / "enterprise-attack.json"
        
        # Mapping data paths
        self.cwe_capec_mitre_mapping_path = self.cti_data_dir / "cwe_capec_mitre_mapping.json"
        
        # Output paths
        self.cve_ttp_mappings_path = self.cti_data_dir / "cve_ttp_mappings.json"
        
        # TIE configuration
        self.tie_confidence_threshold = 0.5  # Minimum confidence for TIE predictions
        self.tie_max_predictions = 10  # Maximum number of TTPs to predict per CVE