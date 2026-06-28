#!/usr/bin/env python3

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.mapper.mapper_config import MapperConfig
from src.mapper.cve_cwe_mapper import CVEtoCWEtoTTPMapper
from src.mapper.simple_tie_inference import SimpleTIEInference


def test_cwe_mapping():
    """Test CWE-based mapping."""
    print("=== Testing CWE-based Mapping ===")
    
    config = MapperConfig()
    
    if not config.cwe_capec_mitre_mapping_path.exists():
        print(f"ERROR: CWE mapping file not found at {config.cwe_capec_mitre_mapping_path}")
        print("Please run the data collection pipeline first")
        return False
    
    cwe_mapper = CVEtoCWEtoTTPMapper(config.cwe_capec_mitre_mapping_path)
    
    # Test CVE with known CWEs
    test_cve = {
        "id": "CVE-2021-44228",
        "cwe_ids": ["CWE-502", "CWE-400", "CWE-20"]
    }
    
    ttps, details = cwe_mapper.map_cve_to_ttps(test_cve)
    
    print(f"CVE: {test_cve['id']}")
    print(f"CWEs: {', '.join(test_cve['cwe_ids'])}")
    print(f"TTPs found: {len(ttps)}")
    if ttps:
        print(f"TTPs: {', '.join(ttps[:5])}")
    
    return len(ttps) > 0


def test_simple_tie():
    """Test simple TIE inference."""
    print("\n=== Testing Simple TIE Inference ===")
    
    config = MapperConfig()
    
    if not config.tie_model_path.exists():
        print(f"TIE model not found at {config.tie_model_path}")
        print("TIE inference will be skipped")
        return False
    
    try:
        tie = SimpleTIEInference(
            model_path=config.tie_model_path,
            enrichment_path=config.tie_enrichment_path
        )
        
        if not tie.model_loaded:
            print("TIE model failed to load")
            return False
        
        print(f"TIE model loaded: {tie.n} techniques, {tie.k}-dim embeddings")
        
        # Test inference
        test_description = """
        A remote code execution vulnerability exists that allows an attacker 
        to execute arbitrary commands via SQL injection attacks.
        """
        
        ttps, details = tie.infer_ttps_from_description(test_description)
        
        print(f"Test description inference:")
        print(f"TTPs found: {len(ttps)}")
        if ttps:
            print(f"TTPs: {', '.join(ttps[:5])}")
        print(f"Method: {details.get('method', 'unknown')}")
        
        return len(ttps) > 0
        
    except ImportError as e:
        print(f"TIE inference requires NumPy: {e}")
        return False
    except Exception as e:
        print(f"TIE test failed: {e}")
        return False


def test_combined():
    """Test combined mapping."""
    print("\n=== Testing Combined Mapping ===")
    
    try:
        from src.mapper.cve_ttp_mapper import CVEtoTTPMapper
        
        config = MapperConfig()
        mapper = CVEtoTTPMapper(config)
        
        test_cve = {
            "id": "CVE-2024-TEST",
            "description": "A buffer overflow vulnerability allows remote code execution via command injection",
            "cwe_ids": ["CWE-119"]
        }
        
        result = mapper.map_cve_to_ttps(test_cve)
        
        print(f"CVE: {result['cve_id']}")
        print(f"Methods used: {', '.join(result['methods_used'])}")
        print(f"Total TTPs: {result['total_ttps_found']}")
        if result['ttps']:
            print(f"TTPs: {', '.join(result['ttps'][:5])}")
        
        return result['total_ttps_found'] > 0
        
    except Exception as e:
        print(f"Combined test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("CVE-to-TTP Mapper Test Suite (Simplified)")
    print("=" * 50)
    
    results = []
    
    results.append(test_cwe_mapping())
    results.append(test_simple_tie())
    results.append(test_combined())
    
    print(f"\n=== Test Results ===")
    print(f"CWE Mapping: {'✓' if results[0] else '✗'}")
    print(f"TIE Inference: {'✓' if results[1] else '✗'}")
    print(f"Combined: {'✓' if results[2] else '✗'}")
    
    if any(results):
        print("\nAt least one method is working! ✓")
    else:
        print("\nNo methods are working. Check your setup.")


if __name__ == "__main__":
    main()