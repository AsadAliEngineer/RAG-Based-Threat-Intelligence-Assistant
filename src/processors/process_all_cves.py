#!/usr/bin/env python3
"""
Processes CVE dataset and creates a comprehensive knowledge base
"""

import json
import logging
import time
import zipfile
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import sys

# Import the centralized config
sys.path.append(str(Path(__file__).parent.parent.parent))
from config import Config

# Import the new extractors and enrichers
from src.processors.extractors import (
    extract_zip_files,
    load_cwe_capec_mitre_mapping,
    load_csaf_data,
    load_exploitdb_data,
    load_kev_data
)
from src.processors.enrichers import enrich_cve_with_cti, enrich_all_cves
from src.processors.filters import filter_rejected_cves
from src.processors.savers import save_processed_data

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CVEProcessor:
    """Processes all CVE data files and creates a comprehensive knowledge base"""
    
    def __init__(self):
        # Initialize config
        self.config = Config()
        
        # CVE data paths
        self.data_dir = self.config.base_data_dir / "CVE"
        self.zip_dir = self.data_dir / "zip"
        self.json_dir = self.data_dir / "json"
        self.processed_dir = self.data_dir / "processed"
        self.correlations_dir = self.data_dir / "correlations"
        
        # Create directories if they don't exist
        self.json_dir.mkdir(exist_ok=True)
        self.processed_dir.mkdir(exist_ok=True)
        self.correlations_dir.mkdir(exist_ok=True)
        
        # CTI data paths
        self.cti_raw_dir = self.config.cti_data_dir
        self.cti_docs_dir = self.config.cti_docs_dir
        
        # Data storage
        self.all_cves = []
        self.kev_data = []
        self.csaf_data = []
        self.exploitdb_data = []
        self.cwe_capec_mitre_mapping = {}
        self.csaf_by_cve = {}
        self.exploitdb_by_cve = {}
        self.kev_by_cve = {}
    
    def extract_zip_files(self):
        extract_zip_files(self.zip_dir, self.json_dir, logger)
    
    def load_cwe_capec_mitre_mapping(self):
        # Try multiple possible locations for the mapping file
        mapping_locations = [
            self.cti_raw_dir / "cwe_capec_mitre_mapping.json",
            self.cti_docs_dir / "cwe_capec_mitre_mapping.json",
            self.cti_raw_dir / "mappings" / "cwe_capec_mitre_mapping.json"
        ]
        
        for location in mapping_locations:
            if location.exists():
                self.cwe_capec_mitre_mapping = load_cwe_capec_mitre_mapping(location, logger)
                logger.info(f"Loaded CWE-CAPEC-MITRE mapping from: {location}")
                return
        
        logger.warning("CWE-CAPEC-MITRE mapping file not found in any location")
        self.cwe_capec_mitre_mapping = {}

    def load_csaf_data(self):
        # Try multiple possible locations for CSAF data
        csaf_locations = [
            self.cti_docs_dir / "csaf",
            self.cti_raw_dir / "csaf",
            self.cti_raw_dir / "CSAF"
        ]
        
        for location in csaf_locations:
            if location.exists():
                self.csaf_data, self.csaf_by_cve = load_csaf_data(location, logger)
                logger.info(f"Loaded CSAF data from: {location}")
                return
        
        logger.warning("CSAF data not found in any location")
        self.csaf_data, self.csaf_by_cve = [], {}

    def load_exploitdb_data(self):
        # Try multiple possible locations for ExploitDB data
        exploitdb_locations = [
            self.cti_docs_dir / "exploitdb",
            self.cti_raw_dir / "exploitdb",
            self.cti_raw_dir / "ExploitDB"
        ]
        
        for location in exploitdb_locations:
            if location.exists():
                self.exploitdb_data, self.exploitdb_by_cve = load_exploitdb_data(location, logger)
                logger.info(f"Loaded ExploitDB data from: {location}")
                return
        
        logger.warning("ExploitDB data not found in any location")
        self.exploitdb_data, self.exploitdb_by_cve = [], {}

    def load_kev_data(self):
        # Try multiple possible locations for KEV data
        kev_locations = [
            self.cti_docs_dir / "kev",
            self.cti_raw_dir / "kev",
            self.cti_raw_dir / "KEV",
            self.cti_raw_dir / "known_exploited_vulnerabilities.csv"
        ]
        
        for location in kev_locations:
            if location.exists():
                if location.suffix == '.csv':
                    # Direct CSV file
                    self.kev_data, self.kev_by_cve = load_kev_data(location.parent, logger)
                else:
                    # Directory with JSON files
                    self.kev_data, self.kev_by_cve = load_kev_data(location, logger)
                logger.info(f"Loaded KEV data from: {location}")
                return
        
        logger.warning("KEV data not found in any location")
        self.kev_data, self.kev_by_cve = [], {}

    def _clean_cvss_data(self, cvss_data: Dict) -> Dict:
        """Remove null values from CVSS data"""
        if not cvss_data:
            return {}
        
        cleaned = {}
        for key, value in cvss_data.items():
            if value is not None:
                cleaned[key] = value
        
        return cleaned

    def _fix_product_name(self, product: str) -> str:
        """Fix escaped slashes in product names"""
        if not product:
            return product
        
        # Fix escaped slashes: \\/ -> //
        fixed = product.replace('\\/', '//')
        return fixed

    def _extract_and_fix_product_from_cpe(self, cpe: str) -> str:
        """Extract product name from CPE and fix escaped slashes"""
        if not cpe:
            return ""
        
        # Parse CPE to extract product information
        parts = cpe.split(':')
        if len(parts) >= 5:
            product = parts[4]
            return self._fix_product_name(product)
        
        return ""

    def _clean_cpe_match(self, cpe_match: Dict) -> Dict:
        """Clean CPE match data by removing null values"""
        if not cpe_match:
            return {}
        
        cleaned = {}
        for key, value in cpe_match.items():
            if value is not None:
                cleaned[key] = value
        
        return cleaned
    
    def process_all_cve_files(self, max_cves: Optional[int] = None) -> List[Dict]:
        """Process all CVE files and extract structured data"""
        logger.info("Processing all CVE files...")
        
        # Extract zip files first
        self.extract_zip_files()
        
        # Get all JSON files
        v1_files = list(self.json_dir.glob("nvdcve-1.1-*.json"))
        v2_files = list(self.json_dir.glob("nvdcve-2.0-*.json"))
        
        logger.info(f"Found {len(v1_files)} v1.1 files and {len(v2_files)} v2.0 files")
        
        # Process v1.1 files first (they're smaller and easier to process)
        logger.info("Processing v1.1 files...")
        for i, json_file in enumerate(sorted(v1_files)):
            logger.info(f"Processing v1.1 file {i+1}/{len(v1_files)}: {json_file.name}")
            cves = self._process_v1_file(json_file)
            self.all_cves.extend(cves)
            
            if max_cves and len(self.all_cves) >= max_cves:
                logger.info(f"Reached max CVEs limit: {max_cves}")
                break
        
        # Process v2.0 files (only if we haven't reached the limit)
        if not max_cves or len(self.all_cves) < max_cves:
            logger.info("Processing v2.0 files...")
            for i, json_file in enumerate(sorted(v2_files)):
                logger.info(f"Processing v2.0 file {i+1}/{len(v2_files)}: {json_file.name}")
                cves = self._process_v2_file(json_file)
                self.all_cves.extend(cves)
                
                if max_cves and len(self.all_cves) >= max_cves:
                    logger.info(f"Reached max CVEs limit: {max_cves}")
                    break
        
        # Filter out rejected CVEs
        self.all_cves = filter_rejected_cves(self.all_cves, logger)
        
        logger.info(f"Processed {len(self.all_cves)} total CVEs (after filtering)")
        return self.all_cves
    
    def _process_v1_file(self, json_file: Path) -> List[Dict]:
        """Process a v1.1 format CVE file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            cve_items = data.get('CVE_Items', [])
            processed_cves = []
            
            for cve_item in cve_items:
                cve_data = cve_item.get('cve', {})
                configurations = cve_item.get('configurations', {})
                cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
                
                if cve_id:
                    processed_cve = self._process_v1_cve(cve_item, configurations)
                    if processed_cve:
                        processed_cves.append(processed_cve)
            
            return processed_cves
            
        except Exception as e:
            logger.error(f"Error processing {json_file.name}: {e}")
            return []
    
    def _process_v2_file(self, json_file: Path) -> List[Dict]:
        """Process a v2.0 format CVE file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', [])
            processed_cves = []
            
            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})
                configurations = vuln.get('configurations', {})
                cve_id = cve_data.get('id', '')
                
                if cve_id:
                    processed_cve = self._process_v2_cve(cve_data, configurations)
                    if processed_cve:
                        processed_cves.append(processed_cve)
            
            return processed_cves
            
        except Exception as e:
            logger.error(f"Error processing {json_file.name}: {e}")
            return []
    
    def _process_v1_cve(self, cve_item: Dict, configurations: Dict) -> Optional[Dict]:
        """Process a single v1.1 CVE"""
        try:
            cve_data = cve_item.get('cve', {})
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            # Get description
            description_data = cve_data.get('description', {}).get('description_data', [])
            description = ""
            for desc in description_data:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS scores and vectors with version information
            impact = cve_item.get('impact', {})
            base_metric_v3 = impact.get('baseMetricV3', {})
            cvss_v3 = base_metric_v3.get('cvssV3', {})
            base_metric_v2 = impact.get('baseMetricV2', {})
            cvss_v2 = base_metric_v2.get('cvssV2', {})
            
            # Get CWE references
            problemtype_data = cve_data.get('problemtype', {}).get('problemtype_data', [])
            cwe_ids = []
            for problem in problemtype_data:
                for desc in problem.get('description', []):
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        cwe_ids.append(cwe_id)
            
            # Get references
            references_data = cve_data.get('references', {}).get('reference_data', [])
            ref_urls = [ref.get('url', '') for ref in references_data if ref.get('url')]
            
            # Get CPE configurations (detailed) - now using the passed configurations parameter
            cpe_configurations = []
            affected_products = []
            
            # Handle the nested structure properly
            nodes = configurations.get('nodes', [])
            
            for node in nodes:
                config_entry = {
                    'operator': node.get('operator', ''),
                    'cpe_match': []
                }
                
                # Process cpe_match entries in this node
                for cpe_match in node.get('cpe_match', []):
                    cpe = cpe_match.get('cpe23Uri', '')
                    if cpe:
                        # Parse CPE to extract product information and fix escaped slashes
                        product = self._extract_and_fix_product_from_cpe(cpe)
                        if product:
                            affected_products.append(product)
                        
                        # Fix the CPE URI itself
                        fixed_cpe = self._fix_product_name(cpe)
                        
                        # Clean CPE match data
                        cleaned_cpe_match = self._clean_cpe_match({
                            'cpe23Uri': fixed_cpe,
                            'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                            'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                            'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                            'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                            'vulnerable': cpe_match.get('vulnerable', True)
                        })
                        
                        config_entry['cpe_match'].append(cleaned_cpe_match)
                
                # Also check children nodes recursively
                children = node.get('children', [])
                for child in children:
                    for cpe_match in child.get('cpe_match', []):
                        cpe = cpe_match.get('cpe23Uri', '')
                        if cpe:
                            # Parse CPE to extract product information and fix escaped slashes
                            product = self._extract_and_fix_product_from_cpe(cpe)
                            if product:
                                affected_products.append(product)
                            
                            # Fix the CPE URI itself
                            fixed_cpe = self._fix_product_name(cpe)
                            
                            # Clean CPE match data
                            cleaned_cpe_match = self._clean_cpe_match({
                                'cpe23Uri': fixed_cpe,
                                'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                                'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                'vulnerable': cpe_match.get('vulnerable', True)
                            })
                            
                            config_entry['cpe_match'].append(cleaned_cpe_match)
                
                if config_entry['cpe_match']:
                    cpe_configurations.append(config_entry)
            
            # Clean CVSS data - only include non-null values
            cleaned_cvss_v3 = self._clean_cvss_data({
                'version': '3.0',
                'base_score': cvss_v3.get('baseScore'),
                'vector_string': cvss_v3.get('vectorString'),
                'base_severity': cvss_v3.get('baseSeverity'),
                'attack_vector': cvss_v3.get('attackVector'),
                'attack_complexity': cvss_v3.get('attackComplexity'),
                'privileges_required': cvss_v3.get('privilegesRequired'),
                'user_interaction': cvss_v3.get('userInteraction'),
                'scope': cvss_v3.get('scope'),
                'confidentiality_impact': cvss_v3.get('confidentialityImpact'),
                'integrity_impact': cvss_v3.get('integrityImpact'),
                'availability_impact': cvss_v3.get('availabilityImpact')
            })
            
            cleaned_cvss_v2 = self._clean_cvss_data({
                'version': '2.0',
                'base_score': cvss_v2.get('baseScore'),
                'vector_string': cvss_v2.get('vectorString'),
                'severity': base_metric_v2.get('severity'),
                'access_vector': cvss_v2.get('accessVector'),
                'access_complexity': cvss_v2.get('accessComplexity'),
                'authentication': cvss_v2.get('authentication'),
                'confidentiality_impact': cvss_v2.get('confidentialityImpact'),
                'integrity_impact': cvss_v2.get('integrityImpact'),
                'availability_impact': cvss_v2.get('availabilityImpact')
            })
            
            result = {
                'cve_id': cve_id,
                'description': description,
                'cwe_ids': list(set(cwe_ids)),
                'affected_products': list(set(affected_products)),
                'cpe_configurations': cpe_configurations,
                'references': ref_urls,
                'published_date': cve_item.get('publishedDate', ''),
                'last_modified_date': cve_item.get('lastModifiedDate', ''),
                'source': 'NVD v1.1'
            }
            
            # Only add CVSS data if it has actual values
            if cleaned_cvss_v3:
                result['cvss_v3'] = cleaned_cvss_v3
            if cleaned_cvss_v2:
                result['cvss_v2'] = cleaned_cvss_v2
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing v1 CVE: {e}")
            return None
    
    def _process_v2_cve(self, cve_data: Dict, configurations: Dict) -> Optional[Dict]:
        """Process a single v2.0 CVE"""
        try:
            cve_id = cve_data.get('id', '')
            
            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS scores and vectors with version information
            metrics = cve_data.get('metrics', {})
            
            # CVSS v3.1 (preferred) or v3.0
            cvss_v3_data = None
            cvss_v3_version = None
            if metrics.get('cvssMetricV31'):
                cvss_v3_data = metrics.get('cvssMetricV31', [{}])[0]
                cvss_v3_version = '3.1'
            elif metrics.get('cvssMetricV30'):
                cvss_v3_data = metrics.get('cvssMetricV30', [{}])[0]
                cvss_v3_version = '3.0'
            
            cvss_v3 = {}
            if cvss_v3_data:
                cvss_data = cvss_v3_data.get('cvssData', {})
                cvss_v3 = {
                    'version': cvss_v3_version,
                    'base_score': cvss_data.get('baseScore'),
                    'vector_string': cvss_data.get('vectorString'),
                    'base_severity': cvss_data.get('baseSeverity'),
                    'attack_vector': cvss_data.get('attackVector'),
                    'attack_complexity': cvss_data.get('attackComplexity'),
                    'privileges_required': cvss_data.get('privilegesRequired'),
                    'user_interaction': cvss_data.get('userInteraction'),
                    'scope': cvss_data.get('scope'),
                    'confidentiality_impact': cvss_data.get('confidentialityImpact'),
                    'integrity_impact': cvss_data.get('integrityImpact'),
                    'availability_impact': cvss_data.get('availabilityImpact')
                }
            
            # CVSS v2
            cvss_v2 = {}
            if metrics.get('cvssMetricV2'):
                cvss_v2_data = metrics.get('cvssMetricV2', [{}])[0]
                cvss_v2_info = cvss_v2_data.get('cvssData', {})
                cvss_v2 = {
                    'version': '2.0',
                    'base_score': cvss_v2_info.get('baseScore'),
                    'vector_string': cvss_v2_info.get('vectorString'),
                    'severity': cvss_v2_data.get('baseSeverity'),
                    'access_vector': cvss_v2_info.get('accessVector'),
                    'access_complexity': cvss_v2_info.get('accessComplexity'),
                    'authentication': cvss_v2_info.get('authentication'),
                    'confidentiality_impact': cvss_v2_info.get('confidentialityImpact'),
                    'integrity_impact': cvss_v2_info.get('integrityImpact'),
                    'availability_impact': cvss_v2_info.get('availabilityImpact')
                }
            
            # Get CWE references
            weaknesses = cve_data.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_id = desc.get('value', '')
                        if cwe_id.startswith('CWE-'):
                            cwe_ids.append(cwe_id)
            
            # Get references
            references = cve_data.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references if ref.get('url')]
            
            # Get CPE configurations (detailed) - now using the passed configurations parameter
            cpe_configurations = []
            affected_products = []
            
            # Handle v2.0 configurations structure (configurations is a list)
            if isinstance(configurations, list):
                for config in configurations:
                    for node in config.get('nodes', []):
                        config_entry = {
                            'operator': node.get('operator', ''),
                            'negate': node.get('negate', False),
                            'cpe_match': []
                        }
                        
                        # Process cpeMatch entries in this node
                        for cpe_match in node.get('cpeMatch', []):
                            cpe = cpe_match.get('criteria', '')  # v2.0 uses 'criteria' instead of 'cpe23Uri'
                            if cpe:
                                # Parse CPE to extract product information and fix escaped slashes
                                product = self._extract_and_fix_product_from_cpe(cpe)
                                if product:
                                    affected_products.append(product)
                                
                                # Fix the CPE URI itself
                                fixed_cpe = self._fix_product_name(cpe)
                                
                                # Clean CPE match data
                                cleaned_cpe_match = self._clean_cpe_match({
                                    'cpe23Uri': fixed_cpe,  # Keep consistent field name
                                    'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                    'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                    'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                                    'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                    'vulnerable': cpe_match.get('vulnerable', True),
                                    'matchCriteriaId': cpe_match.get('matchCriteriaId')  # v2.0 specific
                                })
                                
                                config_entry['cpe_match'].append(cleaned_cpe_match)
                        
                        # Also check children nodes recursively
                        children = node.get('children', [])
                        for child in children:
                            for cpe_match in child.get('cpeMatch', []):
                                cpe = cpe_match.get('criteria', '')
                                if cpe:
                                    # Parse CPE to extract product information and fix escaped slashes
                                    product = self._extract_and_fix_product_from_cpe(cpe)
                                    if product:
                                        affected_products.append(product)
                                    
                                    # Fix the CPE URI itself
                                    fixed_cpe = self._fix_product_name(cpe)
                                    
                                    # Clean CPE match data
                                    cleaned_cpe_match = self._clean_cpe_match({
                                        'cpe23Uri': fixed_cpe,  # Keep consistent field name
                                        'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                        'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                        'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                                        'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                        'vulnerable': cpe_match.get('vulnerable', True),
                                        'matchCriteriaId': cpe_match.get('matchCriteriaId')  # v2.0 specific
                                    })
                                    
                                    config_entry['cpe_match'].append(cleaned_cpe_match)
                        
                        if config_entry['cpe_match']:
                            cpe_configurations.append(config_entry)
            
            # Clean CVSS data - only include non-null values
            cleaned_cvss_v3 = self._clean_cvss_data(cvss_v3)
            cleaned_cvss_v2 = self._clean_cvss_data(cvss_v2)
            
            result = {
                'cve_id': cve_id,
                'description': description,
                'cwe_ids': list(set(cwe_ids)),
                'affected_products': list(set(affected_products)),
                'cpe_configurations': cpe_configurations,
                'references': ref_urls,
                'published_date': cve_data.get('published', ''),
                'last_modified_date': cve_data.get('lastModified', ''),
                'source': 'NVD v2.0'
            }
            
            # Only add CVSS data if it has actual values
            if cleaned_cvss_v3:
                result['cvss_v3'] = cleaned_cvss_v3
            if cleaned_cvss_v2:
                result['cvss_v2'] = cleaned_cvss_v2
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing v2 CVE: {e}")
            return None
    
    def create_enhanced_documents(self) -> List[Dict]:
        """Create enhanced documents for the RAG system"""
        logger.info("Creating enhanced documents for RAG system...")
        
        enhanced_docs = []
        
        # Create CVE documents
        for cve in self.all_cves:
            cve_id = cve.get('cve_id', '')
            description = cve.get('description', '')
            
            if not description:
                continue
            
            # Build comprehensive content
            content_parts = [description]
            
            # Add CVSS information with version details
            cvss_v3 = cve.get('cvss_v3', {})
            cvss_v2 = cve.get('cvss_v2', {})
            
            if cvss_v3.get('base_score'):
                content_parts.append(f"CVSS v{cvss_v3.get('version', '3.x')} Score: {cvss_v3['base_score']} ({cvss_v3.get('base_severity', 'Unknown')})")
                if cvss_v3.get('vector_string'):
                    content_parts.append(f"CVSS v{cvss_v3.get('version', '3.x')} Vector: {cvss_v3['vector_string']}")
            
            if cvss_v2.get('base_score'):
                content_parts.append(f"CVSS v2.0 Score: {cvss_v2['base_score']} ({cvss_v2.get('severity', 'Unknown')})")
                if cvss_v2.get('vector_string'):
                    content_parts.append(f"CVSS v2.0 Vector: {cvss_v2['vector_string']}")
            
            # Add affected products
            affected_products = cve.get('affected_products', [])
            if affected_products:
                content_parts.append(f"Affected Products: {', '.join(affected_products[:5])}")  # Limit to 5
            
            # Add CWE information
            cwe_ids = cve.get('cwe_ids', [])
            if cwe_ids:
                content_parts.append(f"Related CWEs: {', '.join(cwe_ids)}")
            
            # Add CAPEC information
            capec_entries = cve.get('capec_entries', [])
            if capec_entries:
                content_parts.append(f"Related CAPECs: {', '.join(capec_entries[:3])}")  # Limit to 3
            
            # Add MITRE ATT&CK techniques and tactics
            mitre_techniques = cve.get('mitre_techniques', [])
            mitre_tactics = cve.get('mitre_tactics', [])
            if mitre_techniques:
                content_parts.append(f"MITRE ATT&CK Techniques: {', '.join(mitre_techniques[:3])}")  # Limit to 3
            if mitre_tactics:
                content_parts.append(f"MITRE ATT&CK Tactics: {', '.join(mitre_tactics[:3])}")  # Limit to 3
            
            # Add correlation information
            if cve.get('is_in_kev'):
                content_parts.append("WARNING: This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog")
            
            csaf_correlations = cve.get('csaf_correlations', [])
            if csaf_correlations:
                csaf_ids = [csaf.get('id', '') for csaf in csaf_correlations if csaf.get('id')]
                if csaf_ids:
                    content_parts.append(f"CSAF Advisories: {', '.join(csaf_ids[:3])}")  # Limit to 3
            
            exploitdb_correlations = cve.get('exploitdb_correlations', [])
            if exploitdb_correlations:
                exploitdb_ids = [exp.get('id', '') for exp in exploitdb_correlations if exp.get('id')]
                if exploitdb_ids:
                    content_parts.append(f"ExploitDB IDs: {', '.join(exploitdb_ids[:3])}")  # Limit to 3
            
            # Add references
            references = cve.get('references', [])
            if references:
                content_parts.append(f"References: {', '.join(references[:3])}")  # Limit to 3
            
            # Create document
            doc = {
                'id': cve_id,
                'title': f"CVE {cve_id}",
                'content': "\n".join(content_parts),
                'source': cve.get('source', 'NVD'),
                'document_type': 'CVE',
                'cve_refs': [cve_id],
                'cwe_refs': cwe_ids,
                'capec_entries': capec_entries,
                'mitre_techniques': mitre_techniques,
                'mitre_tactics': mitre_tactics,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'affected_products': affected_products,
                'cpe_configurations': cve.get('cpe_configurations', []),
                'published_date': cve.get('published_date', ''),
                'last_modified_date': cve.get('last_modified_date', ''),
                'is_in_kev': cve.get('is_in_kev', False),
                'csaf_correlations_count': len(cve.get('csaf_correlations', [])),
                'exploitdb_correlations_count': len(cve.get('exploitdb_correlations', [])),
                'tags': self._extract_tags_from_cve(cve)
            }
            enhanced_docs.append(doc)
        
        # Create KEV documents
        for kev in self.kev_data:
            cve_id = kev.get('id', '')  # KEV files use 'id' field
            if cve_id:
                content_parts = [
                    f"Known Exploited Vulnerability: {cve_id}",
                    f"Vendor/Project: {kev.get('vendor_project', 'Unknown')}",
                    f"Product: {kev.get('product', 'Unknown')}",
                    f"Vulnerability Name: {kev.get('vulnerability_name', 'Unknown')}",
                    f"Date Added to KEV: {kev.get('date_added', 'Unknown')}",
                    f"Required Action: {kev.get('required_action', 'None specified')}",
                    f"Due Date: {kev.get('due_date', 'None specified')}",
                ]
                
                if kev.get('known_ransomware'):
                    content_parts.append(f"Known Ransomware Campaign Use: {kev.get('known_ransomware')}")
                
                if kev.get('notes'):
                    content_parts.append(f"Notes: {kev.get('notes')}")
                
                doc = {
                    'id': f"KEV-{cve_id}",
                    'title': f"Known Exploited Vulnerability - {cve_id}",
                    'content': "\n".join(content_parts),
                    'source': 'CISA KEV',
                    'document_type': 'KEV',
                    'cve_refs': [cve_id],
                    'severity': 'Critical',
                    'tags': ['exploited', 'critical', 'kev', 'cisa']
                }
                enhanced_docs.append(doc)
        
        logger.info(f"Created {len(enhanced_docs)} enhanced documents")
        return enhanced_docs
    
    def _extract_tags_from_cve(self, cve: Dict) -> List[str]:
        """Extract relevant tags from CVE data"""
        tags = []
        
        # Add severity tag (handle None values)
        severity = cve.get('severity')
        if severity:
            tags.append(severity.lower())
        
        # Add CWE-based tags
        cwe_ids = cve.get('cwe_ids', [])
        for cwe_id in cwe_ids:
            if '787' in cwe_id:  # Out-of-bounds Write
                tags.extend(['buffer_overflow', 'memory_corruption'])
            elif '125' in cwe_id:  # Out-of-bounds Read
                tags.extend(['buffer_overflow', 'information_disclosure'])
            elif '89' in cwe_id:  # SQL Injection
                tags.extend(['sql_injection', 'database'])
            elif '79' in cwe_id:  # XSS
                tags.extend(['xss', 'cross_site_scripting'])
            elif '352' in cwe_id:  # CSRF
                tags.extend(['csrf', 'cross_site_request_forgery'])
        
        # Add product-based tags
        affected_products = cve.get('affected_products', [])
        for product in affected_products:
            product_lower = product.lower()
            if 'web' in product_lower or 'server' in product_lower:
                tags.append('web_application')
            elif 'database' in product_lower or 'sql' in product_lower:
                tags.append('database')
            elif 'os' in product_lower or 'operating_system' in product_lower:
                tags.append('operating_system')
        
        # Add CAPEC tags
        capec_entries = cve.get('capec_entries', [])
        if capec_entries:
            tags.append('capec')
            tags.extend([f"capec_{capec.lower()}" for capec in capec_entries[:3]])  # Limit to 3
        
        # Add MITRE ATT&CK tags
        mitre_techniques = cve.get('mitre_techniques', [])
        mitre_tactics = cve.get('mitre_tactics', [])
        if mitre_techniques:
            tags.append('mitre_attack')
            tags.extend([f"technique_{tech.lower()}" for tech in mitre_techniques[:3]])  # Limit to 3
        if mitre_tactics:
            tags.extend([f"tactic_{tactic.lower()}" for tactic in mitre_tactics[:3]])  # Limit to 3
        
        # Add KEV tag
        if cve.get('is_in_kev'):
            tags.extend(['kev', 'exploited', 'critical'])
        
        return list(set(tags))  # Remove duplicates
    

    def save_processed_data(self, enhanced_docs: List[Dict]):
        """Save processed data by year in both knowledge_base and CVE/processed directories"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Group documents by year
        docs_by_year = {}
        for doc in enhanced_docs:
            if doc['document_type'] == 'CVE':
                # Extract year from CVE ID (e.g., CVE-2024-1234 -> 2024)
                cve_id = doc['id']
                if cve_id.startswith('CVE-'):
                    try:
                        year = cve_id.split('-')[1]
                        if year not in docs_by_year:
                            docs_by_year[year] = []
                        docs_by_year[year].append(doc)
                    except (IndexError, ValueError):
                        # If we can't parse the year, put in 'unknown' category
                        if 'unknown' not in docs_by_year:
                            docs_by_year['unknown'] = []
                        docs_by_year['unknown'].append(doc)
            else:
                # Non-CVE documents (KEV, etc.) go to 'other' category
                if 'other' not in docs_by_year:
                    docs_by_year['other'] = []
                docs_by_year['other'].append(doc)
        
        # Save by year in both locations
        knowledge_base_dir = self.config.knowledge_base_dir
        knowledge_base_dir.mkdir(parents=True, exist_ok=True)
        
        total_saved = 0
        
        for year, year_docs in docs_by_year.items():
            if not year_docs:
                continue
                
            # Save to knowledge_base directory
            kb_file = knowledge_base_dir / f"enhanced_documents_cve_{year}.json"
            with open(kb_file, 'w', encoding='utf-8') as f:
                json.dump(year_docs, f, indent=2, ensure_ascii=False)
            
            # Save to CVE/processed directory
            processed_file = self.processed_dir / f"enhanced_documents_cve_{year}.json"
            with open(processed_file, 'w', encoding='utf-8') as f:
                json.dump(year_docs, f, indent=2, ensure_ascii=False)
            
            total_saved += len(year_docs)
            logger.info(f"Saved {len(year_docs)} documents for year {year}")
        
        # Also save complete dataset with timestamp
        docs_file = self.processed_dir / f"enhanced_documents_{timestamp}.json"
        with open(docs_file, 'w', encoding='utf-8') as f:
            json.dump(enhanced_docs, f, indent=2, ensure_ascii=False)
        
        # Calculate correlation statistics
        kev_count = sum(1 for cve in self.all_cves if cve.get('is_in_kev'))
        csaf_correlations = sum(len(cve.get('csaf_correlations', [])) for cve in self.all_cves)
        exploitdb_correlations = sum(len(cve.get('exploitdb_correlations', [])) for cve in self.all_cves)
        cwe_with_mapping = sum(1 for cve in self.all_cves if any(cwe in self.cwe_capec_mitre_mapping for cwe in cve.get('cwe_ids', [])))
        capec_enriched = sum(1 for cve in self.all_cves if cve.get('capec_entries'))
        mitre_enriched = sum(1 for cve in self.all_cves if cve.get('mitre_techniques'))
        total_capec_entries = sum(len(cve.get('capec_entries', [])) for cve in self.all_cves)
        total_mitre_techniques = sum(len(cve.get('mitre_techniques', [])) for cve in self.all_cves)
        total_mitre_tactics = sum(len(cve.get('mitre_tactics', [])) for cve in self.all_cves)
        
        # Save summary
        summary = {
            'timestamp': timestamp,
            'total_cves_processed': len(self.all_cves),
            'total_kev_entries': len(self.kev_data),
            'total_enhanced_documents': len(enhanced_docs),
            'cve_documents': len([d for d in enhanced_docs if d['document_type'] == 'CVE']),
            'kev_documents': len([d for d in enhanced_docs if d['document_type'] == 'KEV']),
            'documents_by_year': {year: len(docs) for year, docs in docs_by_year.items()},
            'correlation_statistics': {
                'cves_in_kev': kev_count,
                'total_csaf_correlations': csaf_correlations,
                'total_exploitdb_correlations': exploitdb_correlations,
                'cves_with_cwe_mapping': cwe_with_mapping,
                'cwe_capec_mitre_mappings_loaded': len(self.cwe_capec_mitre_mapping),
                'cves_with_capec': capec_enriched,
                'cves_with_mitre_techniques': mitre_enriched,
                'total_capec_entries': total_capec_entries,
                'total_mitre_techniques': total_mitre_techniques,
                'total_mitre_tactics': total_mitre_tactics
            },
            'files': {
                'enhanced_documents_timestamped': str(docs_file),
                'knowledge_base_directory': str(knowledge_base_dir),
                'processed_directory': str(self.processed_dir)
            }
        }
        
        summary_file = self.processed_dir / f"processing_summary_{timestamp}.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Processed data saved to {self.processed_dir} and {knowledge_base_dir}")
        logger.info(f"Summary: {len(self.all_cves)} CVEs, {len(self.kev_data)} KEV entries, {len(enhanced_docs)} enhanced documents")
        logger.info(f"Correlations: {kev_count} CVEs in KEV, {csaf_correlations} CSAF correlations, {exploitdb_correlations} ExploitDB correlations")
        logger.info(f"CWE-CAPEC-MITRE: {capec_enriched} CVEs with CAPEC, {mitre_enriched} CVEs with MITRE techniques")
        logger.info(f"Total enrichments: {total_capec_entries} CAPEC entries, {total_mitre_techniques} MITRE techniques, {total_mitre_tactics} MITRE tactics")
        logger.info(f"Saved {total_saved} documents across {len(docs_by_year)} year categories")

    def run_full_processing(self, max_cves: Optional[int] = None):
        """Run the complete processing pipeline"""
        logger.info("Starting full CVE processing pipeline...")
        
        # Load CTI data first
        logger.info("Loading CTI correlation data...")
        self.load_cwe_capec_mitre_mapping()
        self.load_csaf_data()
        self.load_exploitdb_data()
        self.load_kev_data()
        
        # Process all CVE files
        self.process_all_cve_files(max_cves)
        
        # Enrich CVEs with CTI correlations
        self.all_cves = enrich_all_cves(
            self.all_cves,
            self.kev_by_cve,
            self.csaf_by_cve,
            self.exploitdb_by_cve,
            self.cwe_capec_mitre_mapping,
            logger
        )
        
        # Create enhanced documents
        enhanced_docs = self.create_enhanced_documents()
        
        # Save everything using the class method
        self.save_processed_data(enhanced_docs)
        
        logger.info("Full CVE processing completed!")

def main():
    """Main function"""
    processor = CVEProcessor()
    
    # Process all CVEs
    processor.run_full_processing(max_cves=None)

if __name__ == "__main__":
    main() 
