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
        
    def extract_zip_files(self):
        """Extract all zipped CVE files"""
        logger.info("Extracting zipped CVE files...")
        
        zip_files = list(self.zip_dir.glob("*.zip"))
        if not zip_files:
            logger.info("No zip files found to extract")
            return
        
        for zip_file in zip_files:
            logger.info(f"Extracting {zip_file.name}...")
            try:
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(self.json_dir)
                logger.info(f"Successfully extracted {zip_file.name}")
            except Exception as e:
                logger.error(f"Error extracting {zip_file.name}: {e}")
    
    def load_cwe_capec_mitre_mapping(self):
        """Load the CWE-CAPEC-MITRE mapping data"""
        mapping_file = self.cti_raw_dir / "cwe_capec_mitre_mapping.json"
        
        if not mapping_file.exists():
            logger.warning(f"Mapping file not found: {mapping_file}")
            return
        
        try:
            with open(mapping_file, 'r') as f:
                self.cwe_capec_mitre_mapping = json.load(f)
            logger.info(f"Loaded CWE-CAPEC-MITRE mapping with {len(self.cwe_capec_mitre_mapping)} entries")
        except Exception as e:
            logger.error(f"Error loading mapping file: {e}")
    
    def load_csaf_data(self):
        """Load CSAF data from processed files and create CVE-ID index"""
        csaf_dir = self.cti_docs_dir / "csaf"
        csaf_files = list(csaf_dir.glob("*.json"))
        
        # Create CVE-ID to CSAF entries mapping
        self.csaf_by_cve = {}
        
        for file in csaf_files:
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        entries = data
                    else:
                        entries = [data]
                    
                    for entry in entries:
                        # Extract CVE IDs from CSAF entry
                        cve_ids = self._extract_cve_ids_from_csaf(entry)
                        for cve_id in cve_ids:
                            if cve_id not in self.csaf_by_cve:
                                self.csaf_by_cve[cve_id] = []
                            self.csaf_by_cve[cve_id].append(entry)
                        
                        self.csaf_data.append(entry)
            except Exception as e:
                logger.error(f"Error loading CSAF file {file.name}: {e}")
        
        logger.info(f"Loaded {len(self.csaf_data)} CSAF entries with {len(self.csaf_by_cve)} CVE correlations")
    
    def load_exploitdb_data(self):
        """Load ExploitDB data from processed files and create CVE-ID index"""
        exploitdb_dir = self.cti_docs_dir / "exploitdb"
        exploitdb_files = list(exploitdb_dir.glob("*.json"))
        
        # Create CVE-ID to ExploitDB entries mapping
        self.exploitdb_by_cve = {}
        
        for file in exploitdb_files:
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        entries = data
                    else:
                        entries = [data]
                    
                    for entry in entries:
                        # Extract CVE IDs from ExploitDB entry
                        cve_ids = self._extract_cve_ids_from_exploitdb(entry)
                        for cve_id in cve_ids:
                            if cve_id not in self.exploitdb_by_cve:
                                self.exploitdb_by_cve[cve_id] = []
                            self.exploitdb_by_cve[cve_id].append(entry)
                        
                        self.exploitdb_data.append(entry)
            except Exception as e:
                logger.error(f"Error loading ExploitDB file {file.name}: {e}")
        
        logger.info(f"Loaded {len(self.exploitdb_data)} ExploitDB entries with {len(self.exploitdb_by_cve)} CVE correlations")
    
    def load_kev_data(self) -> List[Dict]:
        """Load KEV data from processed files and create CVE-ID index"""
        kev_dir = self.cti_docs_dir / "kev"
        kev_files = list(kev_dir.glob("*.json"))
        
        # Create CVE-ID to KEV entries mapping
        self.kev_by_cve = {}
        
        for file in kev_files:
            try:
                with open(file, 'r') as f:
                    entry = json.load(f)
                    
                    # Extract CVE ID from the entry
                    cve_id = entry.get('id', '')
                    if cve_id and cve_id.startswith('CVE-'):
                        # Store the full entry
                        self.kev_by_cve[cve_id] = entry
                        self.kev_data.append(entry)
            except Exception as e:
                logger.error(f"Error loading KEV file {file.name}: {e}")
        
        logger.info(f"Loaded {len(self.kev_data)} KEV entries")
        return self.kev_data
    
    def _extract_cve_ids_from_csaf(self, csaf_entry: Dict) -> List[str]:
        """Extract CVE IDs from CSAF entry"""
        cve_ids = []
        
        # Check common CSAF fields for CVE references
        vulnerabilities = csaf_entry.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve', '')
            if cve_id and cve_id.startswith('CVE-'):
                cve_ids.append(cve_id)
        
        # Also check other possible fields
        for key, value in csaf_entry.items():
            if isinstance(value, str) and 'CVE-' in value:
                # Extract CVE IDs from string
                import re
                cve_matches = re.findall(r'CVE-\d{4}-\d+', value)
                cve_ids.extend(cve_matches)
        
        return list(set(cve_ids))  # Remove duplicates
    
    def _extract_cve_ids_from_exploitdb(self, exploit_entry: Dict) -> List[str]:
        """Extract CVE IDs from ExploitDB entry"""
        cve_ids = []
        
        # Check for cve_refs field (primary field for CVE references)
        cve_refs = exploit_entry.get('cve_refs', [])
        if isinstance(cve_refs, list):
            cve_ids.extend([ref for ref in cve_refs if ref.startswith('CVE-')])
        
        # Also check for cve_id field (fallback)
        cve_id = exploit_entry.get('cve_id', '')
        if cve_id and cve_id.startswith('CVE-'):
            cve_ids.append(cve_id)
        
        # Check content field for CVE references
        content = exploit_entry.get('content', '')
        if content:
            import re
            cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
            cve_ids.extend(cve_matches)
        
        # Check codes field for CVE references
        codes = exploit_entry.get('codes', '')
        if codes:
            import re
            cve_matches = re.findall(r'CVE-\d{4}-\d+', codes)
            cve_ids.extend(cve_matches)
        
        return list(set(cve_ids))  # Remove duplicates
    
    def enrich_cve_with_cti(self, cve: Dict) -> Dict:
        """Enrich CVE with CWE-CAPEC-MITRE correlations and other CTI data"""
        enriched_cve = cve.copy()
        cve_id = cve.get('cve_id', '')
        
        # Get CWE IDs from the CVE (already available)
        cwe_ids = cve.get('cwe_ids', [])
        
        # Enrich with CWE-CAPEC-MITRE mapping (fast lookup)
        capec_refs = []
        mitre_techniques = []
        
        for cwe_id in cwe_ids:
            if cwe_id in self.cwe_capec_mitre_mapping:
                mapping = self.cwe_capec_mitre_mapping[cwe_id]
                capec_refs.extend(mapping.get('capecs', []))
                mitre_techniques.extend(mapping.get('mitre_techniques', []))
        
        # Remove duplicates
        capec_refs = list(set(capec_refs))
        mitre_techniques = list(set(mitre_techniques))
        
        # Add to enriched CVE
        enriched_cve['capec_refs'] = capec_refs
        enriched_cve['mitre_techniques'] = mitre_techniques
        
        # Fast CVE-ID based correlations (O(1) lookup)
        csaf_correlations = self.csaf_by_cve.get(cve_id, [])
        exploitdb_correlations = self.exploitdb_by_cve.get(cve_id, [])
        
        enriched_cve['csaf_correlations'] = csaf_correlations
        enriched_cve['exploitdb_correlations'] = exploitdb_correlations
        enriched_cve['is_in_kev'] = cve_id in self.kev_by_cve
        
        # Extract IDs from correlations
        enriched_cve['csaf_ids'] = self._extract_csaf_ids(csaf_correlations)
        enriched_cve['exploitdb_ids'] = self._extract_exploitdb_ids(exploitdb_correlations)
        
        return enriched_cve
    
    def _extract_csaf_ids(self, csaf_correlations: List[Dict]) -> List[str]:
        """Extract CSAF IDs from correlation entries"""
        csaf_ids = []
        for entry in csaf_correlations:
            # Try different possible ID fields
            csaf_id = entry.get('id') or entry.get('csaf_id') or entry.get('advisory_id')
            if csaf_id:
                csaf_ids.append(str(csaf_id))
        return list(set(csaf_ids))  # Remove duplicates
    
    def _extract_exploitdb_ids(self, exploitdb_correlations: List[Dict]) -> List[str]:
        """Extract ExploitDB IDs from correlation entries"""
        exploit_ids = []
        for entry in exploitdb_correlations:
            # Try different possible ID fields
            exploit_id = entry.get('id') or entry.get('exploit_id') or entry.get('edb_id')
            if exploit_id:
                exploit_ids.append(str(exploit_id))
        return list(set(exploit_ids))  # Remove duplicates
    
    def filter_rejected_cves(self, cves: List[Dict]) -> List[Dict]:
        """Filter out rejected CVEs based on description content"""
        logger.info("Filtering out rejected CVEs...")
        
        original_count = len(cves)
        filtered_cves = []
        rejected_count = 0
        
        for cve in cves:
            description = cve.get('description', '').lower()
            
            # Check for rejection indicators
            rejection_indicators = [
                'rejected reason',
                'rejected:',
                'rejection reason',
                'this cve has been rejected',
                'cve rejected',
                'rejected cve',
                'not a vulnerability',
                'duplicate of',
                'duplicate cve',
                'withdrawn',
                'withdrawal reason'
            ]
            
            is_rejected = any(indicator in description for indicator in rejection_indicators)
            
            if is_rejected:
                rejected_count += 1
                logger.debug(f"Rejected CVE: {cve.get('cve_id', 'Unknown')} - {description[:100]}...")
            else:
                filtered_cves.append(cve)
        
        logger.info(f"Filtered out {rejected_count} rejected CVEs ({original_count - rejected_count} remaining)")
        return filtered_cves
    
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
        self.all_cves = self.filter_rejected_cves(self.all_cves)
        
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
                cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
                
                if cve_id:
                    processed_cve = self._process_v1_cve(cve_data)
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
                cve_id = cve_data.get('id', '')
                
                if cve_id:
                    processed_cve = self._process_v2_cve(cve_data)
                    if processed_cve:
                        processed_cves.append(processed_cve)
            
            return processed_cves
            
        except Exception as e:
            logger.error(f"Error processing {json_file.name}: {e}")
            return []
    
    def _process_v1_cve(self, cve_data: Dict) -> Optional[Dict]:
        """Process a single v1.1 CVE"""
        try:
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            # Get description
            description_data = cve_data.get('description', {}).get('description_data', [])
            description = ""
            for desc in description_data:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS scores and vectors with version information
            impact = cve_data.get('impact', {})
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
            
            # Get CPE configurations (detailed)
            configurations = cve_data.get('configurations', {}).get('nodes', [])
            cpe_configurations = []
            affected_products = []
            
            for config in configurations:
                config_entry = {
                    'operator': config.get('operator', ''),
                    'cpe_match': []
                }
                
                for cpe_match in config.get('cpe_match', []):
                    cpe = cpe_match.get('cpe23Uri', '')
                    if cpe:
                        # Parse CPE to extract product information
                        parts = cpe.split(':')
                        if len(parts) >= 5:
                            affected_products.append(parts[4])
                        
                        config_entry['cpe_match'].append({
                            'cpe23Uri': cpe,
                            'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                            'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                            'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                            'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                            'vulnerable': cpe_match.get('vulnerable', True)
                        })
                
                if config_entry['cpe_match']:
                    cpe_configurations.append(config_entry)
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3': {
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
                },
                'cvss_v2': {
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
                },
                'cwe_ids': list(set(cwe_ids)),
                'affected_products': list(set(affected_products)),
                'cpe_configurations': cpe_configurations,
                'references': ref_urls,
                'published_date': cve_data.get('publishedDate', ''),
                'last_modified_date': cve_data.get('lastModifiedDate', ''),
                'source': 'NVD v1.1'
            }
            
        except Exception as e:
            logger.error(f"Error processing v1 CVE: {e}")
            return None
    
    def _process_v2_cve(self, cve_data: Dict) -> Optional[Dict]:
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
            
            # Get CPE configurations (detailed)
            configurations = cve_data.get('configurations', [])
            cpe_configurations = []
            affected_products = []
            
            for config in configurations:
                for node in config.get('nodes', []):
                    config_entry = {
                        'operator': node.get('operator', ''),
                        'negate': node.get('negate', False),
                        'cpe_match': []
                    }
                    
                    for cpe_match in node.get('cpeMatch', []):
                        cpe = cpe_match.get('criteria', '')  # v2.0 uses 'criteria' instead of 'cpe23Uri'
                        if cpe:
                            # Parse CPE to extract product information
                            parts = cpe.split(':')
                            if len(parts) >= 5:
                                affected_products.append(parts[4])
                            
                            config_entry['cpe_match'].append({
                                'cpe23Uri': cpe,  # Keep consistent field name
                                'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                                'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                'vulnerable': cpe_match.get('vulnerable', True),
                                'matchCriteriaId': cpe_match.get('matchCriteriaId')  # v2.0 specific
                            })
                    
                    if config_entry['cpe_match']:
                        cpe_configurations.append(config_entry)
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'cwe_ids': list(set(cwe_ids)),
                'affected_products': list(set(affected_products)),
                'cpe_configurations': cpe_configurations,
                'references': ref_urls,
                'published_date': cve_data.get('published', ''),
                'last_modified_date': cve_data.get('lastModified', ''),
                'source': 'NVD v2.0'
            }
            
        except Exception as e:
            logger.error(f"Error processing v2 CVE: {e}")
            return None
    
    def enrich_all_cves(self):
        """Enrich all CVEs with CTI correlations using efficient indexing"""
        logger.info("Enriching CVEs with CTI correlations...")
        
        # Load all CTI data first (creates indexes)
        self.load_cwe_capec_mitre_mapping()
        self.load_kev_data()
        self.load_csaf_data()
        self.load_exploitdb_data()
        
        # Enrich each CVE (now very fast with indexed lookups)
        enriched_cves = []
        for i, cve in enumerate(self.all_cves):
            if i % 1000 == 0:
                logger.info(f"Enriching CVE {i+1}/{len(self.all_cves)}")
            
            enriched_cve = self.enrich_cve_with_cti(cve)
            enriched_cves.append(enriched_cve)
        
        self.all_cves = enriched_cves
        logger.info(f"Enriched {len(self.all_cves)} CVEs with CTI correlations")
    
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
            capec_refs = cve.get('capec_refs', [])
            if capec_refs:
                content_parts.append(f"Related CAPECs: {', '.join(capec_refs[:3])}")  # Limit to 3
            
            # Add MITRE ATT&CK techniques
            mitre_techniques = cve.get('mitre_techniques', [])
            if mitre_techniques:
                content_parts.append(f"MITRE ATT&CK Techniques: {', '.join(mitre_techniques[:3])}")  # Limit to 3
            
            # Add correlation information
            if cve.get('is_in_kev'):
                content_parts.append("⚠️ This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog")
            
            csaf_ids = cve.get('csaf_ids', [])
            if csaf_ids:
                content_parts.append(f"📋 CSAF Advisories: {', '.join(csaf_ids[:3])}")  # Limit to 3
            
            exploitdb_ids = cve.get('exploitdb_ids', [])
            if exploitdb_ids:
                content_parts.append(f"🔧 ExploitDB IDs: {', '.join(exploitdb_ids[:3])}")  # Limit to 3
            
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
                'capec_refs': capec_refs,
                'mitre_techniques': mitre_techniques,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'affected_products': affected_products,
                'cpe_configurations': cve.get('cpe_configurations', []),
                'published_date': cve.get('published_date', ''),
                'last_modified_date': cve.get('last_modified_date', ''),
                'is_in_kev': cve.get('is_in_kev', False),
                'csaf_correlations_count': len(cve.get('csaf_correlations', [])),
                'csaf_ids': csaf_ids,
                'exploitdb_correlations_count': len(cve.get('exploitdb_correlations', [])),
                'exploitdb_ids': exploitdb_ids,
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
        
        return list(set(tags))  # Remove duplicates
    
    def save_processed_data(self, enhanced_docs: List[Dict]):
        """Save processed data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save enhanced documents with timestamp
        docs_file = self.processed_dir / f"enhanced_documents_{timestamp}.json"
        with open(docs_file, 'w') as f:
            json.dump(enhanced_docs, f, indent=2)
        
        # Also save with the expected filename for CPE extraction
        expected_filename = self.processed_dir / "enhanced_documents_cve_2024.json"
        with open(expected_filename, 'w') as f:
            json.dump(enhanced_docs, f, indent=2)
        
        # Calculate correlation statistics
        kev_count = sum(1 for cve in self.all_cves if cve.get('is_in_kev'))
        csaf_correlations = sum(len(cve.get('csaf_correlations', [])) for cve in self.all_cves)
        exploitdb_correlations = sum(len(cve.get('exploitdb_correlations', [])) for cve in self.all_cves)
        cwe_with_mapping = sum(1 for cve in self.all_cves if any(cwe in self.cwe_capec_mitre_mapping for cwe in cve.get('cwe_ids', [])))
        
        # Save summary
        summary = {
            'timestamp': timestamp,
            'total_cves_processed': len(self.all_cves),
            'total_kev_entries': len(self.kev_data),
            'total_enhanced_documents': len(enhanced_docs),
            'cve_documents': len([d for d in enhanced_docs if d['document_type'] == 'CVE']),
            'kev_documents': len([d for d in enhanced_docs if d['document_type'] == 'KEV']),
            'correlation_statistics': {
                'cves_in_kev': kev_count,
                'total_csaf_correlations': csaf_correlations,
                'total_exploitdb_correlations': exploitdb_correlations,
                'cves_with_cwe_mapping': cwe_with_mapping,
                'cwe_capec_mitre_mappings_loaded': len(self.cwe_capec_mitre_mapping)
            },
            'files': {
                'enhanced_documents': str(docs_file),
                'enhanced_documents_cve_2024': str(expected_filename)
            }
        }
        
        summary_file = self.processed_dir / f"processing_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Processed data saved to {self.processed_dir}")
        logger.info(f"Summary: {len(self.all_cves)} CVEs, {len(self.kev_data)} KEV entries, {len(enhanced_docs)} enhanced documents")
        logger.info(f"Correlations: {kev_count} CVEs in KEV, {csaf_correlations} CSAF correlations, {exploitdb_correlations} ExploitDB correlations")
    
    def run_full_processing(self, max_cves: Optional[int] = None):
        """Run the complete processing pipeline"""
        logger.info("Starting full CVE processing pipeline...")
        
        # Process all CVE files
        self.process_all_cve_files(max_cves)
        
        # Enrich CVEs with CTI correlations
        self.enrich_all_cves()
        
        # Create enhanced documents
        enhanced_docs = self.create_enhanced_documents()
        
        # Save everything
        self.save_processed_data(enhanced_docs)
        
        logger.info("Full CVE processing completed!")

def main():
    """Main function"""
    processor = CVEProcessor()
    
    # Process all CVEs
    processor.run_full_processing(max_cves=None)

if __name__ == "__main__":
    main() 
