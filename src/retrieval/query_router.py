"""
Query router for classifying and processing different types of queries
"""

import re
import logging
from typing import Tuple, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)

class QueryType(Enum):
    CVE_LOOKUP = "cve_lookup"
    VENDOR_ANALYSIS = "vendor_analysis"
    SIMILARITY_SEARCH = "similarity_search"
    TEMPORAL_QUERY = "temporal_query"
    GENERAL = "general"

class QueryRouter:
    """Routes and classifies queries for optimal processing"""
    
    def __init__(self):
        # CVE ID pattern
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
        # Vendor keywords (common vendors in cybersecurity)
        self.vendor_keywords = [
            'microsoft', 'apache', 'cisco', 'oracle', 'adobe', 'google', 'apple',
            'mozilla', 'intel', 'amd', 'nvidia', 'qualcomm', 'samsung', 'huawei',
            'dell', 'hp', 'lenovo', 'ibm', 'vmware', 'red hat', 'canonical',
            'ubuntu', 'debian', 'centos', 'amazon', 'aws', 'azure', 'gcp'
        ]
        
        # Temporal keywords
        self.temporal_keywords = [
            'latest', 'recent', 'new', '2024', '2025', 'this year', 'last year',
            'latest vulnerabilities', 'recent vulnerabilities', 'new vulnerabilities',
            'latest cves', 'recent cves', 'new cves'
        ]
        
        # Similarity keywords
        self.similarity_keywords = [
            'similar', 'like', 'related', 'same', 'equivalent', 'comparable',
            'similar vulnerabilities', 'similar cves', 'related vulnerabilities'
        ]
        
        # Severity keywords
        self.severity_keywords = {
            'critical': ['critical', 'severe', 'high risk', 'dangerous'],
            'high': ['high', 'important', 'significant'],
            'medium': ['medium', 'moderate', 'moderate risk'],
            'low': ['low', 'minor', 'low risk']
        }
        
        logger.info("Initialized QueryRouter")
    
    def analyze_query(self, query: str) -> Tuple[QueryType, Dict[str, Any]]:
        """Analyze query and extract entities"""
        query_lower = query.lower()
        metadata = {}
        
        # Check for CVE IDs
        cve_matches = self.cve_pattern.findall(query)
        if cve_matches:
            metadata['cve_ids'] = [cve.upper() for cve in cve_matches]
            logger.info(f"Detected CVE lookup query: {cve_matches}")
            return QueryType.CVE_LOOKUP, metadata
        
        # Check for vendor analysis
        detected_vendors = []
        for vendor in self.vendor_keywords:
            if vendor in query_lower:
                detected_vendors.append(vendor)
        
        if detected_vendors:
            metadata['vendors'] = detected_vendors
            logger.info(f"Detected vendor analysis query: {detected_vendors}")
            return QueryType.VENDOR_ANALYSIS, metadata
        
        # Check for temporal queries
        detected_temporal = []
        for temporal in self.temporal_keywords:
            if temporal in query_lower:
                detected_temporal.append(temporal)
        
        if detected_temporal:
            metadata['temporal'] = detected_temporal
            logger.info(f"Detected temporal query: {detected_temporal}")
            return QueryType.TEMPORAL_QUERY, metadata
        
        # Check for similarity keywords
        detected_similarity = []
        for similarity in self.similarity_keywords:
            if similarity in query_lower:
                detected_similarity.append(similarity)
        
        if detected_similarity:
            metadata['similarity'] = detected_similarity
            logger.info(f"Detected similarity search query: {detected_similarity}")
            return QueryType.SIMILARITY_SEARCH, metadata
        
        # Check for severity filters
        detected_severity = None
        for severity, keywords in self.severity_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    detected_severity = severity.upper()
                    break
            if detected_severity:
                break
        
        if detected_severity:
            metadata['severity'] = detected_severity
            logger.info(f"Detected severity filter: {detected_severity}")
        
        # Default to general query
        logger.info("Detected general query")
        return QueryType.GENERAL, metadata
    
    def extract_entities(self, query: str) -> Dict[str, Any]:
        """Extract entities from query for enhanced search"""
        entities = {
            'cve_ids': [],
            'vendors': [],
            'products': [],
            'severity': None,
            'years': [],
            'technologies': []
        }
        
        # Extract CVE IDs
        cve_matches = self.cve_pattern.findall(query)
        entities['cve_ids'] = [cve.upper() for cve in cve_matches]
        
        # Extract years
        year_pattern = re.compile(r'\b(20\d{2})\b')
        year_matches = year_pattern.findall(query)
        entities['years'] = year_matches
        
        # Extract vendors
        query_lower = query.lower()
        for vendor in self.vendor_keywords:
            if vendor in query_lower:
                entities['vendors'].append(vendor)
        
        # Extract severity
        for severity, keywords in self.severity_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    entities['severity'] = severity.upper()
                    break
            if entities['severity']:
                break
        
        # Extract common technologies/products
        tech_keywords = [
            'windows', 'linux', 'android', 'ios', 'macos', 'chrome', 'firefox',
            'edge', 'safari', 'wordpress', 'nginx', 'apache', 'mysql', 'postgresql',
            'mongodb', 'redis', 'docker', 'kubernetes', 'jenkins', 'gitlab',
            'jira', 'confluence', 'slack', 'teams', 'zoom', 'vpn', 'ssl', 'tls'
        ]
        
        for tech in tech_keywords:
            if tech in query_lower:
                entities['technologies'].append(tech)
        
        return entities
    
    def build_search_filters(self, query: str) -> Dict[str, Any]:
        """Build search filters based on query analysis"""
        entities = self.extract_entities(query)
        filters = {}
        
        if entities['severity']:
            filters['severity'] = entities['severity']
        
        if entities['vendors']:
            # Use the first vendor for filtering
            filters['vendors'] = {"$contains": entities['vendors'][0]}
        
        if entities['years']:
            # Could be used for date filtering in the future
            filters['year'] = entities['years'][0]
        
        return filters
    
    def get_query_suggestions(self, query: str) -> list:
        """Get query suggestions based on the current query"""
        suggestions = []
        query_lower = query.lower()
        
        # Add CVE-specific suggestions
        if 'cve' in query_lower and not self.cve_pattern.search(query):
            suggestions.append("Try searching for a specific CVE ID (e.g., CVE-2024-1234)")
        
        # Add vendor suggestions
        if any(vendor in query_lower for vendor in ['microsoft', 'windows']):
            suggestions.append("Try: 'Microsoft Exchange vulnerabilities' or 'Windows security updates'")
        
        # Add severity suggestions
        if 'critical' in query_lower or 'severe' in query_lower:
            suggestions.append("Try: 'Critical vulnerabilities 2024' or 'High severity CVEs'")
        
        # Add temporal suggestions
        if any(temporal in query_lower for temporal in ['latest', 'recent', 'new']):
            suggestions.append("Try: 'Latest vulnerabilities 2024' or 'Recent critical CVEs'")
        
        # Add technology suggestions
        if any(tech in query_lower for tech in ['web', 'application']):
            suggestions.append("Try: 'Web application vulnerabilities' or 'SQL injection CVEs'")
        
        return suggestions 