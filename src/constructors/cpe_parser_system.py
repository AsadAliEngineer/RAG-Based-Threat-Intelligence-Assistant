# Advanced CPE Parsing and Product Extraction System

import re
import json
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from urllib.parse import unquote
import logging
from collections import defaultdict, Counter

@dataclass
class CPEComponent:
    """Individual CPE component with metadata"""
    part: str  # a, h, o (application, hardware, operating system)
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    
    # Derived metadata
    is_wildcard: bool = False
    confidence_score: float = 1.0
    normalized_vendor: str = ""
    normalized_product: str = ""

class CPEParser:
    """Advanced CPE parsing with normalization and validation"""
    
    def __init__(self):
        self.vendor_aliases = self.load_vendor_aliases()
        self.product_mappings = self.load_product_mappings()
        self.version_patterns = self.compile_version_patterns()
        self.stop_words = {'the', 'inc', 'corp', 'corporation', 'ltd', 'limited', 'llc'}
        
    def load_vendor_aliases(self) -> Dict[str, List[str]]:
        """Load vendor name aliases and variations"""
        return {
            'microsoft': ['microsoft', 'ms', 'msft', 'redmond'],
            'apache': ['apache', 'apache_software_foundation', 'asf'],
            'oracle': ['oracle', 'oracle_corporation', 'sun_microsystems'],
            'google': ['google', 'alphabet', 'google_llc'],
            'amazon': ['amazon', 'aws', 'amazon_web_services'],
            'redhat': ['redhat', 'red_hat', 'rh'],
            'canonical': ['canonical', 'ubuntu'],
            'mozilla': ['mozilla', 'mozilla_foundation'],
            'adobe': ['adobe', 'adobe_systems', 'macromedia'],
            'ibm': ['ibm', 'international_business_machines']
        }
    
    def load_product_mappings(self) -> Dict[str, Dict[str, any]]:
        """Load product metadata and categorizations"""
        return {
            'android': {
                'category': 'Mobile OS',
                'family': 'Android',
                'criticality': 9.0,
                'aliases': ['android']
            },
            'linux_kernel': {
                'category': 'Operating System',
                'family': 'Linux',
                'criticality': 8.5,
                'aliases': ['linux_kernel', 'linux', 'gnu_linux']
            },
            'junos': {
                'category': 'Network OS',
                'family': 'Juniper Junos',
                'criticality': 8.0,
                'aliases': ['junos', 'juniper_junos']
            },
            'commerce': {
                'category': 'E-commerce',
                'family': 'Adobe Commerce',
                'criticality': 8.0,
                'aliases': ['commerce', 'adobe_commerce', 'magento_commerce']
            },
            'checkmk': {
                'category': 'Monitoring',
                'family': 'Checkmk',
                'criticality': 7.5,
                'aliases': ['checkmk']
            },
            'ios': {
                'category': 'Network OS',
                'family': 'Cisco IOS',
                'criticality': 8.5,
                'aliases': ['ios', 'cisco_ios']
            },
            'junos_os_evolved': {
                'category': 'Network OS',
                'family': 'Juniper Junos OS Evolved',
                'criticality': 8.0,
                'aliases': ['junos_os_evolved', 'juniper_junos_os_evolved']
            },
            'ios_xe': {
                'category': 'Network OS',
                'family': 'Cisco IOS XE',
                'criticality': 8.5,
                'aliases': ['ios_xe', 'cisco_ios_xe']
            },
            'adaptive_security_appliance_software': {
                'category': 'Security Appliance',
                'family': 'Cisco ASA',
                'criticality': 8.5,
                'aliases': ['adaptive_security_appliance_software', 'cisco_asa']
            },
            'magento': {
                'category': 'E-commerce',
                'family': 'Adobe Magento',
                'criticality': 8.0,
                'aliases': ['magento', 'adobe_magento']
            },
            'digital_experience_platform': {
                'category': 'Portal',
                'family': 'Liferay DXP',
                'criticality': 7.5,
                'aliases': ['digital_experience_platform', 'liferay_dxp']
            },
            'secure_firewall_management_center': {
                'category': 'Security Appliance',
                'family': 'Cisco Secure Firewall Management Center',
                'criticality': 8.0,
                'aliases': ['secure_firewall_management_center', 'cisco_firewall_management_center']
            },
            'windows_server_2012': {
                'category': 'Operating System',
                'family': 'Windows Server',
                'criticality': 9.0,
                'aliases': ['windows_server_2012', 'windows_server', 'microsoft_windows_server_2012']
            },
            'nx-os': {
                'category': 'Network OS',
                'family': 'Cisco NX-OS',
                'criticality': 8.0,
                'aliases': ['nx-os', 'cisco_nx-os']
            },
            'identity_services_engine': {
                'category': 'Security Appliance',
                'family': 'Cisco ISE',
                'criticality': 8.0,
                'aliases': ['identity_services_engine', 'cisco_ise']
            },
            'macos': {
                'category': 'Operating System',
                'family': 'Apple macOS',
                'criticality': 8.5,
                'aliases': ['macos', 'apple_macos', 'osx']
            },
            'windows_10_22h2': {
                'category': 'Operating System',
                'family': 'Windows 10',
                'criticality': 9.0,
                'aliases': ['windows_10_22h2', 'windows_10', 'microsoft_windows_10_22h2']
            },
            'windows_10_1809': {
                'category': 'Operating System',
                'family': 'Windows 10',
                'criticality': 9.0,
                'aliases': ['windows_10_1809', 'windows_10', 'microsoft_windows_10_1809']
            },
            'windows_server_2008': {
                'category': 'Operating System',
                'family': 'Windows Server',
                'criticality': 8.5,
                'aliases': ['windows_server_2008', 'windows_server', 'microsoft_windows_server_2008']
            },
            'windows': {
                'category': 'Operating System',
                'family': 'Windows',
                'criticality': 9.0,
                'aliases': ['windows', 'win', 'microsoft_windows']
            },
            'linux': {
                'category': 'Operating System', 
                'family': 'Linux',
                'criticality': 8.5,
                'aliases': ['linux', 'gnu_linux', 'linux_kernel']
            },
            'http_server': {
                'category': 'Web Server',
                'family': 'Apache HTTP Server', 
                'criticality': 8.0,
                'aliases': ['apache', 'httpd', 'apache_httpd']
            },
            'mysql': {
                'category': 'Database',
                'family': 'MySQL',
                'criticality': 7.5,
                'aliases': ['mysql', 'mysql_server']
            }
        }
    
    def compile_version_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for version extraction"""
        return {
            'semantic': re.compile(r'^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?'),
            'date_based': re.compile(r'^(\d{4})(?:\.(\d{2}))?(?:\.(\d{2}))?'),
            'build_number': re.compile(r'^(\d+)(?:\.(\d+))*(?:-(\w+))?'),
            'alpha_beta': re.compile(r'^(\d+\.?\d*)\s*-?\s*(alpha|beta|rc|release|final)'),
            'windows_version': re.compile(r'^(vista|xp|2000|2003|2008|2012|2016|2019|2022)'),
        }
    
    def parse_cpe23_string(self, cpe_string: str) -> Optional[CPEComponent]:
        """Parse CPE 2.3 format string"""
        try:
            if not cpe_string.startswith('cpe:2.3:'):
                return None
                
            # Remove cpe:2.3: prefix and split by colons
            components = cpe_string[9:].split(':')
            
            if len(components) < 11:
                # Pad with wildcards if insufficient components
                components.extend(['*'] * (11 - len(components)))
            
            # Decode URL encoding and handle special values
            decoded_components = []
            for comp in components[:11]:  # Only take first 11 components
                if comp == '*':
                    decoded_components.append('*')
                elif comp == '-':
                    decoded_components.append('')
                else:
                    decoded_components.append(unquote(comp))
            
            cpe_comp = CPEComponent(
                part=decoded_components[0],
                vendor=decoded_components[1],
                product=decoded_components[2], 
                version=decoded_components[3],
                update=decoded_components[4],
                edition=decoded_components[5],
                language=decoded_components[6],
                sw_edition=decoded_components[7],
                target_sw=decoded_components[8],
                target_hw=decoded_components[9],
                other=decoded_components[10]
            )
            
            # Set derived properties
            cpe_comp.is_wildcard = self.is_wildcard_cpe(cpe_comp)
            cpe_comp.normalized_vendor = self.normalize_vendor(cpe_comp.vendor)
            cpe_comp.normalized_product = self.normalize_product(cpe_comp.product)
            cpe_comp.confidence_score = self.calculate_confidence(cpe_comp)
            
            return cpe_comp
            
        except Exception as e:
            logging.error(f"Error parsing CPE {cpe_string}: {e}")
            return None
    
    def normalize_vendor(self, vendor: str) -> str:
        """Normalize vendor name using aliases"""
        if not vendor or vendor == '*':
            return vendor
            
        vendor_lower = vendor.lower().replace('_', ' ')
        
        # Remove common suffixes
        for suffix in self.stop_words:
            vendor_lower = vendor_lower.replace(f' {suffix}', '')
        
        # Check aliases
        for canonical, aliases in self.vendor_aliases.items():
            if vendor_lower in aliases:
                return canonical
                
        return vendor.lower().replace(' ', '_')
    
    def normalize_product(self, product: str) -> str:
        """Normalize product name"""
        if not product or product == '*':
            return product
            
        product_lower = product.lower().replace('_', ' ')
        
        # Handle common product name variations
        normalizations = {
            'http server': 'http_server',
            'web server': 'web_server', 
            'mysql server': 'mysql',
            'sql server': 'sql_server',
            'internet explorer': 'internet_explorer'
        }
        
        for variant, canonical in normalizations.items():
            if variant in product_lower:
                return canonical
                
        return product.lower().replace(' ', '_')
    
    def is_wildcard_cpe(self, cpe: CPEComponent) -> bool:
        """Check if CPE contains wildcards indicating generic match"""
        wildcard_fields = [cpe.vendor, cpe.product, cpe.version]
        return any(field == '*' for field in wildcard_fields)
    
    def calculate_confidence(self, cpe: CPEComponent) -> float:
        """Calculate confidence score for CPE parsing"""
        confidence = 1.0
        
        # Reduce confidence for wildcards
        if cpe.vendor == '*':
            confidence -= 0.3
        if cpe.product == '*':
            confidence -= 0.4
        if cpe.version == '*':
            confidence -= 0.2
            
        # Reduce confidence for very short/generic names
        if len(cpe.vendor) <= 2 and cpe.vendor != '*':
            confidence -= 0.1
        if len(cpe.product) <= 2 and cpe.product != '*':
            confidence -= 0.1
            
        return max(0.0, confidence)
    
    def extract_version_info(self, version_string: str) -> Dict[str, any]:
        """Extract structured version information"""
        if not version_string or version_string == '*':
            return {'raw': version_string, 'type': 'unknown'}
        
        version_info = {'raw': version_string}
        
        # Try different version patterns
        for pattern_name, pattern in self.version_patterns.items():
            match = pattern.match(version_string)
            if match:
                version_info['type'] = pattern_name
                version_info['groups'] = match.groups()
                
                if pattern_name == 'semantic':
                    version_info['major'] = int(match.group(1))
                    version_info['minor'] = int(match.group(2)) if match.group(2) else 0
                    version_info['patch'] = int(match.group(3)) if match.group(3) else 0
                    version_info['build'] = int(match.group(4)) if match.group(4) else 0
                
                break
        else:
            version_info['type'] = 'custom'
            
        return version_info

class ProductExtractor:
    """Extract and enrich product information from CVE data"""
    
    def __init__(self):
        self.cpe_parser = CPEParser()
        self.product_database = {}
        self.vendor_database = {}
        
    def extract_products_from_cve_data(self, cve_data: List[Dict]) -> Dict[str, any]:
        """Extract products and vendors from CVE data, only for valid CPEs"""
        products = {}
        vendors = {}
        product_vulnerabilities = defaultdict(list)
        vendor_vulnerabilities = defaultdict(list)
        cves_with_no_valid_cpe = []

        for cve in cve_data:
            cve_id = cve.get('id')
            configurations = cve.get('configurations', {})
            cpe_list = self.extract_cpe_from_configurations(configurations)
            valid_cpe_found = False
            for cpe_str in cpe_list:
                if not cpe_str or not isinstance(cpe_str, str) or not cpe_str.startswith('cpe:2.3:'):
                    continue  # Skip empty or malformed CPE strings
                cpe_obj = self.cpe_parser.parse_cpe23_string(cpe_str)
                if not cpe_obj:
                    continue  # Skip malformed CPEs
                valid_cpe_found = True
                product_key = f"{cpe_obj.normalized_vendor}:{cpe_obj.normalized_product}"
                print(f"[DEBUG] Creating/updating product {product_key} from CPE: {cpe_str}")
                # Create or update product record
                if product_key not in products:
                    products[product_key] = self.create_product_record(cpe_obj)
                # Add version info
                version_info = self.cpe_parser.extract_version_info(cpe_obj.version)
                self.add_version_to_product(products[product_key], version_info, cve_id)
                # Track vulnerabilities
                product_vulnerabilities[product_key].append(cve_id)
                # Create or update vendor record
                vendor_key = cpe_obj.normalized_vendor
                if vendor_key not in vendors:
                    vendors[vendor_key] = self.create_vendor_record(cpe_obj)
                if product_key not in vendors[vendor_key]['products']:
                    vendors[vendor_key]['products'].append(product_key)
                vendor_vulnerabilities[vendor_key].append(cve_id)
            if not valid_cpe_found:
                print(f"[DEBUG] Skipping CVE {cve_id}: no valid CPEs found.")
                cves_with_no_valid_cpe.append(cve_id)

        # Enrich products with vulnerability statistics
        self.enrich_products_with_stats(products, product_vulnerabilities)
        self.enrich_vendors_with_stats(vendors, vendor_vulnerabilities)

        if cves_with_no_valid_cpe:
            print(f"[INFO] Skipped {len(cves_with_no_valid_cpe)} CVEs with no valid CPEs. Example IDs: {cves_with_no_valid_cpe[:5]}")

        return {
            'products': products,
            'vendors': vendors,
            'product_vulnerabilities': dict(product_vulnerabilities),
            'vendor_vulnerabilities': dict(vendor_vulnerabilities),
            'skipped_cves_no_cpe': cves_with_no_valid_cpe
        }
    
    def extract_cpe_from_configurations(self, configurations: Dict) -> List[str]:
        """Extract CPE strings from CVE configuration data"""
        cpe_list = []
        
        def extract_recursive(config):
            if isinstance(config, dict):
                # Handle CPE match criteria
                if 'cpe_match' in config:
                    for match in config['cpe_match']:
                        if 'cpe23Uri' in match:
                            cpe_list.append(match['cpe23Uri'])
                
                # Handle nodes structure
                if 'nodes' in config:
                    for node in config['nodes']:
                        extract_recursive(node)
                
                # Handle children structure
                if 'children' in config:
                    for child in config['children']:
                        extract_recursive(child)
                        
                # Recurse into other dict values
                for value in config.values():
                    if isinstance(value, (dict, list)):
                        extract_recursive(value)
            
            elif isinstance(config, list):
                for item in config:
                    extract_recursive(item)
        
        extract_recursive(configurations)
        return list(set(cpe_list))  # Remove duplicates
    
    def create_product_record(self, cpe: CPEComponent) -> Dict[str, any]:
        """Create comprehensive product record"""
        product_meta = self.cpe_parser.product_mappings.get(
            cpe.normalized_product, 
            None
        )
        if product_meta:
            category = product_meta['category']
            family = product_meta['family']
            criticality = product_meta['criticality']
            aliases = product_meta['aliases']
        else:
            part_category = {
                'a': 'Application',
                'o': 'Operating System',
                'h': 'Hardware'
            }
            category = part_category.get(cpe.part, 'Unknown')
            family = cpe.product.title()
            criticality = 5.0
            aliases = [cpe.product]
        return {
            'vendor': cpe.normalized_vendor,
            'product': cpe.normalized_product,
            'display_name': f"{cpe.vendor} {cpe.product}",
            'category': category,
            'family': family,
            'criticality_score': criticality,
            'aliases': aliases,
            'versions': {},
            'vulnerability_count': 0,
            'critical_vulnerability_count': 0,
            'first_vulnerability_date': None,
            'latest_vulnerability_date': None,
            'cpe_patterns': [cpe]
        }
    
    def create_vendor_record(self, cpe: CPEComponent) -> Dict[str, any]:
        """Create vendor record"""
        return {
            'name': cpe.normalized_vendor,
            'display_name': cpe.vendor.title(),
            'products': [],
            'vulnerability_count': 0,
            'critical_vulnerability_count': 0,
            'aliases': self.cpe_parser.vendor_aliases.get(cpe.normalized_vendor, [cpe.vendor])
        }
    
    def add_version_to_product(self, product: Dict, version_info: Dict, cve_id: str):
        """Add version information to product record"""
        version_key = version_info['raw']
        
        if version_key not in product['versions']:
            product['versions'][version_key] = {
                'version_string': version_key,
                'version_info': version_info,
                'vulnerabilities': [],
                'vulnerability_count': 0
            }
        
        product['versions'][version_key]['vulnerabilities'].append(cve_id)
        product['versions'][version_key]['vulnerability_count'] += 1
    
    def enrich_products_with_stats(self, products: Dict, product_vulnerabilities: Dict):
        """Add vulnerability statistics to products"""
        for product_key, vuln_list in product_vulnerabilities.items():
            if product_key in products:
                products[product_key]['vulnerability_count'] = len(vuln_list)
                # Additional enrichment would require CVE severity data
    
    def enrich_vendors_with_stats(self, vendors: Dict, vendor_vulnerabilities: Dict):
        """Add vulnerability statistics to vendors"""
        for vendor_key, vuln_list in vendor_vulnerabilities.items():
            if vendor_key in vendors:
                vendors[vendor_key]['vulnerability_count'] = len(vuln_list)
    
    def generate_product_hierarchy(self, products: Dict) -> Dict[str, any]:
        """Generate hierarchical product structure"""
        hierarchy = {
            'vendors': {},
            'categories': defaultdict(list),
            'families': defaultdict(list)
        }
        
        for product_key, product in products.items():
            vendor = product['vendor']
            category = product['category']
            family = product['family']
            
            # Vendor hierarchy
            if vendor not in hierarchy['vendors']:
                hierarchy['vendors'][vendor] = {
                    'products': [],
                    'total_vulnerabilities': 0
                }
            
            hierarchy['vendors'][vendor]['products'].append(product_key)
            hierarchy['vendors'][vendor]['total_vulnerabilities'] += product['vulnerability_count']
            
            # Category grouping
            hierarchy['categories'][category].append(product_key)
            
            # Family grouping  
            hierarchy['families'][family].append(product_key)
        
        return hierarchy

# Example usage and testing
def main():
    """Test the CPE parsing and product extraction system"""
    
    # Sample CVE data
    sample_cve_data = [
        {
            'id': 'CVE-2023-12345',
            'configurations': {
                'nodes': [
                    {
                        'cpe_match': [
                            {'cpe23Uri': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'},
                            {'cpe23Uri': 'cpe:2.3:a:apache:http_server:2.4.42:*:*:*:*:*:*:*'}
                        ]
                    }
                ]
            }
        },
        {
            'id': 'CVE-2023-67890', 
            'configurations': {
                'nodes': [
                    {
                        'cpe_match': [
                            {'cpe23Uri': 'cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*'},
                            {'cpe23Uri': 'cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*'}
                        ]
                    }
                ]
            }
        }
    ]
    
    # Initialize extractor
    extractor = ProductExtractor()
    
    # Extract products
    results = extractor.extract_products_from_cve_data(sample_cve_data)
    
    print("Extracted Products:")
    for product_key, product in results['products'].items():
        print(f"  {product_key}: {product['display_name']} ({product['vulnerability_count']} vulnerabilities)")
    
    print("\nExtracted Vendors:")
    for vendor_key, vendor in results['vendors'].items():
        print(f"  {vendor_key}: {vendor['display_name']} ({vendor['vulnerability_count']} vulnerabilities)")
    
    # Generate hierarchy
    hierarchy = extractor.generate_product_hierarchy(results['products'])
    
    print("\nProduct Hierarchy by Category:")
    for category, products in hierarchy['categories'].items():
        print(f"  {category}: {len(products)} products")

if __name__ == "__main__":
    main()