import json
import sys
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.constructors.cpe_parser_system import ProductExtractor
from tqdm import tqdm
from config import Config

def cpecomponent_to_dict(obj):
    if hasattr(obj, '__dict__'):
        return {k: cpecomponent_to_dict(v) for k, v in obj.__dict__.items()}
    if isinstance(obj, dict):
        return {k: cpecomponent_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [cpecomponent_to_dict(i) for i in obj]
    return obj

config = Config()
KNOWLEDGE_BASE_DIR = config.knowledge_base_dir
OUTPUT_FILE = config.knowledge_base_dir / 'cpe_parsing_results_full.json'


def load_all_cves_from_year_files(knowledge_base_dir):
    """Load CVEs from all year-based files in the knowledge base directory"""
    all_cve_docs = []
    
    # Find all year-based CVE files
    cve_files = list(knowledge_base_dir.glob("enhanced_documents_cve_*.json"))
    cve_files.sort()  # Sort to process in chronological order
    
    print(f"Found {len(cve_files)} year-based CVE files:")
    for file in cve_files:
        print(f"  - {file.name}")
    
    for file in cve_files:
        print(f"Loading CVEs from {file.name}...")
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Filter for CVE documents only
            cve_docs = [doc for doc in data if doc.get('document_type') == 'CVE']
            print(f"  Loaded {len(cve_docs)} CVEs from {file.name}")
            
            # Extract only id and cpe_configurations fields (mapped to 'configurations' for compatibility)
            for doc in cve_docs:
                all_cve_docs.append({
                    'id': doc.get('id'),
                    'configurations': doc.get('cpe_configurations', {})
                })
                
        except Exception as e:
            print(f"Error loading {file.name}: {e}")
            continue
    
    print(f"Total CVEs loaded: {len(all_cve_docs)}")
    return all_cve_docs


def main():
    print(f"Loading all CVEs from year-based files in {KNOWLEDGE_BASE_DIR}...")
    cve_sample = load_all_cves_from_year_files(KNOWLEDGE_BASE_DIR)
    
    if not cve_sample:
        print("No CVEs found! Please run the CVE processor first to generate the year-based files.")
        return
    
    print(f"Loaded {len(cve_sample)} CVEs. Running CPE parser with progress bar...")
    
    # Show a sample of CVE data structure for verification
    if cve_sample:
        sample_cve = cve_sample[0]
        print(f"\nSample CVE structure:")
        print(f"  ID: {sample_cve['id']}")
        print(f"  Configurations type: {type(sample_cve['configurations'])}")
        if isinstance(sample_cve['configurations'], list):
            print(f"  Number of configuration groups: {len(sample_cve['configurations'])}")
            if sample_cve['configurations']:
                first_config = sample_cve['configurations'][0]
                print(f"  First config keys: {list(first_config.keys())}")
                if 'cpe_match' in first_config:
                    print(f"  Number of CPE matches: {len(first_config['cpe_match'])}")
                    if first_config['cpe_match']:
                        print(f"  Sample CPE: {first_config['cpe_match'][0].get('cpe23Uri', 'N/A')}")
    
    extractor = ProductExtractor()

    # Patch the extract_products_from_cve_data to use tqdm
    orig_method = extractor.extract_products_from_cve_data
    def extract_with_progress(cve_data):
        products = {}
        vendors = {}
        product_vulnerabilities = {}
        vendor_vulnerabilities = {}
        skipped = []
        # Use tqdm for progress bar
        for cve in tqdm(cve_data, desc="Processing CVEs"):
            # Use the original logic
            res = orig_method([cve])
            # Merge results
            for k, v in res['products'].items():
                if k not in products:
                    products[k] = v
            for k, v in res['vendors'].items():
                if k not in vendors:
                    vendors[k] = v
            for k, v in res['product_vulnerabilities'].items():
                if k not in product_vulnerabilities:
                    product_vulnerabilities[k] = v
                else:
                    product_vulnerabilities[k].extend(v)
            for k, v in res['vendor_vulnerabilities'].items():
                if k not in vendor_vulnerabilities:
                    vendor_vulnerabilities[k] = v
                else:
                    vendor_vulnerabilities[k].extend(v)
            skipped.extend(res['skipped_cves_no_cpe'])
        return {
            'products': products,
            'vendors': vendors,
            'product_vulnerabilities': product_vulnerabilities,
            'vendor_vulnerabilities': vendor_vulnerabilities,
            'skipped_cves_no_cpe': skipped
        }

    results = extract_with_progress(cve_sample)
    print(f"Extracted {len(results['products'])} products and {len(results['vendors'])} vendors.")
    # Print a few sample products for inspection
    print("\nSample products:")
    for i, (product_key, product) in enumerate(results['products'].items()):
        if i >= 5:
            break
        print(f"- {product_key}: {product['display_name']} (Vulns: {product['vulnerability_count']})")
    # Print a few sample vendors for inspection
    print("\nSample vendors:")
    for i, (vendor_key, vendor) in enumerate(results['vendors'].items()):
        if i >= 5:
            break
        print(f"- {vendor_key}: {vendor['display_name']} (Vulns: {vendor['vulnerability_count']})")
    # Print skipped CVEs
    print(f"\nSkipped {len(results['skipped_cves_no_cpe'])} CVEs with no valid CPEs.")
    if results['skipped_cves_no_cpe']:
        print("Sample skipped CVE IDs:", results['skipped_cves_no_cpe'][:5])
    # Save results to file (convert CPEComponent to dict)
    results_serializable = cpecomponent_to_dict(results)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(results_serializable, f, indent=2)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main() 