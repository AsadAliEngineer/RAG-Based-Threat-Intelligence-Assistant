import json
from pathlib import Path
from cpe_parser_system import ProductExtractor
from tqdm import tqdm

def cpecomponent_to_dict(obj):
    if hasattr(obj, '__dict__'):
        return {k: cpecomponent_to_dict(v) for k, v in obj.__dict__.items()}
    if isinstance(obj, dict):
        return {k: cpecomponent_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [cpecomponent_to_dict(i) for i in obj]
    return obj

# Path to the processed CVE dataset (adjust if needed)
CVE_FILE = Path(__file__).parent.parent.parent / 'data' / 'CVE' / 'processed' / 'enhanced_documents_cve_2024.json'
OUTPUT_FILE = Path(__file__).parent.parent.parent / 'data' / 'knowledge_base' / 'cpe_parsing_results_full.json'


def load_all_cves(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    # Filter for CVE documents only
    cve_docs = [doc for doc in data if doc.get('document_type') == 'CVE']
    # Extract only id and configurations fields
    sample = []
    for doc in cve_docs:
        sample.append({
            'id': doc.get('id'),
            'configurations': doc.get('cpe_configurations', {})
        })
    return sample


def main():
    print(f"Loading all CVEs from {CVE_FILE}...")
    cve_sample = load_all_cves(CVE_FILE)
    print(f"Loaded {len(cve_sample)} CVEs. Running CPE parser with progress bar...")
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
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results_serializable, f, indent=2)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main() 