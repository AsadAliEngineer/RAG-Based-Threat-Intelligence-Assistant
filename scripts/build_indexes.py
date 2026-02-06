# scripts/build_indexes.py
"""
Build complete indexes for all CVE data (2002-2025)
Run this script once to pre-build all indexes for fast API startup
"""

import sys
import os
import time
import json
import pickle
import logging
from datetime import datetime
from typing import Dict, List, Set

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('build_indexes.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IndexBuilder:
    """Dedicated index builder for preprocessing all CVE data"""

    def __init__(self, base_path: str = 'data/knowledge_base'):
        self.base_path = base_path
        self.start_year = 2002
        self.end_year = 2025

        # Index structures
        self.cve_index = {}  # cve_id -> document
        self.keyword_index = {}  # keyword -> set of cve_ids
        self.year_index = {}  # year -> set of cve_ids
        self.severity_index = {}  # severity -> set of cve_ids
        self.cwe_index = {}  # cwe_id -> set of cve_ids
        self.capec_index = {}  # capec_id -> set of cve_ids
        self.mitre_tactic_index = {}  # tactic -> set of cve_ids
        self.mitre_technique_index = {}  # technique -> set of cve_ids

        # Statistics
        self.stats = {
            'total_cves': 0,
            'years_processed': [],
            'cves_per_year': {},
            'processing_time': {},
            'index_sizes': {}
        }

    def build_all_indexes(self):
        """Build indexes for all years"""
        logger.info(f"Starting index build for years {self.start_year}-{self.end_year}")
        logger.info("This process will take 10-30 minutes depending on your system")
        logger.info("-" * 60)

        overall_start = time.time()

        # Detect available years
        available_years = self._detect_available_years()
        logger.info(f"Found CVE data for {len(available_years)} years: {available_years}")

        # Process each year
        for i, year in enumerate(available_years):
            year_start = time.time()

            logger.info(f"\nProcessing year {year} ({i + 1}/{len(available_years)})...")

            try:
                cve_count = self._process_year(year)

                year_time = time.time() - year_start
                self.stats['years_processed'].append(year)
                self.stats['cves_per_year'][year] = cve_count
                self.stats['processing_time'][year] = year_time

                logger.info(f"  Processed {cve_count:,} CVEs in {year_time:.2f} seconds")

                # Show progress
                progress = (i + 1) / len(available_years) * 100
                logger.info(f"  Overall progress: {progress:.1f}%")

            except Exception as e:
                logger.error(f"  Error processing year {year}: {e}")
                continue

        # Save indexes
        logger.info("\nSaving indexes...")
        self._save_indexes()

        # Final statistics
        overall_time = time.time() - overall_start
        self._print_statistics(overall_time)

        logger.info("\nIndex building complete!")
        logger.info(f"Indexes saved to: {os.path.join(self.base_path, 'master_index_full.pkl')}")

    def _detect_available_years(self) -> List[int]:
        """Detect which years have CVE data files"""
        available_years = []

        for year in range(self.start_year, self.end_year + 1):
            file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')
            if os.path.exists(file_path):
                available_years.append(year)

        return sorted(available_years)

    def _process_year(self, year: int) -> int:
        """Process a single year of CVE data"""
        file_path = os.path.join(self.base_path, f'enhanced_documents_cve_{year}.json')

        with open(file_path, 'r', encoding='utf-8') as f:
            documents = json.load(f)

        processed = 0

        for doc in documents:
            cve_id = doc.get('id', '') or doc.get('cve_id', '')
            if not cve_id:
                continue

            # Store full document
            self.cve_index[cve_id] = doc

            # Update year index
            if year not in self.year_index:
                self.year_index[year] = set()
            self.year_index[year].add(cve_id)

            # Extract and index metadata
            self._index_document(doc, cve_id)

            processed += 1

            # Progress indicator for large years
            if processed % 5000 == 0:
                logger.info(f"    Processed {processed:,}/{len(documents):,} CVEs...")

        self.stats['total_cves'] += processed
        return processed

    def _index_document(self, doc: Dict, cve_id: str):
        """Index a single document"""
        # Severity index
        severity = (doc.get('severity', '') or 'unknown').lower()
        if severity not in self.severity_index:
            self.severity_index[severity] = set()
        self.severity_index[severity].add(cve_id)

        # CWE index
        cwe_ids = doc.get('cwe_ids', []) or []
        for cwe_id in cwe_ids:
            cwe_str = str(cwe_id)
            if cwe_str not in self.cwe_index:
                self.cwe_index[cwe_str] = set()
            self.cwe_index[cwe_str].add(cve_id)

        # CAPEC index
        capec_ids = doc.get('capec_ids', []) or []
        for capec_id in capec_ids:
            capec_str = str(capec_id)
            if capec_str not in self.capec_index:
                self.capec_index[capec_str] = set()
            self.capec_index[capec_str].add(cve_id)

        # MITRE ATT&CK indexes
        mitre_tactics = doc.get('mitre_tactics', []) or []
        for tactic in mitre_tactics:
            tactic_lower = tactic.lower()
            if tactic_lower not in self.mitre_tactic_index:
                self.mitre_tactic_index[tactic_lower] = set()
            self.mitre_tactic_index[tactic_lower].add(cve_id)

        mitre_techniques = doc.get('mitre_techniques', []) or []
        for technique in mitre_techniques:
            technique_lower = technique.lower()
            if technique_lower not in self.mitre_technique_index:
                self.mitre_technique_index[technique_lower] = set()
            self.mitre_technique_index[technique_lower].add(cve_id)

        # Keyword extraction (optimized for large dataset)
        keywords = self._extract_keywords_fast(doc)
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if keyword_lower not in self.keyword_index:
                self.keyword_index[keyword_lower] = set()
            self.keyword_index[keyword_lower].add(cve_id)

    def _extract_keywords_fast(self, doc: Dict) -> Set[str]:
        """Fast keyword extraction for large datasets"""
        keywords = set()

        # Get text fields
        description = (doc.get('description', '') or '').lower()

        # Common technology keywords (pre-defined for speed)
        tech_keywords = {
            'apache', 'nginx', 'iis', 'tomcat', 'docker', 'kubernetes',
            'windows', 'linux', 'ubuntu', 'debian', 'redhat', 'macos',
            'chrome', 'firefox', 'safari', 'edge',
            'mysql', 'postgresql', 'mongodb', 'oracle', 'redis',
            'java', 'python', 'php', 'ruby', 'javascript', 'node.js',
            'wordpress', 'drupal', 'joomla',
            'aws', 'azure', 'gcp', 'vmware',
            'cisco', 'microsoft', 'adobe', 'apple', 'google',
            'android', 'ios', 'mobile',
            '5g', '4g', 'lte', 'wifi', 'bluetooth'
        }

        # Quick keyword matching
        for keyword in tech_keywords:
            if keyword in description:
                keywords.add(keyword)

        # Vulnerability type keywords
        vuln_keywords = {
            'rce': 'remote code execution',
            'sqli': 'sql injection',
            'xss': 'cross-site scripting',
            'dos': 'denial of service',
            'privesc': 'privilege escalation',
            'overflow': 'buffer overflow'
        }

        for short, full in vuln_keywords.items():
            if full in description or short in description:
                keywords.add(short)

        # Add product names from affected_products
        affected_products = doc.get('affected_products', [])
        if affected_products:
            for product in affected_products[:5]:  # Limit to prevent explosion
                if product:
                    # Extract first word as keyword
                    words = str(product).lower().split()
                    if words and len(words[0]) > 2:
                        keywords.add(words[0])

        return keywords

    def _save_indexes(self):
        """Save all indexes to disk"""
        # Prepare data for pickling
        index_data = {
            'metadata': {
                'build_date': datetime.now().isoformat(),
                'start_year': self.start_year,
                'end_year': self.end_year,
                'total_cves': self.stats['total_cves'],
                'years_available': sorted(self.year_index.keys()),
                'index_version': '2.0'
            },
            'indexes': {
                'keyword_index': {k: list(v) for k, v in self.keyword_index.items()},
                'year_index': {k: list(v) for k, v in self.year_index.items()},
                'severity_index': {k: list(v) for k, v in self.severity_index.items()},
                'cwe_index': {k: list(v) for k, v in self.cwe_index.items()},
                'capec_index': {k: list(v) for k, v in self.capec_index.items()},
                'mitre_tactic_index': {k: list(v) for k, v in self.mitre_tactic_index.items()},
                'mitre_technique_index': {k: list(v) for k, v in self.mitre_technique_index.items()},
            },
            'cve_ids': list(self.cve_index.keys()),
            'stats': self.stats
        }

        # Calculate index sizes
        for index_name, index_data_dict in index_data['indexes'].items():
            size_bytes = sys.getsizeof(pickle.dumps(index_data_dict))
            self.stats['index_sizes'][index_name] = size_bytes / (1024 * 1024)  # MB

        # Save to file
        output_path = os.path.join(self.base_path, 'master_index_full.pkl')
        logger.info(f"Saving indexes to {output_path}...")

        with open(output_path, 'wb') as f:
            pickle.dump(index_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        # Also save a lightweight version without full documents
        output_path_light = os.path.join(self.base_path, 'master_index_light.pkl')
        with open(output_path_light, 'wb') as f:
            pickle.dump(index_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("Indexes saved successfully!")

    def _print_statistics(self, total_time: float):
        """Print final statistics"""
        logger.info("\n" + "=" * 60)
        logger.info("INDEX BUILD STATISTICS")
        logger.info("=" * 60)

        logger.info(f"\nTotal CVEs indexed: {self.stats['total_cves']:,}")
        logger.info(f"Years processed: {len(self.stats['years_processed'])}")
        logger.info(f"Total time: {total_time / 60:.2f} minutes")
        logger.info(f"Average time per CVE: {total_time / self.stats['total_cves'] * 1000:.2f} ms")

        logger.info("\nCVEs per year:")
        for year in sorted(self.stats['cves_per_year'].keys()):
            count = self.stats['cves_per_year'][year]
            time_taken = self.stats['processing_time'].get(year, 0)
            logger.info(f"  {year}: {count:,} CVEs ({time_taken:.2f}s)")

        logger.info("\nIndex sizes:")
        logger.info(f"  Keywords indexed: {len(self.keyword_index):,}")
        logger.info(f"  CWE mappings: {len(self.cwe_index):,}")
        logger.info(f"  CAPEC mappings: {len(self.capec_index):,}")
        logger.info(f"  MITRE tactics: {len(self.mitre_tactic_index):,}")
        logger.info(f"  MITRE techniques: {len(self.mitre_technique_index):,}")

        if self.stats['index_sizes']:
            logger.info("\nIndex file sizes:")
            for index_name, size_mb in self.stats['index_sizes'].items():
                logger.info(f"  {index_name}: {size_mb:.2f} MB")


def main():
    """Main entry point"""
    print("CVE Index Builder")
    print("=" * 60)
    print("This script will build complete indexes for all CVE data (2002-2025)")
    print("Expected time: 10-30 minutes depending on your system")
    print("=" * 60)

    # Ask for confirmation
    response = input("\nDo you want to continue? (yes/no): ").lower().strip()
    if response not in ['yes', 'y']:
        print("Index building cancelled.")
        return

    # Build indexes
    builder = IndexBuilder()
    builder.build_all_indexes()

    print("\n✓ Index building complete!")
    print("  You can now start the API with fast loading.")
    print("  The API will automatically use the pre-built indexes.")


if __name__ == "__main__":
    main()