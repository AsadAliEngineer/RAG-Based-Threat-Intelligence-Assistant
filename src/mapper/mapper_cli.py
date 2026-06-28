#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path

from .mapper_config import MapperConfig
from .cve_ttp_mapper import CVEtoTTPMapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def map_single_cve(mapper: CVEtoTTPMapper, cve_id: str, description: str = "", cwe_ids: list = None):
    """Map a single CVE to TTPs."""
    cve_data = {
        "id": cve_id,
        "description": description,
        "cwe_ids": cwe_ids or []
    }
    
    result = mapper.map_cve_to_ttps(cve_data)
    
    print(f"\nCVE-to-TTP Mapping for {cve_id}:")
    print(f"TTPs found: {len(result['ttps'])}")
    print(f"Methods used: {', '.join(result['methods_used'])}")
    
    if result['ttps']:
        print("\nMapped TTPs:")
        for ttp in result['ttps']:
            print(f"  - {ttp}")
    else:
        print("\nNo TTPs found for this CVE")
    
    return result


def map_cve_file(mapper: CVEtoTTPMapper, input_file: Path, output_file: Path = None):
    """Map CVEs from a file."""
    logger.info(f"Processing CVE file: {input_file}")
    
    results = mapper.process_cve_file(input_file)
    
    if results:
        if output_file:
            mapper.save_mappings(results, output_file)
        else:
            mapper.save_mappings(results)
        
        # Print summary
        total_cves = len(results)
        cves_with_ttps = len([r for r in results if r['ttps']])
        unique_ttps = len(set(ttp for r in results for ttp in r['ttps']))
        
        print(f"\nProcessing complete:")
        print(f"  Total CVEs processed: {total_cves}")
        print(f"  CVEs with TTPs: {cves_with_ttps}")
        print(f"  Unique TTPs found: {unique_ttps}")
    else:
        print("No results generated")


def main():
    parser = argparse.ArgumentParser(
        description="Map CVEs to MITRE ATT&CK TTPs using CWE relationships and TIE inference"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Single CVE mapping
    single_parser = subparsers.add_parser('single', help='Map a single CVE')
    single_parser.add_argument('cve_id', help='CVE identifier (e.g., CVE-2021-44228)')
    single_parser.add_argument('--description', '-d', help='CVE description text')
    single_parser.add_argument('--cwe', '-c', action='append', help='CWE IDs (can specify multiple)')
    
    # File processing
    file_parser = subparsers.add_parser('file', help='Process CVE file')
    file_parser.add_argument('input_file', type=Path, help='Input CVE JSON file')
    file_parser.add_argument('--output', '-o', type=Path, help='Output file path')
    
    # Batch processing
    batch_parser = subparsers.add_parser('batch', help='Process all CVE files in directory')
    batch_parser.add_argument('input_dir', type=Path, help='Directory containing CVE JSON files')
    batch_parser.add_argument('--pattern', '-p', default='*.json', help='File pattern (default: *.json)')
    batch_parser.add_argument('--output', '-o', type=Path, help='Output directory')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize mapper
    config = MapperConfig()
    mapper = CVEtoTTPMapper(config)
    
    if args.command == 'single':
        map_single_cve(mapper, args.cve_id, args.description or "", args.cwe)
    
    elif args.command == 'file':
        map_cve_file(mapper, args.input_file, args.output)
    
    elif args.command == 'batch':
        output_dir = args.output or args.input_dir / 'ttp_mappings'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        cve_files = list(args.input_dir.glob(args.pattern))
        logger.info(f"Found {len(cve_files)} files to process")
        
        all_results = []
        for cve_file in cve_files:
            logger.info(f"Processing {cve_file}")
            results = mapper.process_cve_file(cve_file)
            all_results.extend(results)
        
        if all_results:
            output_file = output_dir / 'all_cve_ttp_mappings.json'
            mapper.save_mappings(all_results, output_file)


if __name__ == "__main__":
    main()