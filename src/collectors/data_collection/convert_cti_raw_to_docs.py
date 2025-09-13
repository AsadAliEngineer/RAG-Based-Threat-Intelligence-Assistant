# data_collection/convert_cti_raw_to_docs.py
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from config import Config
import csv
import json
import pandas as pd
from pathlib import Path
import xml.etree.ElementTree as ET
import logging
import os

config = Config()
RAW_CTI_DIR = config.cti_data_dir
DOCS_CTI_DIR = config.cti_docs_dir
LOGS_DIR = config.logs_dir

# Debug: Print actual paths
print(f"DEBUG: Raw CTI directory: {RAW_CTI_DIR}")
print(f"DEBUG: Docs CTI directory: {DOCS_CTI_DIR}")
print(f"DEBUG: Logs directory: {LOGS_DIR}")
print(f"DEBUG: Raw CTI exists: {RAW_CTI_DIR.exists()}")

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DOCS_CTI_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging with explicit logger instance
log_file = LOGS_DIR / "cti_conversion.log"
print(f"DEBUG: Log file will be created at: {log_file}")

# Create a specific logger for this module to avoid conflicts
logger = logging.getLogger('cti_conversion')
logger.setLevel(logging.INFO)

# Clear any existing handlers on this logger
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Create file handler
file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Prevent propagation to root logger to avoid conflicts
logger.propagate = False

# Test logging immediately
logger.info("=== CTI Conversion Process Started ===")
print(f"DEBUG: Log file exists after setup: {log_file.exists()}")
if log_file.exists():
    print(f"DEBUG: Log file size: {log_file.stat().st_size} bytes")


def process_csaf_vulnerability(vuln: dict) -> dict:
    """Extract comprehensive fields from a CSAF vulnerability."""
    try:
        cve = vuln.get("cve", "")
        cwe = vuln.get("cwe", {})
        cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else ""
        cwe_name = cwe.get("name", "") if isinstance(cwe, dict) else ""

        # Process notes
        notes = []
        for note in vuln.get("notes", []):
            notes.append({
                "category": note.get("category", ""),
                "title": note.get("title", ""),
                "text": note.get("text", "")
            })

        # Extract summary from notes
        summary = ""
        for note in notes:
            if note.get("category") == "summary":
                summary = note["text"]
                break

        # Process CVSS scores
        cvss_scores = []
        for score in vuln.get("scores", []):
            if "cvss_v3" in score:
                cvss_scores.append({
                    "base_score": score["cvss_v3"].get("baseScore", 0),
                    "severity": score["cvss_v3"].get("baseSeverity", ""),
                    "vector": score["cvss_v3"].get("vectorString", ""),
                    "version": score["cvss_v3"].get("version", ""),
                    "products": score.get("products", [])
                })

        # Process remediations
        remediations = []
        for rem in vuln.get("remediations", []):
            remediations.append({
                "category": rem.get("category", ""),
                "details": rem.get("details", ""),
                "product_ids": rem.get("product_ids", []),
                "url": rem.get("url", "")
            })

        # Process references
        references = []
        for ref in vuln.get("references", []):
            references.append({
                "category": ref.get("category", ""),
                "summary": ref.get("summary", ""),
                "url": ref.get("url", "")
            })

        product_status = vuln.get("product_status", {})

        return {
            "cve": cve,
            "cwe": {"id": cwe_id, "name": cwe_name},
            "summary": summary,
            "notes": notes,
            "cvss_scores": cvss_scores,
            "remediations": remediations,
            "references": references,
            "product_status": product_status
        }
    except Exception as e:
        logger.error(f"Error processing CSAF vulnerability: {e}")
        return {}


def create_comprehensive_content(vulnerabilities: list, notes: list, title: str) -> str:
    """Create a comprehensive content field that includes all important information."""
    content_parts = []

    # Add title
    if title:
        content_parts.append(f"Title: {title}")

    # Add document-level notes that provide context
    for note in notes:
        if note.get("category") in ["summary", "general"] and note.get("text"):
            # Skip boilerplate legal disclaimers
            text = note["text"]
            if not any(skip_phrase in text.lower() for skip_phrase in
                       ["legal disclaimer", "cisa disclaimer", "tlp", "traffic light protocol"]):
                content_parts.append(f"{note.get('title', 'Note')}: {text}")

    # Add vulnerability information
    for vuln in vulnerabilities:
        if not vuln:
            continue

        cve = vuln.get("cve", "")
        if cve:
            content_parts.append(f"\nVulnerability: {cve}")

        # Add CWE information
        cwe = vuln.get("cwe", {})
        if cwe.get("id"):
            cwe_text = f"CWE: {cwe['id']}"
            if cwe.get("name"):
                cwe_text += f" - {cwe['name']}"
            content_parts.append(cwe_text)

        # Add vulnerability summary
        if vuln.get("summary"):
            content_parts.append(f"Summary: {vuln['summary']}")

        # Add CVSS scores
        for score in vuln.get("cvss_scores", []):
            if score.get("base_score") and score.get("severity"):
                content_parts.append(
                    f"CVSS {score.get('version', 'v3')}: {score['base_score']} ({score['severity']})"
                )
                if score.get("vector"):
                    content_parts.append(f"Vector: {score['vector']}")

        # Add remediation information
        for remediation in vuln.get("remediations", []):
            if remediation.get("details"):
                category = remediation.get("category", "remediation").title()
                content_parts.append(f"{category}: {remediation['details']}")
                if remediation.get("url"):
                    content_parts.append(f"Reference: {remediation['url']}")

    return " ".join(content_parts)


def extract_metadata(vulnerabilities: list, notes: list) -> dict:
    """Extract metadata like severity, exploit status, etc."""
    metadata = {
        "severity": "",
        "exploit_status": "",
        "max_cvss_score": 0,
        "cve_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0
    }

    # Count CVEs and get severity distribution
    cves = []
    max_score = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for vuln in vulnerabilities:
        if not vuln:
            continue

        if vuln.get("cve"):
            cves.append(vuln["cve"])

        for score in vuln.get("cvss_scores", []):
            base_score = score.get("base_score", 0)
            severity = score.get("severity", "").upper()

            if base_score > max_score:
                max_score = base_score
                metadata["severity"] = severity

            if severity in severity_counts:
                severity_counts[severity] += 1

    metadata["cve_count"] = len(cves)
    metadata["max_cvss_score"] = max_score
    metadata["critical_count"] = severity_counts["CRITICAL"]
    metadata["high_count"] = severity_counts["HIGH"]
    metadata["medium_count"] = severity_counts["MEDIUM"]
    metadata["low_count"] = severity_counts["LOW"]

    # Check for exploit information in notes
    for note in notes:
        text = note.get("text", "").lower()
        if "exploit" in text:
            if any(phrase in text for phrase in ["public exploit", "known exploit", "active exploit"]):
                metadata["exploit_status"] = "public_exploits"
            elif "no known public exploit" in text:
                metadata["exploit_status"] = "no_known_exploits"
            elif any(phrase in text for phrase in ["proof of concept", "poc", "exploit code"]):
                metadata["exploit_status"] = "poc_available"
            else:
                metadata["exploit_status"] = "exploitable"
            break

    return metadata


def process_single_csaf_file(fpath: Path, csaf_out: Path) -> bool:
    """Process a single CSAF JSON file."""
    try:
        logger.info(f"Processing: {fpath.name}")

        with open(fpath, 'r', encoding="utf-8") as f:
            data = json.load(f)

        # Check if this is a valid CSAF file
        if not data.get("document"):
            logger.warning(f"Skipping {fpath.name} - not a valid CSAF file (no document section)")
            return False

        # Extract document information
        doc = data.get("document", {})
        doc_id = doc.get("tracking", {}).get("id", fpath.stem)
        title = doc.get("title", "")

        # Process notes
        notes = []
        for note in doc.get("notes", []):
            notes.append({
                "category": note.get("category", ""),
                "title": note.get("title", ""),
                "text": note.get("text", "")
            })

        # Process vulnerabilities with comprehensive extraction
        vulnerabilities = [
            process_csaf_vulnerability(v) for v in data.get("vulnerabilities", [])
        ]
        vulnerabilities = [v for v in vulnerabilities if v]  # Remove empty dicts

        # Extract other important data
        product_tree = data.get("product_tree", {})

        # Process document references
        references = []
        for ref in doc.get("references", []):
            references.append({
                "category": ref.get("category", ""),
                "summary": ref.get("summary", ""),
                "url": ref.get("url", "")
            })

        # Process acknowledgments
        acknowledgments = []
        for ack in doc.get("acknowledgments", []):
            acknowledgments.append({
                "names": ack.get("names", []),
                "organization": ack.get("organization", ""),
                "summary": ack.get("summary", "")
            })

        # Extract publisher and tracking info
        publisher = doc.get("publisher", {})
        tracking = doc.get("tracking", {})

        # Create comprehensive content
        content = create_comprehensive_content(vulnerabilities, notes, title)

        # Extract metadata
        metadata = extract_metadata(vulnerabilities, notes)

        # Build comprehensive document
        processed_doc = {
            "id": doc_id,
            "type": "CSAF",
            "title": title,
            "content": content,
            "cve_refs": [v["cve"] for v in vulnerabilities if v.get("cve")],
            "vulnerabilities": vulnerabilities,
            "severity": metadata["severity"],
            "max_cvss_score": metadata["max_cvss_score"],
            "exploit_status": metadata["exploit_status"],
            "cve_count": metadata["cve_count"],
            "severity_distribution": {
                "critical": metadata["critical_count"],
                "high": metadata["high_count"],
                "medium": metadata["medium_count"],
                "low": metadata["low_count"]
            },
            "product_tree": product_tree,
            "notes": notes,
            "references": references,
            "acknowledgments": acknowledgments,
            "publisher": publisher,
            "tracking": tracking,
            "csaf_version": doc.get("csaf_version", ""),
            "category": doc.get("category", ""),
            "distribution": doc.get("distribution", {}),
            "lang": doc.get("lang", "")
        }

        # Convert filename to uppercase for output
        output_filename = f"{doc_id.upper()}.json"
        output_path = csaf_out / output_filename

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(processed_doc, f, indent=2, ensure_ascii=False)

        logger.info(f"Successfully converted {fpath.name} -> {output_filename}")
        return True

    except Exception as e:
        logger.error(f"Error processing CSAF file {fpath}: {e}")
        return False


def find_and_convert_csaf_files():
    """Find and convert CSAF files from various possible locations."""
    csaf_out = DOCS_CTI_DIR / "csaf"
    csaf_out.mkdir(parents=True, exist_ok=True)

    converted_count = 0

    # List of possible locations for CSAF files
    possible_locations = [
        RAW_CTI_DIR / "csaf",
        RAW_CTI_DIR,
        RAW_CTI_DIR / "CSAF"
    ]

    csaf_files = []

    print(f"DEBUG: Searching for CSAF files in:")
    for location in possible_locations:
        print(f"  - {location} (exists: {location.exists()})")
        if location.exists():
            files = list(location.glob("*.json"))
            print(f"    Found {len(files)} JSON files")
            for f in files[:3]:
                print(f"      - {f.name}")
            if len(files) > 3:
                print(f"      ... and {len(files) - 3} more")

    for location in possible_locations:
        if location.exists():
            json_files = list(location.glob("*.json"))
            if json_files:
                logging.info(f"Found {len(json_files)} JSON files in {location}")
                csaf_files.extend(json_files)
                break

    if not csaf_files:
        logging.info("No CSAF directory found, searching for CSAF-like files...")
        print("DEBUG: Searching recursively for JSON files...")
        all_json_files = list(RAW_CTI_DIR.rglob("*.json"))
        print(f"DEBUG: Found {len(all_json_files)} JSON files total")

        for json_file in all_json_files:
            print(f"DEBUG: Checking {json_file}")
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if (data.get("document") and
                        (data.get("vulnerabilities") or
                         data.get("document", {}).get("category") == "csaf_security_advisory")):
                    csaf_files.append(json_file)
                    logging.info(f"Found CSAF-like file: {json_file}")
                    print(f"DEBUG: ✓ Valid CSAF file: {json_file}")
                else:
                    print(f"DEBUG: ✗ Not a CSAF file: {json_file}")
            except Exception as e:
                print(f"DEBUG: ✗ Error reading {json_file}: {e}")
                continue

    if not csaf_files:
        logging.warning("No CSAF files found in any location")
        print("DEBUG: No CSAF files found anywhere!")
        print("DEBUG: Contents of raw directory:")
        if RAW_CTI_DIR.exists():
            for item in RAW_CTI_DIR.iterdir():
                print(f"  - {item.name} ({'dir' if item.is_dir() else 'file'})")
        return 0

    logging.info(f"Processing {len(csaf_files)} CSAF files...")
    print(f"DEBUG: Will process {len(csaf_files)} CSAF files")

    for csaf_file in csaf_files:
        if process_single_csaf_file(csaf_file, csaf_out):
            converted_count += 1

    return converted_count


def convert_kev_files():
    """Find and convert KEV CSV files."""
    converted_count = 0

    kev_candidates = [
        RAW_CTI_DIR / "known_exploited_vulnerabilities.csv",
        RAW_CTI_DIR / "kev" / "known_exploited_vulnerabilities.csv",
        RAW_CTI_DIR / "KEV" / "known_exploited_vulnerabilities.csv"
    ]

    csv_files = list(RAW_CTI_DIR.rglob("*.csv"))
    print(f"DEBUG: Found {len(csv_files)} CSV files")
    for csv_file in csv_files:
        print(f"DEBUG: CSV file: {csv_file}")
        if "kev" in csv_file.name.lower() or "exploit" in csv_file.name.lower():
            kev_candidates.append(csv_file)

    kev_csv = None
    for candidate in kev_candidates:
        print(f"DEBUG: Checking KEV candidate: {candidate} (exists: {candidate.exists()})")
        if candidate.exists():
            kev_csv = candidate
            logging.info(f"Found KEV CSV: {kev_csv}")
            break

    if not kev_csv:
        logging.warning("KEV CSV file not found")
        return 0

    try:
        kev_out = DOCS_CTI_DIR / "kev"
        kev_out.mkdir(parents=True, exist_ok=True)

        with open(kev_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = row.get("cveID") or row.get("CVE_ID") or row.get("CVE")
                if not cve:
                    continue

                doc = {
                    "id": cve,
                    "type": "KEV",
                    "title": f"Known Exploited Vulnerability {cve}",
                    "content": row.get("shortDescription", "") or row.get("description", ""),
                    "vendor_project": row.get("vendorProject", "") or row.get("vendor", ""),
                    "product": row.get("product", ""),
                    "vulnerability_name": row.get("vulnerabilityName", "") or row.get("name", ""),
                    "date_added": row.get("dateAdded", "") or row.get("date_added", ""),
                    "required_action": row.get("requiredAction", "") or row.get("action", ""),
                    "due_date": row.get("dueDate", "") or row.get("due_date", ""),
                    "known_ransomware": row.get("knownRansomwareCampaignUse", "") or row.get("ransomware", ""),
                    "notes": row.get("notes", "").split(";") if row.get("notes") else [],
                    "cwes": row.get("cwes", "").split(",") if row.get("cwes") else []
                }

                output_file = kev_out / f"{cve}.json"
                with open(output_file, 'w', encoding='utf-8') as out_f:
                    json.dump(doc, out_f, indent=2, ensure_ascii=False)
                converted_count += 1

        logging.info(f"Converted {converted_count} KEV documents")

    except Exception as e:
        logging.error(f"Failed to convert KEV CSV: {e}")

    return converted_count


def convert_capec_files():
    """Find and convert CAPEC XML files."""
    converted_count = 0

    try:
        capec_candidates = list(RAW_CTI_DIR.rglob("*capec*.xml"))
        print(f"DEBUG: Found {len(capec_candidates)} CAPEC candidates")
        for candidate in capec_candidates:
            print(f"DEBUG: CAPEC candidate: {candidate}")

        capec_xml = capec_candidates[0] if capec_candidates else None

        if not capec_xml:
            logging.warning("CAPEC XML file not found")
            return 0

        logging.info(f"Found CAPEC XML: {capec_xml}")

        capec_out = DOCS_CTI_DIR / "capec"
        capec_out.mkdir(parents=True, exist_ok=True)

        tree = ET.parse(capec_xml)
        root = tree.getroot()

        # Handle namespaces
        ns_uri = root.tag[root.tag.find("{") + 1:root.tag.find("}")] if "{" in root.tag else ""
        ns = {"c": ns_uri} if ns_uri else {}

        # Find attack patterns
        pattern_xpath = ".//c:Attack_Pattern" if ns_uri else ".//Attack_Pattern"

        for ap in root.findall(pattern_xpath, ns):
            cid = ap.attrib.get("ID")
            if not cid:
                continue

            title = ap.attrib.get("Name", cid)

            # Find description
            desc_xpath = "c:Description" if ns_uri else "Description"
            desc_el = ap.find(desc_xpath, ns)
            desc = "".join(desc_el.itertext()).strip() if desc_el is not None else ""

            doc = {
                "id": cid,
                "type": "CAPEC",
                "title": title,
                "content": desc
            }

            output_file = capec_out / f"capec-{cid}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(doc, f, indent=2, ensure_ascii=False)
            converted_count += 1

        logging.info(f"Converted {converted_count} CAPEC patterns")

    except Exception as e:
        logging.error(f"Failed to convert CAPEC XML: {e}")

    return converted_count


def convert_attack_files():
    """Find and convert ATT&CK technique XLSX files, including tactics."""
    converted_count = 0

    try:
        # Find technique and tactics files
        technique_candidates = list(RAW_CTI_DIR.rglob("*technique*.xlsx"))
        tactics_candidates = list(RAW_CTI_DIR.rglob("*tactics*.xlsx"))
        
        # Filter out temporary files
        technique_candidates = [c for c in technique_candidates if not c.name.startswith('~$')]
        tactics_candidates = [c for c in tactics_candidates if not c.name.startswith('~$')]
        
        technique_xlsx = technique_candidates[0] if technique_candidates else None
        tactics_xlsx = tactics_candidates[0] if tactics_candidates else None

        if not technique_xlsx:
            logging.warning("ATT&CK technique XLSX file not found")
            return 0
            
        if not tactics_xlsx:
            logging.warning("ATT&CK tactics XLSX file not found")
            return 0

        logging.info(f"Found ATT&CK technique XLSX: {technique_xlsx}")
        logging.info(f"Found ATT&CK tactics XLSX: {tactics_xlsx}")

        attack_out = DOCS_CTI_DIR / "attack_techniques"
        attack_out.mkdir(parents=True, exist_ok=True)

        # First, load tactics to create name-to-ID mapping
        logging.info("Loading tactics mapping...")
        tactics_df = pd.read_excel(tactics_xlsx, dtype=str)
        tactic_name_to_id = {}
        
        for _, row in tactics_df.iterrows():
            tactic_id = row.get('ID', '')
            tactic_name = row.get('name', '')
            if tactic_id and tactic_name and not pd.isna(tactic_id) and not pd.isna(tactic_name):
                tactic_name_to_id[tactic_name.strip()] = tactic_id.strip()
        
        logging.info(f"Loaded {len(tactic_name_to_id)} tactic mappings")
        logging.info(f"Sample mappings: {dict(list(tactic_name_to_id.items())[:5])}")

        # Now load techniques
        logging.info("Loading techniques...")
        technique_df = pd.read_excel(technique_xlsx, dtype=str)
        
        # Create tactic-to-technique mapping
        tactic_technique_mapping = {}
        technique_tactic_mapping = {}

        for _, row in technique_df.iterrows():
            technique_id = row.get('ID', '')
            if not technique_id or pd.isna(technique_id):
                continue

            name = row.get('name', '')
            desc = row.get('description', '')
            tactics_raw = row.get('tactics', '')

            # Parse tactics and convert names to IDs
            tactic_names = []
            tactic_ids = []
            if tactics_raw and not pd.isna(tactics_raw):
                # Split by comma and clean up
                tactic_names = [t.strip() for t in str(tactics_raw).split(',') if t.strip()]
                for tactic_name in tactic_names:
                    if tactic_name in tactic_name_to_id:
                        tactic_ids.append(tactic_name_to_id[tactic_name])
                    else:
                        logging.warning(f"Unknown tactic name: {tactic_name} for technique {technique_id}")

            # Create mappings
            for tactic_id in tactic_ids:
                if tactic_id not in tactic_technique_mapping:
                    tactic_technique_mapping[tactic_id] = []
                tactic_technique_mapping[tactic_id].append(technique_id)
            
            technique_tactic_mapping[technique_id] = tactic_ids

            doc = {
                "id": str(technique_id),
                "type": "ATT&CK",
                "title": str(name) if not pd.isna(name) else "",
                "content": str(desc) if not pd.isna(desc) else "",
                "tactics": tactic_names,  # Store tactic names
                "tactic_ids": tactic_ids  # Store tactic IDs
            }

            output_file = attack_out / f"{technique_id}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(doc, f, indent=2, ensure_ascii=False)
            converted_count += 1

        # Save the mappings for easy lookup
        mapping_file = DOCS_CTI_DIR / "attack_mappings.json"
        mappings = {
            "tactic_to_techniques": tactic_technique_mapping,
            "technique_to_tactics": technique_tactic_mapping,
            "tactic_name_to_id": tactic_name_to_id,
            "total_techniques": converted_count,
            "total_tactics": len(tactic_technique_mapping)
        }
        
        with open(mapping_file, 'w', encoding='utf-8') as f:
            json.dump(mappings, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Converted {converted_count} ATT&CK techniques with {len(tactic_technique_mapping)} tactic mappings")
        logging.info(f"Saved tactic-technique mappings to {mapping_file}")

    except Exception as e:
        logging.error(f"Failed to convert ATT&CK XLSX: {e}")
        import traceback
        traceback.print_exc()

    return converted_count


def convert_tactics_files():
    """Find and convert ATT&CK tactics XLSX files."""
    converted_count = 0

    try:
        tactics_candidates = list(RAW_CTI_DIR.rglob("*tactics*.xlsx"))
        print(f"DEBUG: Found {len(tactics_candidates)} ATT&CK tactics candidates")
        for candidate in tactics_candidates:
            print(f"DEBUG: Tactics candidate: {candidate}")

        tactics_xlsx = tactics_candidates[0] if tactics_candidates else None

        if not tactics_xlsx:
            logging.warning("ATT&CK tactics XLSX file not found")
            return 0

        logging.info(f"Found ATT&CK tactics XLSX: {tactics_xlsx}")

        tactics_out = DOCS_CTI_DIR / "attack_tactics"
        tactics_out.mkdir(parents=True, exist_ok=True)

        # Read sheet names
        try:
            sheet_names = pd.ExcelFile(tactics_xlsx).sheet_names
            print(f"DEBUG: Available sheets in {tactics_xlsx}: {sheet_names}")
        except Exception as e:
            logging.error(f"Failed to read sheet names from {tactics_xlsx}: {e}")
            return 0

        # Try reading each sheet
        df = None
        for sheet_name in sheet_names:
            try:
                df = pd.read_excel(tactics_xlsx, sheet_name=sheet_name, dtype=str)
                logging.info(f"Successfully read sheet: {sheet_name}")
                break
            except Exception as e:
                logging.error(f"Failed to read sheet {sheet_name}: {e}")
                continue

        if df is None:
            logging.error("Could not read any sheet from ATT&CK tactics XLSX file")
            return 0

        for _, row in df.iterrows():
            tid = row.get("ID")
            if not tid or pd.isna(tid):
                continue

            name = row.get("name", "")
            desc = row.get("description", "")

            doc = {
                "id": str(tid),
                "type": "ATT&CK-TACTIC",
                "title": str(name) if not pd.isna(name) else "",
                "content": str(desc) if not pd.isna(desc) else ""
            }

            output_file = tactics_out / f"{tid}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(doc, f, indent=2, ensure_ascii=False)
            converted_count += 1

        logging.info(f"Converted {converted_count} ATT&CK tactics")

    except Exception as e:
        logging.error(f"Failed to convert ATT&CK tactics XLSX: {e}")

    return converted_count


def convert_exploitdb_files():
    """Find and convert ExploitDB CSV files."""
    converted_count = 0

    try:
        # Look for ExploitDB files in various possible locations
        exploitdb_candidates = [
            RAW_CTI_DIR / "exploitdb" / "files_exploits.csv",
            RAW_CTI_DIR / "files_exploits.csv",
            RAW_CTI_DIR / "exploitdb" / "exploits.csv"
        ]

        # Also search recursively for exploit-related CSV files
        csv_files = list(RAW_CTI_DIR.rglob("*.csv"))
        for csv_file in csv_files:
            if any(keyword in csv_file.name.lower() for keyword in ["exploit", "files_exploit"]):
                exploitdb_candidates.append(csv_file)

        print(f"DEBUG: Found {len(exploitdb_candidates)} ExploitDB candidates")
        for candidate in exploitdb_candidates:
            print(f"DEBUG: ExploitDB candidate: {candidate} (exists: {candidate.exists()})")

        exploitdb_csv = None
        for candidate in exploitdb_candidates:
            if candidate.exists():
                exploitdb_csv = candidate
                logging.info(f"Found ExploitDB CSV: {exploitdb_csv}")
                break

        if not exploitdb_csv:
            logging.warning("ExploitDB CSV file not found")
            return 0

        exploitdb_out = DOCS_CTI_DIR / "exploitdb"
        exploitdb_out.mkdir(parents=True, exist_ok=True)

        # Read the CSV file
        try:
            df = pd.read_csv(exploitdb_csv, dtype=str, low_memory=False)
            logging.info(f"Successfully read ExploitDB CSV with {len(df)} rows")
            print(f"DEBUG: ExploitDB CSV columns: {list(df.columns)}")
        except Exception as e:
            logging.error(f"Failed to read ExploitDB CSV: {e}")
            return 0

        # Process each exploit entry
        for _, row in df.iterrows():
            exploit_id = row.get("id")
            if not exploit_id or pd.isna(exploit_id):
                continue

            # Clean and extract fields
            title = str(row.get("description", "")).strip() if not pd.isna(row.get("description")) else ""
            file_path = str(row.get("file", "")).strip() if not pd.isna(row.get("file")) else ""
            author = str(row.get("author", "")).strip() if not pd.isna(row.get("author")) else ""
            exploit_type = str(row.get("type", "")).strip() if not pd.isna(row.get("type")) else ""
            platform = str(row.get("platform", "")).strip() if not pd.isna(row.get("platform")) else ""
            date_published = str(row.get("date_published", "")).strip() if not pd.isna(
                row.get("date_published")) else ""
            date_added = str(row.get("date_added", "")).strip() if not pd.isna(row.get("date_added")) else ""
            verified = str(row.get("verified", "0")).strip() if not pd.isna(row.get("verified")) else "0"
            tags = str(row.get("tags", "")).strip() if not pd.isna(row.get("tags")) else ""
            codes = str(row.get("codes", "")).strip() if not pd.isna(row.get("codes")) else ""
            port = str(row.get("port", "")).strip() if not pd.isna(row.get("port")) else ""

            # Create comprehensive content
            content_parts = [f"Exploit: {title}"]

            if author:
                content_parts.append(f"Author: {author}")
            if exploit_type:
                content_parts.append(f"Type: {exploit_type}")
            if platform:
                content_parts.append(f"Platform: {platform}")
            if port and port != "nan":
                content_parts.append(f"Port: {port}")
            if tags:
                content_parts.append(f"Tags: {tags}")
            if codes:
                content_parts.append(f"CVE/CWE References: {codes}")
            if verified == "1":
                content_parts.append("Status: Verified")

            content = " | ".join(content_parts)

            # Parse CVE references from codes field
            cve_refs = []
            if codes:
                # Look for CVE patterns in the codes field
                import re
                cve_pattern = r'CVE-\d{4}-\d{4,}'
                cve_matches = re.findall(cve_pattern, codes.upper())
                cve_refs = list(set(cve_matches))

            # Create document
            doc = {
                "id": f"EDB-{exploit_id}",
                "type": "EXPLOIT",
                "title": title,
                "content": content,
                "exploit_id": exploit_id,
                "file_path": file_path,
                "author": author,
                "exploit_type": exploit_type,
                "platform": platform,
                "port": port if port and port != "nan" else "",
                "date_published": date_published,
                "date_added": date_added,
                "verified": verified == "1",
                "tags": tags.split(",") if tags else [],
                "codes": codes,
                "cve_refs": cve_refs,
                "source_url": str(row.get("source_url", "")).strip() if not pd.isna(row.get("source_url")) else "",
                "application_url": str(row.get("application_url", "")).strip() if not pd.isna(
                    row.get("application_url")) else ""
            }

            # Save document
            output_file = exploitdb_out / f"EDB-{exploit_id}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(doc, f, indent=2, ensure_ascii=False)
            converted_count += 1

            # Log progress for large datasets
            if converted_count % 1000 == 0:
                print(f"DEBUG: Processed {converted_count} exploits...")

        logging.info(f"Converted {converted_count} ExploitDB entries")

    except Exception as e:
        logging.error(f"Failed to convert ExploitDB CSV: {e}")

    return converted_count


if __name__ == "__main__":
    print("=== Starting CTI conversion process ===")
    logger.info("Starting CTI conversion process...")
    logger.info(f"Raw CTI directory: {RAW_CTI_DIR}")
    logger.info(f"Docs CTI directory: {DOCS_CTI_DIR}")

    # Flush the log immediately
    for handler in logger.handlers:
        if hasattr(handler, 'flush'):
            handler.flush()

    if not RAW_CTI_DIR.exists():
        error_msg = f"Raw CTI directory does not exist: {RAW_CTI_DIR}"
        logger.error(error_msg)
        print(f"ERROR: {error_msg}")
        print("Creating the directory...")
        RAW_CTI_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Directory created. Please add CTI files to this directory and run again.")
        print("Directory created. Please add CTI files to this directory and run again.")

        # Ensure logs are written before exit
        for handler in logger.handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        exit(1)

    total_converted = 0

    logger.info("Converting KEV files...")
    print("Converting KEV files...")
    kev_count = convert_kev_files()
    total_converted += kev_count
    logger.info(f"KEV conversion completed: {kev_count} files")

    logger.info("Converting CSAF files...")
    print("Converting CSAF files...")
    csaf_count = find_and_convert_csaf_files()
    total_converted += csaf_count
    logger.info(f"CSAF conversion completed: {csaf_count} files")

    logger.info("Converting CAPEC files...")
    print("Converting CAPEC files...")
    capec_count = convert_capec_files()
    total_converted += capec_count
    logger.info(f"CAPEC conversion completed: {capec_count} files")

    logger.info("Converting ATT&CK techniques...")
    print("Converting ATT&CK techniques...")
    attack_count = convert_attack_files()
    total_converted += attack_count
    logger.info(f"ATT&CK techniques conversion completed: {attack_count} files")

    logger.info("Converting ATT&CK tactics...")
    print("Converting ATT&CK tactics...")
    tactics_count = convert_tactics_files()
    total_converted += tactics_count
    logger.info(f"ATT&CK tactics conversion completed: {tactics_count} files")

    logger.info("Converting ExploitDB files...")
    print("Converting ExploitDB files...")
    exploitdb_count = convert_exploitdb_files()
    total_converted += exploitdb_count
    logger.info(f"ExploitDB conversion completed: {exploitdb_count} files")

    final_msg = f"Conversion complete! Total files converted: {total_converted}"
    logger.info(final_msg)
    logger.info(f"Converted raw CTI from {RAW_CTI_DIR} into JSON docs at {DOCS_CTI_DIR}")
    logger.info("=== CTI Conversion Process Completed ===")

    print(final_msg)
    print(f"Converted raw CTI from {RAW_CTI_DIR} into JSON docs at {DOCS_CTI_DIR}")

    # Force flush all handlers before exit
    for handler in logger.handlers:
        if hasattr(handler, 'flush'):
            handler.flush()

    # Final log file check
    log_file = LOGS_DIR / "cti_conversion.log"
    if log_file.exists():
        print(f"Log file created successfully: {log_file}")
        print(f"Log file size: {log_file.stat().st_size} bytes")
        if log_file.stat().st_size > 0:
            print("Log file contains data - check the contents!")
        else:
            print("WARNING: Log file is empty!")
    else:
        print(f"WARNING: Log file was not created at {log_file}")