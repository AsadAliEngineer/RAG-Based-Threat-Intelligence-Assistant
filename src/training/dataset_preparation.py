import json
import pandas as pd
from datetime import datetime
import random
import re
from typing import List, Dict, Any

def load_json_file(file_path: str) -> Any:
    """Load JSON file with proper UTF-8 encoding."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None

def load_mitre_techniques() -> Dict[str, Dict[str, Any]]:
    """Load MITRE ATT&CK techniques with detection and data source information."""
    print("Loading MITRE ATT&CK techniques...")
    try:
        df = pd.read_excel('data/CTI/raw/enterprise-attack-v17.1-techniques.xlsx')
        techniques = {}
        
        for _, row in df.iterrows():
            if pd.notna(row['ID']) and str(row['ID']).startswith('T'):
                technique_id = str(row['ID'])
                techniques[technique_id] = {
                    'name': row['name'] if pd.notna(row['name']) else '',
                    'description': row['description'] if pd.notna(row['description']) else '',
                    'detection': row['detection'] if pd.notna(row['detection']) else '',
                    'data_sources': row['data sources'] if pd.notna(row['data sources']) else '',
                    'tactics': row['tactics'] if pd.notna(row['tactics']) else '',
                    'platforms': row['platforms'] if pd.notna(row['platforms']) else ''
                }
        
        print(f"Loaded {len(techniques)} MITRE ATT&CK techniques")
        return techniques
    except Exception as e:
        print(f"Error loading MITRE techniques: {e}")
        return {}

def create_enhanced_dataset_with_mitigations():
    """Create an enhanced dataset with CVE, CWE, MITRE, CAPEC, and mitigation data."""
    
    print("Loading CVE nodes...")
    cve_nodes = load_json_file('data/knowledge_base/knowledge_graph/cves_nodes.json')
    if not cve_nodes:
        return
    
    print("Loading CWE relationships...")
    cwe_relationships = load_json_file('data/knowledge_base/knowledge_graph/cve_cwe_relationships.json')
    if not cwe_relationships:
        return
    
    print("Loading MITRE technique relationships...")
    mitre_relationships = load_json_file('data/knowledge_base/knowledge_graph/cve_mitre_technique_relationships.json')
    if not mitre_relationships:
        return
    
    print("Loading MITRE tactics relationships...")
    mitre_tactics_relationships = load_json_file('data/knowledge_base/knowledge_graph/cve_mitre_tactic_relationships.json')
    if not mitre_tactics_relationships:
        return
    
    print("Loading CAPEC relationships...")
    capec_relationships = load_json_file('data/knowledge_base/knowledge_graph/cve_capec_relationships.json')
    if not capec_relationships:
        return
    
    print("Loading known exploited vulnerabilities...")
    kev_df = pd.read_csv('data/CTI/raw/known_exploited_vulnerabilities.csv')
    
    # Load MITRE techniques for mitigation data
    mitre_techniques = load_mitre_techniques()
    
    # Create relationship mappings
    print("Creating relationship mappings...")
    cve_to_cwe = {}
    for rel in cwe_relationships:
        cve_id = rel['cve_id']
        if cve_id not in cve_to_cwe:
            cve_to_cwe[cve_id] = []
        cve_to_cwe[cve_id].append(rel['cwe_id'])
    
    cve_to_mitre_techniques = {}
    for rel in mitre_relationships:
        cve_id = rel['cve_id']
        if cve_id not in cve_to_mitre_techniques:
            cve_to_mitre_techniques[cve_id] = []
        cve_to_mitre_techniques[cve_id].append(rel['technique_id'])
    
    cve_to_mitre_tactics = {}
    for rel in mitre_tactics_relationships:
        cve_id = rel['cve_id']
        if cve_id not in cve_to_mitre_tactics:
            cve_to_mitre_tactics[cve_id] = []
        cve_to_mitre_tactics[cve_id].append(rel['tactic_id'])
    
    cve_to_capec = {}
    for rel in capec_relationships:
        cve_id = rel['cve_id']
        if cve_id not in cve_to_capec:
            cve_to_capec[cve_id] = []
        cve_to_capec[cve_id].append(rel['capec_id'])
    
    # Create KEV mapping
    kev_cves = set(kev_df['cveID'].tolist())
    
    # Create enhanced dataset
    print("Creating enhanced dataset with mitigations...")
    dataset = []
    
    for cve_id, cve_data in cve_nodes.items():
        # Get relationships
        cwes = cve_to_cwe.get(cve_id, [])
        mitre_techniques_list = cve_to_mitre_techniques.get(cve_id, [])
        mitre_tactics = cve_to_mitre_tactics.get(cve_id, [])
        capecs = cve_to_capec.get(cve_id, [])
        is_kev = cve_id in kev_cves
        
        # Get MITRE technique details for mitigations
        mitre_technique_details = []
        for tech_id in mitre_techniques_list:
            if tech_id in mitre_techniques:
                mitre_technique_details.append({
                    'id': tech_id,
                    'name': mitre_techniques[tech_id]['name'],
                    'description': mitre_techniques[tech_id]['description'],
                    'detection': mitre_techniques[tech_id]['detection'],
                    'data_sources': mitre_techniques[tech_id]['data_sources']
                })
        
        # Create enhanced CVE data
        enhanced_cve = {
            'id': cve_id,
            'title': cve_data.get('title', ''),
            'description': cve_data.get('description', ''),
            'cvss_v3_score': cve_data.get('cvss_v3', {}).get('base_score', 0),
            'cvss_v3_severity': cve_data.get('cvss_v3', {}).get('base_severity', 'UNKNOWN'),
            'affected_products': cve_data.get('affected_products', []),
            'is_in_kev': is_kev,
            'cwes': cwes,
            'mitre_techniques': mitre_techniques_list,
            'mitre_technique_details': mitre_technique_details,
            'mitre_tactics': mitre_tactics,
            'capecs': capecs
        }
        
        dataset.append(enhanced_cve)
    
    print(f"Created enhanced dataset with {len(dataset)} CVEs")
    
    # Count CVEs with different types of mappings
    cves_with_cwe = sum(1 for cve in dataset if cve['cwes'])
    cves_with_mitre_techniques = sum(1 for cve in dataset if cve['mitre_techniques'])
    cves_with_mitre_tactics = sum(1 for cve in dataset if cve['mitre_tactics'])
    cves_with_capec = sum(1 for cve in dataset if cve['capecs'])
    cves_in_kev = sum(1 for cve in dataset if cve['is_in_kev'])
    
    print(f"CVEs with CWE mappings: {cves_with_cwe}")
    print(f"CVEs with MITRE technique mappings: {cves_with_mitre_techniques}")
    print(f"CVEs with MITRE tactic mappings: {cves_with_mitre_tactics}")
    print(f"CVEs with CAPEC mappings: {cves_with_capec}")
    print(f"CVEs in KEV database: {cves_in_kev}")
    
    # Save enhanced dataset
    output_file = 'data/training_datasets/enhanced_cve_dataset_with_mitigations.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    
    print(f"Enhanced dataset with mitigations saved to {output_file}")
    
    # Create training examples
    create_training_examples_with_mitigations(dataset)

def create_training_examples_with_mitigations(enhanced_cves: List[Dict[str, Any]]):
    """Create training examples from enhanced CVE data with MITRE mitigations."""
    
    print("Creating training examples with mitigations...")
    training_examples = []
    
    for cve in enhanced_cves:
        # Skip CVEs without sufficient data
        if not cve['description'] or not cve['title']:
            continue
        
        # Create different types of training examples
        examples = create_vulnerability_analysis_examples_with_mitigations(cve)
        training_examples.extend(examples)
        
        examples = create_remediation_examples_with_mitigations(cve)
        training_examples.extend(examples)
        
        examples = create_technical_analysis_examples_with_mitigations(cve)
        training_examples.extend(examples)
        
        examples = create_detection_examples(cve)
        training_examples.extend(examples)
        
        examples = create_mitigation_strategy_examples(cve)
        training_examples.extend(examples)
    
    # Apply data quality improvements directly
    print("Applying data quality improvements...")
    training_examples = improve_data_quality(training_examples)
    
    # Shuffle and limit to 1500 examples (increased for more variety)
    random.shuffle(training_examples)
    training_examples = training_examples[:1500]
    
    print(f"Created {len(training_examples)} high-quality training examples with mitigations")
    
    # Save training dataset
    output_file = 'data/training_datasets/enhanced_training_dataset_with_mitigations.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(training_examples, f, indent=2, ensure_ascii=False)
    
    print(f"Enhanced training dataset with mitigations saved to {output_file}")

def improve_data_quality(examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply data quality improvements to prevent overfitting"""
    print("🔄 Improving data quality...")
    
    # Step 1: Diversify instructions
    examples = diversify_instructions(examples)
    
    # Step 2: Diversify inputs
    examples = diversify_inputs(examples)
    
    # Step 3: Diversify outputs
    examples = diversify_outputs(examples)
    
    # Step 4: Remove duplicates
    examples = remove_duplicates(examples)
    
    print(f"✅ Data quality improvements applied. Final count: {len(examples)} examples")
    return examples

def diversify_instructions(examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Diversify instructions to increase variety"""
    print("🔄 Diversifying instructions...")
    
    # Define instruction templates with variations
    instruction_templates = [
        "Analyze this CVE vulnerability and provide a comprehensive security assessment.",
        "Examine the following CVE and explain its technical details and potential impact.",
        "Provide a detailed analysis of this cybersecurity vulnerability with mitigation strategies.",
        "Investigate this CVE and describe its attack vectors and security implications.",
        "Conduct a thorough security analysis of this vulnerability, including risk assessment.",
        "Review this CVE and provide technical insights along with recommended countermeasures.",
        "Analyze the security implications of this vulnerability and suggest protective measures.",
        "Examine this CVE for potential threats and provide detailed security recommendations.",
        "Provide a comprehensive vulnerability analysis with technical details and remediation steps.",
        "Investigate this cybersecurity issue and explain its severity and potential exploits.",
        "Conduct a detailed security review of this CVE with attack scenario analysis.",
        "Analyze this vulnerability's technical aspects and provide security best practices.",
        "Review this CVE for security risks and provide detailed mitigation guidance.",
        "Examine this vulnerability and explain its technical characteristics and security impact.",
        "Provide a thorough analysis of this CVE with technical details and security recommendations."
    ]
    
    # Additional instruction variations for specific aspects
    aspect_instructions = [
        "Focus on the technical implementation details and code-level analysis.",
        "Emphasize the business impact and risk assessment aspects.",
        "Include MITRE ATT&CK framework mapping and attack patterns.",
        "Provide detailed remediation steps and security controls.",
        "Analyze the vulnerability from an attacker's perspective.",
        "Focus on detection methods and monitoring strategies.",
        "Include compliance implications and regulatory considerations.",
        "Provide detailed patch analysis and update recommendations."
    ]
    
    all_instructions = instruction_templates + aspect_instructions
    
    # Apply instruction diversification
    for i, example in enumerate(examples):
        # Use different instructions based on index to ensure diversity
        instruction_idx = i % len(all_instructions)
        example['instruction'] = all_instructions[instruction_idx]
        
        # Add some randomness to further diversify
        if random.random() < 0.3:  # 30% chance to add aspect-specific instruction
            aspect_idx = random.randint(0, len(aspect_instructions) - 1)
            example['instruction'] += f" {aspect_instructions[aspect_idx]}"
    
    print(f"✅ Diversified instructions for {len(examples)} examples")
    return examples

def diversify_inputs(examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Diversify input formats to increase variety"""
    print("🔄 Diversifying inputs...")
    
    # Define different input formats
    input_formats = [
        "CVE Information:\n{input}",
        "Vulnerability Details:\n{input}",
        "Security Issue:\n{input}",
        "CVE Analysis Request:\n{input}",
        "Vulnerability Assessment:\n{input}",
        "Security Analysis:\n{input}",
        "CVE Details:\n{input}",
        "Vulnerability Report:\n{input}"
    ]
    
    # Apply input diversification
    for i, example in enumerate(examples):
        format_idx = i % len(input_formats)
        original_input = example['input']
        example['input'] = input_formats[format_idx].format(input=original_input)
    
    print(f"✅ Diversified inputs for {len(examples)} examples")
    return examples

def diversify_outputs(examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Diversify output patterns to prevent repetitive responses"""
    print("🔄 Diversifying outputs...")
    
    # Define different output structure variations
    output_variations = [
        "## Analysis\n{content}",
        "**Security Assessment:**\n{content}",
        "### Vulnerability Analysis\n{content}",
        "**CVE Analysis:**\n{content}",
        "## Security Review\n{content}",
        "**Technical Assessment:**\n{content}",
        "### Security Analysis\n{content}",
        "**Vulnerability Assessment:**\n{content}"
    ]
    
    # Apply output diversification
    for i, example in enumerate(examples):
        # Extract the main content (remove existing formatting)
        content = example['output']
        
        # Remove common headers if present
        content = re.sub(r'^#+\s*.*?\n', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\*\*.*?\*\*:\n', '', content, flags=re.MULTILINE)
        
        # Apply new format
        format_idx = i % len(output_variations)
        example['output'] = output_variations[format_idx].format(content=content.strip())
    
    print(f"✅ Diversified outputs for {len(examples)} examples")
    return examples

def remove_duplicates(examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate examples based on content similarity"""
    print("🔄 Removing duplicates...")
    
    seen = set()
    unique_examples = []
    duplicates_removed = 0
    
    for example in examples:
        # Create a hash of the example content
        content_hash = hash(f"{example['instruction']}_{example['input']}_{example['output']}")
        
        if content_hash not in seen:
            seen.add(content_hash)
            unique_examples.append(example)
        else:
            duplicates_removed += 1
    
    print(f"✅ Removed {duplicates_removed} duplicate examples")
    print(f"✅ Final unique examples: {len(unique_examples)}")
    return unique_examples

def create_vulnerability_analysis_examples_with_mitigations(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    """Create vulnerability analysis training examples with MITRE context."""
    examples = []
    
    # Enhanced vulnerability analysis with MITRE context
    prompt = f"""Analyze the following CVE vulnerability with MITRE ATT&CK context:

CVE ID: {cve['id']}
Title: {cve['title']}
Description: {cve['description']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
Affected Products: {', '.join(cve['affected_products']) if cve['affected_products'] else 'Not specified'}

Provide a comprehensive analysis including MITRE ATT&CK techniques, attack patterns, and potential mitigations."""

    response = f"""## Vulnerability Analysis for {cve['id']}

**Severity Assessment:**
- CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
- This is a {cve['cvss_v3_severity'].lower()} severity vulnerability

**Technical Details:**
{cve['description']}

**Affected Systems:**
{', '.join(cve['affected_products']) if cve['affected_products'] else 'Not specified'}

**Attack Vectors:**
Based on the CVSS metrics, this vulnerability can be exploited remotely without authentication."""

    if cve['cwes']:
        response += f"\n\n**Related Weaknesses:**\n- CWE IDs: {', '.join(cve['cwes'])}"

    if cve['mitre_technique_details']:
        response += f"\n\n**MITRE ATT&CK Techniques:**"
        for tech in cve['mitre_technique_details'][:3]:  # Limit to top 3
            response += f"\n- **{tech['id']} ({tech['name']}):** {tech['description'][:150]}..."

    if cve['capecs']:
        response += f"\n\n**Attack Patterns:**\n- CAPEC IDs: {', '.join(cve['capecs'])}"

    if cve['is_in_kev']:
        response += "\n\n**Exploitation Status:**\n- This vulnerability is listed in the Known Exploited Vulnerabilities (KEV) database, indicating active exploitation in the wild."

    examples.append({
        "instruction": "Analyze the following CVE vulnerability with MITRE ATT&CK context and provide a comprehensive security assessment.",
        "input": prompt,
        "output": response
    })
    
    return examples

def create_remediation_examples_with_mitigations(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    """Create remediation training examples with MITRE-based mitigations."""
    examples = []
    
    prompt = f"""Provide comprehensive remediation guidance with MITRE ATT&CK mitigations for the following CVE vulnerability:

CVE ID: {cve['id']}
Title: {cve['title']}
Description: {cve['description']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
Affected Products: {', '.join(cve['affected_products']) if cve['affected_products'] else 'Not specified'}

What are the recommended remediation steps and MITRE ATT&CK mitigations for this vulnerability?"""

    response = f"""## Remediation Guidance for {cve['id']}

**Immediate Actions:**
1. **Assess Impact:** Determine if your systems are affected by this vulnerability
2. **Prioritize:** Given the {cve['cvss_v3_severity'].lower()} severity, this should be addressed promptly
3. **Inventory:** Identify all affected systems and applications

**Recommended Remediation Steps:**

1. **Patch Management:**
   - Apply vendor-provided security patches as soon as they become available
   - Test patches in a non-production environment first
   - Implement automated patch management where possible

2. **Compensating Controls:**
   - Implement network segmentation to limit exposure
   - Use firewalls and intrusion detection systems
   - Apply the principle of least privilege

3. **Monitoring:**
   - Monitor affected systems for suspicious activity
   - Implement logging and alerting for potential exploitation attempts
   - Regular vulnerability scanning and assessment"""

    if cve['mitre_technique_details']:
        response += f"\n\n**MITRE ATT&CK Mitigations:**"
        for tech in cve['mitre_technique_details'][:3]:
            response += f"\n\n**For {tech['id']} ({tech['name']}):**"
            if tech['detection']:
                response += f"\n- **Detection:** {tech['detection'][:200]}..."
            if tech['data_sources']:
                response += f"\n- **Data Sources:** {tech['data_sources']}"
            response += f"\n- **Mitigation:** Implement controls to prevent {tech['name'].lower()}"

    if cve['is_in_kev']:
        response += "\n\n**Critical Note:** This vulnerability is actively exploited in the wild. Immediate action is required."

    if cve['cwes']:
        response += f"\n\n**Addressing Root Causes:**\n- Focus on the underlying weaknesses: {', '.join(cve['cwes'])}\n- Implement secure coding practices to prevent similar vulnerabilities"

    response += f"""

**Affected Products:**
{', '.join(cve['affected_products']) if cve['affected_products'] else 'Contact vendor for specific guidance'}

**Follow-up:**
- Verify remediation effectiveness through testing
- Document all changes and maintain security baselines
- Consider implementing additional security controls"""

    examples.append({
        "instruction": "Provide comprehensive remediation guidance with MITRE ATT&CK mitigations for this CVE vulnerability.",
        "input": prompt,
        "output": response
    })
    
    return examples

def create_technical_analysis_examples_with_mitigations(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    """Create technical analysis training examples with MITRE context."""
    examples = []
    
    prompt = f"""Provide a detailed technical analysis with MITRE ATT&CK context for the following CVE vulnerability:

CVE ID: {cve['id']}
Title: {cve['title']}
Description: {cve['description']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})

Analyze the technical aspects including attack vectors, MITRE techniques, and technical impact."""

    response = f"""## Technical Analysis: {cve['id']}

**Vulnerability Overview:**
{cve['title']}

**Technical Description:**
{cve['description']}

**CVSS Analysis:**
- Base Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
- The high CVSS score indicates significant security impact

**Attack Vector Analysis:**
Based on the CVSS metrics, this vulnerability:
- Can be exploited over the network (AV:N)
- Requires low attack complexity (AC:L)
- Does not require authentication (PR:N)
- Does not require user interaction (UI:N)
- Has high impact on confidentiality, integrity, and availability (C:H/I:H/A:H)"""

    if cve['cwes']:
        response += f"\n\n**Underlying Weaknesses:**\n- CWE IDs: {', '.join(cve['cwes'])}\n- These represent the root causes that should be addressed in future development"

    if cve['mitre_technique_details']:
        response += f"\n\n**MITRE ATT&CK Analysis:**"
        for tech in cve['mitre_technique_details'][:3]:
            response += f"\n\n**{tech['id']} ({tech['name']}):**"
            response += f"\n- Description: {tech['description'][:150]}..."
            if tech['detection']:
                response += f"\n- Detection: {tech['detection'][:150]}..."

    if cve['capecs']:
        response += f"\n\n**Attack Patterns:**\n- CAPEC IDs: {', '.join(cve['capecs'])}\n- These represent common attack patterns associated with this vulnerability"

    response += f"""

**Technical Impact:**
- **Confidentiality:** High - sensitive data may be exposed
- **Integrity:** High - data or system integrity may be compromised
- **Availability:** High - system availability may be affected

**Exploitation Complexity:**
The low attack complexity suggests this vulnerability can be exploited with minimal effort and resources."""

    examples.append({
        "instruction": "Provide a detailed technical analysis with MITRE ATT&CK context for this CVE vulnerability.",
        "input": prompt,
        "output": response
    })
    
    return examples

def create_detection_examples(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    """Create detection strategy training examples."""
    examples = []
    
    if not cve['mitre_technique_details']:
        return examples
    
    prompt = f"""Create detection strategies for the following CVE vulnerability:

CVE ID: {cve['id']}
Title: {cve['title']}
Description: {cve['description']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})

What detection methods and monitoring strategies should be implemented for this vulnerability?"""

    response = f"""## Detection Strategies for {cve['id']}

**Vulnerability Context:**
{cve['title']}
- CVSS Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
- Severity: {cve['cvss_v3_severity']}

**Detection Approach:**

1. **Network Monitoring:**
   - Monitor for unusual network traffic patterns
   - Implement IDS/IPS rules for known attack signatures
   - Monitor for failed authentication attempts

2. **System Monitoring:**
   - Monitor system logs for suspicious activities
   - Track file system changes and unusual processes
   - Monitor for privilege escalation attempts"""

    if cve['mitre_technique_details']:
        response += f"\n\n**MITRE ATT&CK Detection Strategies:**"
        for tech in cve['mitre_technique_details'][:3]:
            response += f"\n\n**For {tech['id']} ({tech['name']}):**"
            if tech['detection']:
                response += f"\n- **Detection Method:** {tech['detection'][:200]}..."
            if tech['data_sources']:
                response += f"\n- **Data Sources:** {tech['data_sources']}"
            response += f"\n- **Monitoring Focus:** Look for indicators of {tech['name'].lower()}"

    response += f"""

**SIEM Correlation Rules:**
- Create alerts for multiple failed authentication attempts
- Monitor for unusual process execution patterns
- Track network connections to suspicious destinations

**Log Analysis:**
- Review authentication logs for unusual patterns
- Monitor system logs for privilege escalation
- Track application logs for error conditions

**Threat Hunting:**
- Search for indicators of compromise (IOCs)
- Look for persistence mechanisms
- Investigate unusual network connections"""

    examples.append({
        "instruction": "Create comprehensive detection strategies for this CVE vulnerability.",
        "input": prompt,
        "output": response
    })
    
    return examples

def create_mitigation_strategy_examples(cve: Dict[str, Any]) -> List[Dict[str, str]]:
    """Create mitigation strategy training examples."""
    examples = []
    
    if not cve['mitre_technique_details']:
        return examples
    
    prompt = f"""Develop a comprehensive mitigation strategy for the following CVE vulnerability:

CVE ID: {cve['id']}
Title: {cve['title']}
Description: {cve['description']}
CVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})

What mitigation strategies and security controls should be implemented?"""

    response = f"""## Mitigation Strategy for {cve['id']}

**Vulnerability Overview:**
{cve['title']}
- CVSS Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})
- Priority: {'Critical' if cve['cvss_v3_score'] >= 9.0 else 'High' if cve['cvss_v3_score'] >= 7.0 else 'Medium'}

**Defense-in-Depth Strategy:**

1. **Preventive Controls:**
   - Implement network segmentation
   - Use application whitelisting
   - Apply principle of least privilege
   - Implement strong authentication mechanisms

2. **Detective Controls:**
   - Deploy intrusion detection systems
   - Implement comprehensive logging
   - Use security information and event management (SIEM)
   - Regular vulnerability assessments"""

    if cve['mitre_technique_details']:
        response += f"\n\n**MITRE ATT&CK Mitigation Strategies:**"
        for tech in cve['mitre_technique_details'][:3]:
            response += f"\n\n**Mitigating {tech['id']} ({tech['name']}):**"
            response += f"\n- **Technique Description:** {tech['description'][:150]}..."
            response += f"\n- **Mitigation Approach:**"
            response += f"\n  - Implement access controls to prevent {tech['name'].lower()}"
            response += f"\n  - Use monitoring and alerting for detection"
            response += f"\n  - Apply security hardening measures"

    if cve['cwes']:
        response += f"\n\n**Addressing Root Causes:**\n- **CWE Focus:** {', '.join(cve['cwes'])}\n- Implement secure coding practices\n- Use static and dynamic code analysis\n- Provide developer security training"

    response += f"""

**Implementation Timeline:**
1. **Immediate (0-24 hours):** Apply emergency patches and workarounds
2. **Short-term (1-7 days):** Implement compensating controls
3. **Medium-term (1-4 weeks):** Deploy comprehensive security controls
4. **Long-term (1-6 months):** Implement preventive measures and training

**Success Metrics:**
- Reduced attack surface
- Improved detection capabilities
- Enhanced incident response readiness
- Decreased vulnerability exposure time"""

    examples.append({
        "instruction": "Develop a comprehensive mitigation strategy for this CVE vulnerability.",
        "input": prompt,
        "output": response
    })
    
    return examples

if __name__ == "__main__":
    create_enhanced_dataset_with_mitigations() 