from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class NodeType(Enum):
    CVE = "CVE"
    CWE = "CWE"
    CAPEC = "CAPEC"
    TECHNIQUE = "Technique"
    TACTIC = "Tactic"
    PRODUCT = "Product"
    VENDOR = "Vendor"
    VERSION = "Version"
    PLATFORM = "Platform"
    EXPLOIT = "Exploit"
    ADVISORY = "Advisory"
    THREAT_ACTOR = "ThreatActor"

@dataclass
class CVENode:
    id: str
    description: str
    published_date: str
    modified_date: str
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None
    cvss_v4_score: Optional[float] = None
    severity: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    has_public_exploit: bool = False
    has_patch: bool = False
    weaponization_level: str = "UNKNOWN"

@dataclass
class ProductNode:
    cpe: str
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
    product_family: Optional[str] = None
    product_category: Optional[str] = None
    is_end_of_life: bool = False
    support_status: str = "UNKNOWN"
    market_share: float = 0.0
    criticality_score: float = 0.0

@dataclass
class VendorNode:
    name: str
    aliases: List[str]
    website: Optional[str] = None
    vendor_type: Optional[str] = None
    market_cap: Optional[float] = None
    is_fortune_500: bool = False

@dataclass
class VersionNode:
    id: str
    version_string: str
    release_date: Optional[str] = None
    is_latest: bool = False
    is_lts: bool = False
    predecessor: Optional[str] = None
    successor: Optional[str] = None

@dataclass
class PlatformNode:
    name: str
    platform_type: str
    description: Optional[str] = None

@dataclass
class WeaknessNode:
    id: str
    name: str
    description: str
    abstraction: Optional[str] = None
    status: Optional[str] = None
    parent_cwe: Optional[str] = None
    child_cwes: Optional[List[str]] = None
    likelihood: str = "UNKNOWN"
    technical_impact: Optional[List[str]] = None

@dataclass
class AttackPatternNode:
    id: str
    name: str
    description: str
    abstraction: Optional[str] = None
    status: Optional[str] = None
    typical_severity: Optional[str] = None
    typical_likelihood: Optional[str] = None
    execution_flow: Optional[List[str]] = None
    prerequisites: Optional[List[str]] = None
    skills_required: Optional[List[str]] = None
    resources_required: Optional[List[str]] = None

@dataclass
class TechniqueNode:
    id: str
    name: str
    description: str
    tactic: Optional[str] = None
    platforms: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None
    detection_methods: Optional[List[str]] = None
    mitigations: Optional[List[str]] = None
    version: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    is_sub_technique: bool = False
    parent_technique: Optional[str] = None

@dataclass
class ExploitNode:
    id: str
    title: str
    description: str
    exploit_type: Optional[str] = None
    platform: Optional[str] = None
    author: Optional[str] = None
    date_published: Optional[str] = None
    verified: bool = False
    exploit_code: Optional[str] = None
    proof_of_concept: bool = False
    reliability: str = "UNKNOWN"

class RelationshipType(Enum):
    AFFECTS = "AFFECTS"
    EXPLOITS = "EXPLOITS"
    RELATES_TO = "RELATES_TO"
    USES_PATTERN = "USES_PATTERN"
    IMPLEMENTS_TECHNIQUE = "IMPLEMENTS_TECHNIQUE"
    MANUFACTURED_BY = "MANUFACTURED_BY"
    HAS_VERSION = "HAS_VERSION"
    RUNS_ON = "RUNS_ON"
    DEPENDS_ON = "DEPENDS_ON"
    SUPERSEDED_BY = "SUPERSEDED_BY"
    PARENT_OF = "PARENT_OF"
    CHILD_OF = "CHILD_OF"
    RELATED_TO = "RELATED_TO"
    PREREQUISITE_FOR = "PREREQUISITE_FOR"
    FOLLOWS = "FOLLOWS"
    TARGETS = "TARGETS"
    DISCOVERED_BEFORE = "DISCOVERED_BEFORE"
    PATCHED_BY = "PATCHED_BY"
    SIMILAR_TO = "SIMILAR_TO"
    VARIANT_OF = "VARIANT_OF" 