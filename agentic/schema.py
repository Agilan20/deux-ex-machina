"""
FalkorDB Graph Schema Definitions for AI Dependency Remediation.
Directly implements Section 2 of ai_dependency_remediation_agent_guide.md.
"""

from dataclasses import dataclass
from typing import List


class NodeLabels:
    REPOSITORY = "Repository"
    MANIFEST = "Manifest"
    PACKAGE = "Package"
    PACKAGE_VERSION = "PackageVersion"
    VULNERABILITY = "Vulnerability"
    CODE_SYMBOL = "CodeSymbol"
    TEST = "Test"
    UPGRADE_CANDIDATE = "UpgradeCandidate"


class RelTypes:
    CONTAINS = "CONTAINS"                       # (Repository)-[:CONTAINS]->(Manifest)
    DECLARES = "DECLARES"                       # (Manifest)-[:DECLARES]->(PackageVersion)
    DEPENDS_ON = "DEPENDS_ON"                   # (PackageVersion)-[:DEPENDS_ON]->(PackageVersion)
    AFFECTED_BY = "AFFECTED_BY"                 # (PackageVersion)-[:AFFECTED_BY]->(Vulnerability)
    USES_API = "USES_API"                       # (CodeSymbol)-[:USES_API]->(PackageVersion)
    BREAKS_COMPATIBILITY_WITH = "BREAKS_COMPATIBILITY_WITH"  # (UpgradeCandidate)-[:BREAKS_COMPATIBILITY_WITH]->(PackageVersion)
    VALIDATED_BY = "VALIDATED_BY"               # (UpgradeCandidate)-[:VALIDATED_BY]->(Test)
    TESTS = "TESTS"                             # (Test)-[:TESTS]->(CodeSymbol)


# Schema index creation queries for fast path traversals in FalkorDB
INDEX_QUERIES: List[str] = [
    f"CREATE INDEX FOR (r:{NodeLabels.REPOSITORY}) ON (r.name)",
    f"CREATE INDEX FOR (m:{NodeLabels.MANIFEST}) ON (m.path)",
    f"CREATE INDEX FOR (pv:{NodeLabels.PACKAGE_VERSION}) ON (pv.purl)",
    f"CREATE INDEX FOR (v:{NodeLabels.VULNERABILITY}) ON (v.cveId)",
    f"CREATE INDEX FOR (cs:{NodeLabels.CODE_SYMBOL}) ON (cs.qualifiedName)",
    f"CREATE INDEX FOR (t:{NodeLabels.TEST}) ON (t.name)",
]
