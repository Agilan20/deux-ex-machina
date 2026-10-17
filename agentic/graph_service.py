"""
FalkorDB Graph Service
----------------------
Manages graph interactions for the AI Dependency Remediation Agent System.
Provides high-level methods to ingest code structure, dependency trees,
vulnerabilities, and execute Cypher queries (including blast-radius analysis).
"""

from typing import Any, Dict, List, Optional
from db.connection import get_client
from agentic.config import FALKORDB_GRAPH_NAME
from agentic.schema import NodeLabels, RelTypes, INDEX_QUERIES


class GraphService:
    def __init__(self, graph_name: str = FALKORDB_GRAPH_NAME):
        self.graph_name = graph_name
        self.client = get_client()
        self.graph = self.client.select_graph(self.graph_name)

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None):
        """Execute a Cypher query with error handling."""
        try:
            return self.graph.query(cypher, params)
        except Exception as e:
            # Re-raise with context
            raise RuntimeError(f"FalkorDB query failed on [{self.graph_name}]: {e}\nQuery:\n{cypher}") from e

    def init_schema(self) -> None:
        """Create indices to optimize path traversals."""
        for query in INDEX_QUERIES:
            try:
                self.query(query)
            except Exception:
                # FalkorDB may raise if index already exists
                pass

    def clear_graph(self) -> None:
        """Clear all nodes and relationships in the current graph."""
        try:
            self.query("MATCH (n) DETACH DELETE n")
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────
    # Ingestion Methods (Agents 1 & 2)
    # ─────────────────────────────────────────────────────────────

    def ingest_repository(self, name: str, url: str, branch: str = "main") -> None:
        cypher = f"""
        MERGE (r:{NodeLabels.REPOSITORY} {{name: $name}})
        ON CREATE SET r.url = $url, r.branch = $branch
        ON MATCH SET r.url = $url, r.branch = $branch
        """
        self.query(cypher, {"name": name, "url": url, "branch": branch})

    def ingest_manifest(self, repo_name: str, path: str, manifest_type: str = "pom.xml") -> None:
        cypher = f"""
        MATCH (r:{NodeLabels.REPOSITORY} {{name: $repo_name}})
        MERGE (m:{NodeLabels.MANIFEST} {{path: $path}})
        ON CREATE SET m.type = $manifest_type
        MERGE (r)-[:{RelTypes.CONTAINS}]->(m)
        """
        self.query(cypher, {"repo_name": repo_name, "path": path, "manifest_type": manifest_type})

    def ingest_direct_dependency(
        self,
        manifest_path: str,
        group_id: str,
        artifact_id: str,
        version: str,
        scope: str = "compile",
    ) -> str:
        purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
        cypher = f"""
        MATCH (m:{NodeLabels.MANIFEST} {{path: $manifest_path}})
        MERGE (p:{NodeLabels.PACKAGE} {{groupId: $group_id, artifactId: $artifact_id}})
        MERGE (pv:{NodeLabels.PACKAGE_VERSION} {{purl: $purl}})
        ON CREATE SET pv.version = $version, pv.groupId = $group_id, pv.artifactId = $artifact_id, pv.scope = $scope
        MERGE (p)-[:HAS_VERSION]->(pv)
        MERGE (m)-[:{RelTypes.DECLARES}]->(pv)
        """
        self.query(
            cypher,
            {
                "manifest_path": manifest_path,
                "group_id": group_id,
                "artifact_id": artifact_id,
                "version": version,
                "purl": purl,
                "scope": scope,
            },
        )
        return purl

    def ingest_transitive_dependency(
        self,
        parent_purl: str,
        group_id: str,
        artifact_id: str,
        version: str,
        scope: str = "compile",
    ) -> str:
        child_purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
        cypher = f"""
        MATCH (parent:{NodeLabels.PACKAGE_VERSION} {{purl: $parent_purl}})
        MERGE (p:{NodeLabels.PACKAGE} {{groupId: $group_id, artifactId: $artifact_id}})
        MERGE (child:{NodeLabels.PACKAGE_VERSION} {{purl: $child_purl}})
        ON CREATE SET child.version = $version, child.groupId = $group_id, child.artifactId = $artifact_id, child.scope = $scope
        MERGE (p)-[:HAS_VERSION]->(child)
        MERGE (parent)-[:{RelTypes.DEPENDS_ON}]->(child)
        """
        self.query(
            cypher,
            {
                "parent_purl": parent_purl,
                "group_id": group_id,
                "artifact_id": artifact_id,
                "version": version,
                "child_purl": child_purl,
                "scope": scope,
            },
        )
        return child_purl

    def ingest_vulnerability(
        self,
        target_purl: str,
        cve_id: str,
        severity: str,
        cvss_score: float,
        title: str = "",
        remediation_version: str = "",
    ) -> None:
        cypher = f"""
        MATCH (pv:{NodeLabels.PACKAGE_VERSION} {{purl: $target_purl}})
        MERGE (v:{NodeLabels.VULNERABILITY} {{cveId: $cve_id}})
        ON CREATE SET v.severity = $severity, v.cvssScore = $cvss_score,
                      v.title = $title, v.remediationVersion = $remediation_version
        MERGE (pv)-[:{RelTypes.AFFECTED_BY}]->(v)
        """
        self.query(
            cypher,
            {
                "target_purl": target_purl,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "title": title,
                "remediation_version": remediation_version,
            },
        )

    def ingest_code_symbol(
        self,
        qualified_name: str,
        file_path: str,
        line: int,
        target_package_purl: str,
    ) -> None:
        cypher = f"""
        MATCH (pv:{NodeLabels.PACKAGE_VERSION} {{purl: $target_purl}})
        MERGE (cs:{NodeLabels.CODE_SYMBOL} {{qualifiedName: $qualified_name}})
        ON CREATE SET cs.file = $file_path, cs.line = $line
        MERGE (cs)-[:{RelTypes.USES_API}]->(pv)
        """
        self.query(
            cypher,
            {
                "qualified_name": qualified_name,
                "file_path": file_path,
                "line": line,
                "target_purl": target_package_purl,
            },
        )

    def ingest_test_link(self, test_name: str, test_file: str, code_symbol_name: str) -> None:
        cypher = f"""
        MATCH (cs:{NodeLabels.CODE_SYMBOL} {{qualifiedName: $code_symbol_name}})
        MERGE (t:{NodeLabels.TEST} {{name: $test_name}})
        ON CREATE SET t.filePath = $test_file
        MERGE (t)-[:{RelTypes.TESTS}]->(cs)
        """
        self.query(
            cypher,
            {"test_name": test_name, "test_file": test_file, "code_symbol_name": code_symbol_name},
        )

    def record_upgrade_candidate(
        self,
        vulnerable_purl: str,
        target_version: str,
        status: str = "PLANNED",
        breaks_compatibility: bool = False,
    ) -> None:
        candidate_purl = f"{vulnerable_purl.split('@')[0]}@{target_version}"
        cypher = f"""
        MATCH (pv:{NodeLabels.PACKAGE_VERSION} {{purl: $vulnerable_purl}})
        MERGE (uc:{NodeLabels.UPGRADE_CANDIDATE} {{targetVersion: $target_version, targetPurl: $candidate_purl}})
        ON CREATE SET uc.status = $status
        """
        self.query(
            cypher,
            {
                "vulnerable_purl": vulnerable_purl,
                "target_version": target_version,
                "candidate_purl": candidate_purl,
                "status": status,
            },
        )

        if breaks_compatibility:
            compat_cypher = f"""
            MATCH (uc:{NodeLabels.UPGRADE_CANDIDATE} {{targetPurl: $candidate_purl}})
            MATCH (pv:{NodeLabels.PACKAGE_VERSION} {{purl: $vulnerable_purl}})
            MERGE (uc)-[:{RelTypes.BREAKS_COMPATIBILITY_WITH}]->(pv)
            """
            self.query(compat_cypher, {"candidate_purl": candidate_purl, "vulnerable_purl": vulnerable_purl})

    # ─────────────────────────────────────────────────────────────
    # Analytical Cypher Queries (Agent 3: Upgrade Planner)
    # ─────────────────────────────────────────────────────────────

    def query_transitive_vulnerabilities(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Query 1 from Section 4:
        Find the direct dependency responsible for bringing in a transitive vulnerability.
        """
        cypher = f"""
        MATCH (m:{NodeLabels.MANIFEST})-[:{RelTypes.DECLARES}]->(direct:{NodeLabels.PACKAGE_VERSION})
        MATCH path = (direct)-[:{RelTypes.DEPENDS_ON}*0..5]->(transitive:{NodeLabels.PACKAGE_VERSION})
        MATCH (transitive)-[:{RelTypes.AFFECTED_BY}]->(v:{NodeLabels.VULNERABILITY})
        WHERE v.cveId = $cve_id
        RETURN direct.purl AS DirectDependency,
               transitive.purl AS VulnerablePackage,
               [n IN nodes(path) | n.purl] AS DependencyChain
        """
        res = self.query(cypher, {"cve_id": cve_id})
        records = []
        for row in res.result_set:
            records.append({
                "DirectDependency": row[0],
                "VulnerablePackage": row[1],
                "DependencyChain": row[2],
            })
        return records

    def query_blast_radius(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Query 2 from Section 4:
        Compute impact blast radius on application code:
        vulnerability -> package -> code symbols -> impact tests.
        """
        cypher = f"""
        MATCH (v:{NodeLabels.VULNERABILITY} {{cveId: $cve_id}})<-[:{RelTypes.AFFECTED_BY}]-(pkg:{NodeLabels.PACKAGE_VERSION})
        OPTIONAL MATCH (sym:{NodeLabels.CODE_SYMBOL})-[:{RelTypes.USES_API}]->(pkg)
        OPTIONAL MATCH (t:{NodeLabels.TEST})-[:{RelTypes.TESTS}]->(sym)
        RETURN pkg.purl AS VulnerablePackage,
               collect(DISTINCT sym.qualifiedName) AS AffectedCodeSymbols,
               collect(DISTINCT t.name) AS ImpactedTests
        """
        res = self.query(cypher, {"cve_id": cve_id})
        records = []
        for row in res.result_set:
            # FalkorDB may return None or empty lists
            symbols = [s for s in (row[1] or []) if s is not None]
            tests = [t for t in (row[2] or []) if t is not None]
            records.append({
                "VulnerablePackage": row[0],
                "AffectedCodeSymbols": symbols,
                "ImpactedTests": tests,
            })
        return records

    def query_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Retrieve all vulnerabilities and their affected packages and severities."""
        cypher = f"""
        MATCH (v:{NodeLabels.VULNERABILITY})<-[:{RelTypes.AFFECTED_BY}]-(pv:{NodeLabels.PACKAGE_VERSION})
        RETURN v.cveId AS cveId,
               v.severity AS severity,
               v.cvssScore AS cvssScore,
               v.remediationVersion AS remediationVersion,
               v.title AS title,
               pv.purl AS purl
        ORDER BY v.cvssScore DESC
        """
        res = self.query(cypher)
        records = []
        for row in res.result_set:
            records.append({
                "cveId": row[0],
                "severity": row[1],
                "cvssScore": row[2],
                "remediationVersion": row[3],
                "title": row[4],
                "purl": row[5],
            })
        return records

    def get_graph_summary(self) -> Dict[str, int]:
        """Return counts of all nodes in the graph."""
        summary = {}
        for label in [
            NodeLabels.REPOSITORY,
            NodeLabels.MANIFEST,
            NodeLabels.PACKAGE_VERSION,
            NodeLabels.VULNERABILITY,
            NodeLabels.CODE_SYMBOL,
            NodeLabels.TEST,
            NodeLabels.UPGRADE_CANDIDATE,
        ]:
            res = self.query(f"MATCH (n:{label}) RETURN count(n)")
            summary[label] = res.result_set[0][0] if res.result_set else 0
        return summary
