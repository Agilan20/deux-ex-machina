"""
Agent 1: Dependency Analyst
---------------------------
Task: Analyzes target repository manifest and package-manager resolution trees
      (e.g., mvn dependency:tree or lockfiles). Populates FalkorDB with direct
      and transitive package hierarchies, code symbols, and test mappings.
Output: Initial Dependency Graph in FalkorDB.
"""

from typing import Any, Dict, List
from agentic.agents.base_agent import BaseAgent
from agentic.graph_service import GraphService
from agentic.llm import LLMClient


class DependencyAnalystAgent(BaseAgent):
    def __init__(self, graph_service: GraphService, llm: LLMClient):
        super().__init__(
            name="Agent 1: Dependency Analyst",
            role="Dependency Discovery & Graph Ingestion",
            graph_service=graph_service,
            llm=llm,
        )

    def analyze_and_ingest(
        self,
        repo_name: str,
        repo_url: str,
        branch: str,
        manifest_path: str,
        dependency_tree: Dict[str, Any],
        code_symbols: List[Dict[str, Any]] = None,
        test_mappings: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parses dependency tree structure and ingests it into FalkorDB.
        """
        self.log_step(f"Analyzing repository '{repo_name}' on branch '{branch}'...")

        # 1. Ingest Repository and Manifest
        self.graph_service.ingest_repository(repo_name, repo_url, branch)
        self.graph_service.ingest_manifest(repo_name, manifest_path, manifest_type="pom.xml")
        self.log_success(f"Ingested Repository node and Manifest '{manifest_path}'")

        direct_count = 0
        transitive_count = 0

        # 2. Ingest Direct and Transitive Dependencies
        # Format of dependency_tree:
        # direct_deps: list of { groupId, artifactId, version, scope, dependencies: [...] }
        for direct in dependency_tree.get("direct_dependencies", []):
            direct_purl = self.graph_service.ingest_direct_dependency(
                manifest_path=manifest_path,
                group_id=direct["groupId"],
                artifact_id=direct["artifactId"],
                version=direct["version"],
                scope=direct.get("scope", "compile"),
            )
            direct_count += 1

            # Ingest Transitive Dependencies under this direct dependency
            for trans in direct.get("transitive_dependencies", []):
                self.graph_service.ingest_transitive_dependency(
                    parent_purl=direct_purl,
                    group_id=trans["groupId"],
                    artifact_id=trans["artifactId"],
                    version=trans["version"],
                    scope=trans.get("scope", "compile"),
                )
                transitive_count += 1

        self.log_success(f"Ingested {direct_count} direct and {transitive_count} transitive dependencies into FalkorDB")

        # 3. Ingest Code Symbols (USES_API relationships)
        symbols_count = 0
        if code_symbols:
            for sym in code_symbols:
                self.graph_service.ingest_code_symbol(
                    qualified_name=sym["qualifiedName"],
                    file_path=sym["file"],
                    line=sym.get("line", 1),
                    target_package_purl=sym["targetPurl"],
                )
                symbols_count += 1
            self.log_success(f"Linked {symbols_count} application CodeSymbols to package APIs")

        # 4. Ingest Test Mappings (TESTS relationships)
        test_count = 0
        if test_mappings:
            for tm in test_mappings:
                self.graph_service.ingest_test_link(
                    test_name=tm["name"],
                    test_file=tm["filePath"],
                    code_symbol_name=tm["testsSymbol"],
                )
                test_count += 1
            self.log_success(f"Linked {test_count} unit tests to CodeSymbols")

        return {
            "repository": repo_name,
            "manifest": manifest_path,
            "direct_dependencies_count": direct_count,
            "transitive_dependencies_count": transitive_count,
            "code_symbols_count": symbols_count,
            "tests_count": test_count,
        }
