"""
Agent 3: Upgrade Planner
------------------------
Task: Executes analytical Cypher queries on FalkorDB to determine transitive paths,
      blast radius on application code, and test coverage.
      Uses LLM grounded reasoning to formulate an ordered, low-risk upgrade strategy.
Output: Remediation Execution Plan JSON and UpgradeCandidate nodes in FalkorDB.
"""

import json
from typing import Any, Dict, List, Optional
from agentic.agents.base_agent import BaseAgent
from agentic.graph_service import GraphService
from agentic.llm import LLMClient


class UpgradePlannerAgent(BaseAgent):
    def __init__(self, graph_service: GraphService, llm: LLMClient):
        super().__init__(
            name="Agent 3: Upgrade Planner",
            role="Blast Radius Analysis & Strategic Upgrade Planning",
            graph_service=graph_service,
            llm=llm,
        )

    def plan_remediation(self, cve_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes Section 4 Cypher queries against FalkorDB, evaluates blast radius,
        and generates an actionable remediation plan.
        """
        self.log_step("Querying FalkorDB for active vulnerabilities...")
        vulns = self.graph_service.query_all_vulnerabilities()

        if not vulns:
            self.log_warning("No active vulnerabilities found in FalkorDB graph.")
            return {"status": "NO_VULNERABILITIES", "plan": []}

        plans = []
        for v in vulns:
            target_cve = v["cveId"]
            if cve_id and target_cve != cve_id:
                continue

            self.log_step(f"Analyzing impact for [bold red]{target_cve}[/]...")

            # 1. Query 1: Find direct dependencies bringing in transitive vulnerability
            transitive_info = self.graph_service.query_transitive_vulnerabilities(target_cve)

            # 2. Query 2: Compute blast radius on application code
            blast_radius_info = self.graph_service.query_blast_radius(target_cve)

            # Extract impacted symbols and tests
            affected_symbols = []
            impacted_tests = []
            for b in blast_radius_info:
                affected_symbols.extend(b.get("AffectedCodeSymbols", []))
                impacted_tests.extend(b.get("ImpactedTests", []))

            affected_symbols = list(set(affected_symbols))
            impacted_tests = list(set(impacted_tests))

            # Determine whether this is a direct or transitive vulnerability
            is_transitive = False
            direct_parent = None
            dep_chain = []
            if transitive_info:
                first_match = transitive_info[0]
                dep_chain = first_match.get("DependencyChain", [])
                direct_parent = first_match.get("DirectDependency")
                is_transitive = len(dep_chain) > 1

            remediation_ver = v.get("remediationVersion", "latest-secure")
            vulnerable_purl = v.get("purl")

            # Determine strategic action
            # Direct: bump manifest version
            # Transitive: add <dependencyManagement> override or exclude
            if is_transitive:
                action_type = "DEPENDENCY_MANAGEMENT_OVERRIDE"
                strategy_desc = (
                    f"Transitive vulnerability introduced via [{direct_parent}]. "
                    f"Override target version to [{remediation_ver}] in <dependencyManagement> "
                    f"without risking breakages in direct dependencies."
                )
            else:
                action_type = "DIRECT_VERSION_BUMP"
                strategy_desc = (
                    f"Direct dependency [{vulnerable_purl}]. "
                    f"Bump version directly in pom.xml to [{remediation_ver}]."
                )

            # Record UpgradeCandidate in FalkorDB
            self.graph_service.record_upgrade_candidate(
                vulnerable_purl=vulnerable_purl,
                target_version=remediation_ver,
                status="PLANNED",
                breaks_compatibility=len(affected_symbols) > 5,  # Heuristic marker
            )

            # Grounded LLM Prompt to synthesize plan
            llm_prompt = f"""
            You are an autonomous AI Dependency Upgrade Planner.
            Analyze the following FalkorDB graph-grounded vulnerability and blast radius data:

            - Vulnerability: {target_cve} ({v.get('severity')}, CVSS: {v.get('cvssScore')})
            - Title: {v.get('title')}
            - Vulnerable Package: {vulnerable_purl}
            - Fix Target Version: {remediation_ver}
            - Is Transitive: {is_transitive}
            - Direct Parent: {direct_parent}
            - Dependency Chain: {' -> '.join(dep_chain)}
            - Affected Application Code Symbols: {affected_symbols}
            - Impacted Unit/Integration Tests: {impacted_tests}

            Provide a concise technical assessment:
            1. Risk Level (Low/Medium/High)
            2. Recommended Remediation Strategy (Direct Bump or DependencyManagement override)
            3. Breaking Change Verification instructions
            """

            system_instruction = "You are a software security engineer. Ground all advice in the provided dependency graph."
            ai_reasoning = self.llm.generate(llm_prompt, system_instruction)

            item_plan = {
                "cveId": target_cve,
                "severity": v.get("severity"),
                "cvssScore": v.get("cvssScore"),
                "vulnerablePackage": vulnerable_purl,
                "targetVersion": remediation_ver,
                "isTransitive": is_transitive,
                "directParent": direct_parent,
                "dependencyChain": dep_chain,
                "affectedSymbols": affected_symbols,
                "impactedTests": impacted_tests,
                "actionType": action_type,
                "strategy": strategy_desc,
                "aiReasoning": ai_reasoning,
            }
            plans.append(item_plan)

            self.log_success(
                f"Planned upgrade for {target_cve} -> [{remediation_ver}] "
                f"({action_type}, {len(affected_symbols)} symbols, {len(impacted_tests)} tests affected)"
            )

        return {
            "status": "SUCCESS",
            "totalVulnerabilities": len(plans),
            "remediationPlan": plans,
        }
