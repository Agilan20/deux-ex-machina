"""
Central Orchestrator
--------------------
Coordinates the multi-agent network according to Section 3 of
ai_dependency_remediation_agent_guide.md:
  1. Dependency Analyst (Agent 1)
  2. Vulnerability Analyst (Agent 2)
  3. Upgrade Planner (Agent 3)
  4. Code Remediator (Agent 4)
  5. Validator & PR Agent (Agent 5)
"""

from typing import Any, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentic.graph_service import GraphService
from agentic.llm import LLMClient
from agentic.agents.dependency_analyst import DependencyAnalystAgent
from agentic.agents.vulnerability_analyst import VulnerabilityAnalystAgent
from agentic.agents.upgrade_planner import UpgradePlannerAgent
from agentic.agents.code_remediator import CodeRemediatorAgent
from agentic.agents.validator_pr import ValidatorPRAgent

console = Console(force_terminal=True, highlight=False)


class CentralOrchestrator:
    def __init__(self, graph_name: Optional[str] = None):
        self.graph_service = GraphService(graph_name) if graph_name else GraphService()
        self.llm = LLMClient()

        # Initialize all 5 specialized agents
        self.agent1_dep = DependencyAnalystAgent(self.graph_service, self.llm)
        self.agent2_vuln = VulnerabilityAnalystAgent(self.graph_service, self.llm)
        self.agent3_plan = UpgradePlannerAgent(self.graph_service, self.llm)
        self.agent4_code = CodeRemediatorAgent(self.graph_service, self.llm)
        self.agent5_valid = ValidatorPRAgent(self.graph_service, self.llm)

    def run_remediation_pipeline(
        self,
        repo_name: str,
        repo_url: str,
        branch: str,
        manifest_path: str,
        dependency_tree: Dict[str, Any],
        snyk_scan_data: Dict[str, Any],
        code_symbols: Optional[list] = None,
        test_mappings: Optional[list] = None,
        target_cve: Optional[str] = None,
        reset_graph_first: bool = True,
        publish_pr: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes the end-to-end multi-agent dependency remediation pipeline.
        """
        console.print(
            Panel(
                "[bold cyan]AI Dependency Remediation Agent Network[/]\n"
                "[dim]Autonomous Vulnerability & Blast Radius Analysis via FalkorDB[/]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        if reset_graph_first:
            console.print("[dim]Resetting and initializing schema in FalkorDB...[/]")
            self.graph_service.clear_graph()
            self.graph_service.init_schema()

        # ── Step 1: Agent 1 (Dependency Discovery & Graph Ingestion) ──
        console.print("\n[bold yellow]=== Stage 1: Dependency Analyst (Agent 1) ===[/]")
        stage1_output = self.agent1_dep.analyze_and_ingest(
            repo_name=repo_name,
            repo_url=repo_url,
            branch=branch,
            manifest_path=manifest_path,
            dependency_tree=dependency_tree,
            code_symbols=code_symbols,
            test_mappings=test_mappings,
        )

        # ── Step 2: Agent 2 (Vulnerability Enrichment) ──
        console.print("\n[bold yellow]=== Stage 2: Vulnerability Analyst (Agent 2) ===[/]")
        stage2_output = self.agent2_vuln.analyze_and_enrich(snyk_scan_data)

        # Print FalkorDB graph node summary
        summary = self.graph_service.get_graph_summary()
        summary_table = Table(title="FalkorDB Graph Node Count Summary", border_style="cyan")
        summary_table.add_column("Node Label", style="bold green")
        summary_table.add_column("Count", style="white")
        for label, count in summary.items():
            summary_table.add_row(label, str(count))
        console.print(summary_table)

        # ── Step 3: Agent 3 (Upgrade Planner & Blast Radius) ──
        console.print("\n[bold yellow]=== Stage 3: Upgrade Planner (Agent 3) ===[/]")
        stage3_plan = self.agent3_plan.plan_remediation(cve_id=target_cve)

        # ── Step 4: Agent 4 (Code & Manifest Remediator) ──
        console.print("\n[bold yellow]=== Stage 4: Code Remediator (Agent 4) ===[/]")
        stage4_patches = self.agent4_code.remediate(stage3_plan)

        # ── Step 5: Agent 5 (Validator & PR Agent) ──
        console.print("\n[bold yellow]=== Stage 5: Validator & PR Agent (Agent 5) ===[/]")
        stage5_pr = self.agent5_valid.validate_and_draft_pr(
            execution_plan=stage3_plan,
            remediation_result=stage4_patches,
            repo_name=repo_name,
            publish_pr=publish_pr,
        )

        console.print(
            Panel(
                f"[bold green]Pipeline Execution Completed Successfully![/]\n"
                f"PR Title: [cyan]{stage5_pr['prTitle']}[/]\n"
                f"Branch: [yellow]{stage5_pr['branch']}[/]",
                border_style="green",
            )
        )

        return {
            "stage1_dependency_analysis": stage1_output,
            "stage2_vulnerability_enrichment": stage2_output,
            "stage3_upgrade_plan": stage3_plan,
            "stage4_code_patches": stage4_patches,
            "stage5_pr_payload": stage5_pr,
        }
