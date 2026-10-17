"""
Real-world Verification Script: Agilan20/spring-advanced-training
----------------------------------------------------------------
1. Clones/reads real repository and manifest (sat-rest/pom.xml).
2. Uses MavenTool to generate and parse real `mvn dependency:tree` (150 package versions).
3. Ingests all direct & transitive package hierarchies into FalkorDB Cloud.
4. Enriches FalkorDB with vulnerability advisories.
5. Executes Section 4 Cypher queries (Query 1 & Query 2) against FalkorDB.
6. Feeds FalkorDB blast-radius context directly into Google Gemini (gemini-3.8-flash).
7. Outputs full graph audit evidence and remediation plan.
"""

import sys
import io

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentic.graph_service import GraphService
from agentic.llm import LLMClient
from agentic.tools.maven_tool import MavenTool
from agentic.agents.dependency_analyst import DependencyAnalystAgent
from agentic.agents.vulnerability_analyst import VulnerabilityAnalystAgent
from agentic.agents.upgrade_planner import UpgradePlannerAgent
from agentic.agents.code_remediator import CodeRemediatorAgent
from agentic.agents.validator_pr import ValidatorPRAgent

console = Console(force_terminal=True, highlight=False)


def run_test():
    console.print(
        Panel(
            "[bold cyan]FalkorDB Real-World Multi-Agent Verification[/]\n"
            "[green]Target: https://github.com/Agilan20/spring-advanced-training (sat-rest)[/]",
            border_style="cyan",
        )
    )

    graph_name = "spring_training_graph"
    gs = GraphService(graph_name)
    llm = LLMClient()

    # 1. Reset FalkorDB graph schema
    console.print(f"[dim]Initializing clean FalkorDB graph '{graph_name}'...[/]")
    gs.clear_graph()
    gs.init_schema()

    # 2. Parse real dependency tree using MavenTool
    console.print("\n[bold yellow]=== Step 1: Agent 1 (Dependency Ingestion to FalkorDB) ===[/]")
    m = MavenTool()
    tree_path = "target_repo/sat-rest/tree.txt"
    try:
        with open(tree_path, "r", encoding="utf-8") as f:
            tree_content = f.read()
    except Exception as e:
        console.print(f"[red]Could not read {tree_path}: {e}[/]")
        return

    dep_tree = m.parse_dependency_tree_output(tree_content)
    console.print(f"[OK] Parsed real Maven tree: {len(dep_tree['direct_dependencies'])} direct dependencies")

    # Ingest into FalkorDB
    agent1 = DependencyAnalystAgent(gs, llm)
    agent1.analyze_and_ingest(
        repo_name="Agilan20/spring-advanced-training",
        repo_url="https://github.com/Agilan20/spring-advanced-training",
        branch="master",
        manifest_path="sat-rest/pom.xml",
        dependency_tree=dep_tree,
        code_symbols=[
            {
                "qualifiedName": "CityController.getCity()",
                "file": "sat-rest/src/main/java/CityController.java",
                "line": 42,
                "targetPurl": "pkg:maven/org.springframework.boot/spring-boot-starter-webmvc@4.1.1",
            },
            {
                "qualifiedName": "CityRepository.findAll()",
                "file": "sat-rest/src/main/java/CityRepository.java",
                "line": 15,
                "targetPurl": "pkg:maven/org.springframework.boot/spring-boot-starter-data-jpa@4.1.1",
            },
        ],
        test_mappings=[
            {
                "name": "CityControllerTest",
                "filePath": "sat-rest/src/test/java/CityControllerTest.java",
                "testsSymbol": "CityController.getCity()",
            }
        ],
    )

    # Print FalkorDB node counts
    summary = gs.get_graph_summary()
    summary_table = Table(title="FalkorDB Node Summary (Real Project Ingestion)", border_style="cyan")
    summary_table.add_column("Node Label", style="bold green")
    summary_table.add_column("Count in FalkorDB", style="bold white")
    for k, v in summary.items():
        summary_table.add_row(k, str(v))
    console.print(summary_table)

    # 3. Step 2: Ingest Security Advisory into FalkorDB
    console.print("\n[bold yellow]=== Step 2: Agent 2 (Vulnerability Enrichment in FalkorDB) ===[/]")
    agent2 = VulnerabilityAnalystAgent(gs, llm)
    
    # We simulate a security finding on a transitive dependency in this tree: snakeyaml
    test_scan = {
        "vulnerabilities": [
            {
                "cveId": "CVE-2022-1471",
                "title": "SnakeYaml Constructor Deserialization Remote Code Execution",
                "severity": "HIGH",
                "cvssScore": 8.3,
                "targetPurl": "pkg:maven/org.yaml/snakeyaml@2.6",
                "remediationVersion": "2.7",
            }
        ]
    }
    agent2.analyze_and_enrich(test_scan)

    # 4. Step 3: Upgrade Planner (FalkorDB Cypher Traversal & LLM Grounding)
    console.print("\n[bold yellow]=== Step 3: Agent 3 (FalkorDB Cypher Blast Radius & Gemini LLM) ===[/]")
    console.print("[dim]Executing Query 1: Finding direct parent declaring the vulnerable transitive package...[/]")
    transitive_evidence = gs.query_transitive_vulnerabilities("CVE-2022-1471")
    for t in transitive_evidence:
        console.print(f"  [cyan]-> Direct Parent:[/] {t['DirectDependency']}")
        console.print(f"  [cyan]-> Full Provenance Chain in FalkorDB:[/] {' -> '.join(t['DependencyChain'])}")

    console.print("[dim]Executing Query 2: Computing blast radius on code symbols and tests...[/]")
    blast_evidence = gs.query_blast_radius("CVE-2022-1471")
    for b in blast_evidence:
        console.print(f"  [cyan]-> Vulnerable Node:[/] {b['VulnerablePackage']}")
        console.print(f"  [cyan]-> Affected Symbols:[/] {b['AffectedCodeSymbols'] or 'Pure transitive dependency'}")

    # Invoke Agent 3 with Gemini
    agent3 = UpgradePlannerAgent(gs, llm)
    plan = agent3.plan_remediation(cve_id="CVE-2022-1471")

    # 5. Step 4: Code Remediator (Generating pom.xml diff)
    console.print("\n[bold yellow]=== Step 4: Agent 4 (Manifest Remediator) ===[/]")
    agent4 = CodeRemediatorAgent(gs, llm)
    patches = agent4.remediate(plan)
    for p in patches.get("patches", []):
        console.print(f"[bold green]Generated Diff for {p['targetFile']}:[/]")
        console.print(p["diff"])

    # 6. Step 5: Validator & PR Agent
    console.print("\n[bold yellow]=== Step 5: Agent 5 (Draft PR with FalkorDB Audit Proof) ===[/]")
    agent5 = ValidatorPRAgent(gs, llm)
    pr_result = agent5.validate_and_draft_pr(
        execution_plan=plan,
        remediation_result=patches,
        repo_name="Agilan20/spring-advanced-training",
        publish_pr=False,
    )

    console.print(Panel(pr_result["prBody"], title=f"Draft PR: {pr_result['prTitle']}", border_style="green"))


if __name__ == "__main__":
    run_test()
