"""
AI Dependency Remediation Pipeline Runner
-----------------------------------------
Executes the autonomous 5-agent network against FalkorDB.
Directly implements ai_dependency_remediation_agent_guide.md.

Usage:
    python agentic/run_pipeline.py
"""

import sys
import io

# Force UTF-8 output on Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse
from rich.console import Console
from rich.panel import Panel

from agentic.config import GITHUB_REPOSITORY
from agentic.orchestrator import CentralOrchestrator
from agentic.sample_data import (
    SAMPLE_REPO,
    SAMPLE_DEPENDENCY_TREE,
    SAMPLE_SNYK_SCAN,
    SAMPLE_CODE_SYMBOLS,
    SAMPLE_TEST_MAPPINGS,
)

console = Console(force_terminal=True, highlight=False)


def main():
    parser = argparse.ArgumentParser(description="AI Dependency Remediation Agent Pipeline Runner")
    parser.add_argument("--publish-pr", action="store_true", help="Publish Draft PR to GitHub via REST API")
    parser.add_argument("--repo", default=GITHUB_REPOSITORY, help="Target GitHub repository (e.g. owner/repo)")
    parser.add_argument("--cve", default="CVE-2023-1234", help="Specific CVE ID to target for remediation")
    args = parser.parse_args()

    orchestrator = CentralOrchestrator()

    # Execute full multi-agent pipeline
    results = orchestrator.run_remediation_pipeline(
        repo_name=args.repo,
        repo_url=f"https://github.com/{args.repo}",
        branch=SAMPLE_REPO["branch"],
        manifest_path=SAMPLE_REPO["manifest_path"],
        dependency_tree=SAMPLE_DEPENDENCY_TREE,
        snyk_scan_data=SAMPLE_SNYK_SCAN,
        code_symbols=SAMPLE_CODE_SYMBOLS,
        test_mappings=SAMPLE_TEST_MAPPINGS,
        target_cve=args.cve,
        publish_pr=args.publish_pr,
    )

    # Display the final generated Pull Request Body
    pr = results["stage5_pr_payload"]
    console.print("\n[bold cyan]=== Generated GitHub Pull Request Draft ===[/]\n")
    console.print(Panel(pr["prBody"], title=f"Draft PR: {pr['prTitle']}", border_style="green"))


if __name__ == "__main__":
    main()
