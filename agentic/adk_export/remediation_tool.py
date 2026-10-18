# -*- coding: utf-8 -*-
"""Utility functions that expose the FalkorDB remediation pipeline as tools for Google ADK."""

import os
import sys
import re
from typing import Dict, Any

# Ensure project root is in sys.path so agentic packages are always resolvable by ADK
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from agentic.test_spring_training import run_test


def _extract_repo_name(repo_url: str) -> str:
    """Extract ``owner/repo`` from a standard GitHub URL."""
    pattern = r"(?:github\.com[:/])([^/]+/[^/]+)(?:\.git)?$"
    match = re.search(pattern, repo_url.strip())
    if not match:
        # Fallback if user just entered owner/repo
        if "/" in repo_url and not repo_url.startswith("http"):
            return repo_url.strip()
        raise ValueError(f"Could not parse repository name from URL: {repo_url}")
    return match.group(1)


def remediate(repo_url: str, publish_pr: bool = False, target_cve: str = None) -> Dict[str, Any]:
    """ADK-compatible tool that runs the full FalkorDB remediation workflow.

    Args:
        repo_url: The HTTPS or SSH URL of the GitHub repository to analyse and remediate.
        publish_pr: When True, opens a live Pull Request on GitHub. Default is False (draft PR).
        target_cve: Optional specific CVE ID (e.g. 'CVE-2022-1471') to target, or None to remediate all dependencies.

    Returns:
        dict: A summary of the remediation including PR title, branch, and status.
    """
    try:
        repo_name = _extract_repo_name(repo_url)
    except Exception as exc:
        return {"status": "ERROR", "message": f"Invalid repository URL: {exc}"}

    try:
        pr_result = run_test(publish_pr=publish_pr, repo_name=repo_name, repo_url=repo_url, target_cve=target_cve)
        if not pr_result:
            return {"status": "ERROR", "message": "Pipeline did not produce PR result."}

        published = pr_result.get("published") or {}
        return {
            "status": "SUCCESS",
            "repo": repo_name,
            "branch": pr_result.get("branch"),
            "prTitle": pr_result.get("prTitle"),
            "prUrl": published.get("prUrl") or f"https://github.com/{repo_name}/compare/{pr_result.get('targetBranch', 'develop')}...{pr_result.get('branch')}?expand=1",
            "published": bool(published.get("prUrl")),
        }
    except Exception as exc:
        return {"status": "ERROR", "message": str(exc)}
