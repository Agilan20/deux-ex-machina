# -*- coding: utf-8 -*-
"""Pipeline definition for Google ADK export.

Defines the FalkorDBRemediationAgent as an LlmAgent exposing the `remediate` tool,
fully compatible with the Google ADK Web UI, CLI, and Cloud deployments.
"""

from google.adk.agents.llm_agent import LlmAgent
from .remediation_tool import remediate

root_agent = LlmAgent(
    name="FalkorDBRemediationAgent",
    model="gemini-3.8-flash",
    description="Autonomous dependency remediation agent powered by FalkorDB graph blast-radius analysis.",
    instruction=(
        "You are an AI Dependency Remediation Agent powered by FalkorDB graph blast-radius analysis.\n\n"
        "Your capabilities:\n"
        "1. Ingest repository dependency trees (direct and transitive) into FalkorDB Cloud.\n"
        "2. Query transitive vulnerability provenance and blast radius on code symbols using Cypher.\n"
        "3. Generate targeted Maven <dependencyManagement> patches to eliminate vulnerabilities without breaking direct dependencies.\n"
        "4. Validate fixes and draft or publish GitHub Pull Requests.\n\n"
        "Interaction Guidelines:\n"
        "- If the user greets you or asks what you do, welcome them and ask them to provide a GitHub repository URL to remediate.\n"
        "- When the user provides a repository URL (e.g., https://github.com/Agilan20/spring-advanced-training), call the `remediate` tool with `repo_url`.\n"
        "- If the user indicates they want to publish the PR live to GitHub, set `publish_pr=True`.\n"
        "- When the tool finishes, summarize the remediation clearly: report the target repo, the branch created, the CVE remediated, and the PR link."
    ),
    tools=[remediate],
)
