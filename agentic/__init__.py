"""
AI Dependency Remediation Agent System
--------------------------------------
Autonomous multi-agent system powered by FalkorDB for vulnerability blast radius analysis.
"""

from agentic.orchestrator import CentralOrchestrator
from agentic.graph_service import GraphService
from agentic.llm import LLMClient

__all__ = ["CentralOrchestrator", "GraphService", "LLMClient"]
