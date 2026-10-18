"""
Configuration for the AI Dependency Remediation Agent System.
Reads settings from environment variables or .env file.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# FalkorDB Knowledge Graph Name for software supply chain & remediation
FALKORDB_GRAPH_NAME = os.getenv("FALKORDB_GRAPH_NAME", "software_supply_chain_graph")

# LLM API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip() or None
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "").strip() or None
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-3.8-flash")

# Snyk & GitHub configurations
SNYK_TOKEN = os.getenv("SNYK_TOKEN", "").strip() or None
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip() or None
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "Agilan20/deux-ex-machina")
DEFAULT_BRANCH = os.getenv("DEFAULT_BRANCH", "main")
REMEDIATION_BRANCH_PREFIX = os.getenv("REMEDIATION_BRANCH_PREFIX", "falkordb-remediation/")
