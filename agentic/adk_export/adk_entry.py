# -*- coding: utf-8 -*-
"""Google ADK export for the FalkorDB remediation pipeline.

Run the interactive UI with:

    adk web

Then type a command like:

    /remediate https://github.com/owner/repo

The tool will ingest the repository, compute a remediation plan, and draft (or publish) a Pull Request.
"""

# The entry point for `adk web` – ADK expects a variable named `root_agent`.
from .pipeline_definition import root_agent

# Optionally expose a chat helper for nicer UI rendering.
from google.adk.core import ToolContext

def chat_response(context: ToolContext) -> str:
    """Return the final summary text produced by the pipeline for display.
    """
    return context.get("summary_text", "No summary available.")
