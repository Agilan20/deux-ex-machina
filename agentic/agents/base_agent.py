"""
Base Agent Interface.
Provides common graph access, LLM capabilities, and rich logging.
"""

from rich.console import Console
from rich.panel import Panel
from agentic.graph_service import GraphService
from agentic.llm import LLMClient

console = Console(force_terminal=True, highlight=False)


class BaseAgent:
    def __init__(self, name: str, role: str, graph_service: GraphService, llm: LLMClient):
        self.name = name
        self.role = role
        self.graph_service = graph_service
        self.llm = llm
        self.console = console

    def log_step(self, message: str, style: str = "bold cyan") -> None:
        self.console.print(f"[{style}][{self.name}][/] {message}")

    def log_success(self, message: str) -> None:
        self.console.print(f"[bold green][ OK ][/] [{self.name}] {message}")

    def log_warning(self, message: str) -> None:
        self.console.print(f"[bold yellow][WARN][/] [{self.name}] {message}")

    def log_panel(self, content: str, title: str) -> None:
        self.console.print(Panel(content, title=f"[{self.name}] {title}", border_style="cyan"))
