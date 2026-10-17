"""
GitHub REST API Client for Autonomous Pull Request Creation.
Enables Agent 5 to create remediation branches, commit patches, and publish PRs.
"""

import json
import base64
import urllib.request
import urllib.error
from typing import Any, Dict, Optional
from agentic.config import GITHUB_TOKEN, GITHUB_REPOSITORY, DEFAULT_BRANCH


class GitHubTool:
    def __init__(self, token: Optional[str] = None, repository: Optional[str] = None):
        self.token = token or GITHUB_TOKEN
        self.repository = repository or GITHUB_REPOSITORY
        self.base_url = f"https://api.github.com/repos/{self.repository}"

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ai-dependency-remediation-agent",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def is_configured(self) -> bool:
        return bool(self.token and self.repository)

    def get_default_branch_sha(self, branch: str = DEFAULT_BRANCH) -> Optional[str]:
        """Fetch the latest commit SHA of the base branch."""
        url = f"{self.base_url}/git/ref/heads/{branch}"
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["object"]["sha"]
        except Exception as e:
            return None

    def create_branch(self, branch_name: str, base_branch: str = DEFAULT_BRANCH) -> Dict[str, Any]:
        """Create a new git ref (branch) from the base branch commit SHA."""
        base_sha = self.get_default_branch_sha(base_branch)
        if not base_sha:
            return {"status": "ERROR", "message": f"Could not find SHA for branch '{base_branch}'"}

        url = f"{self.base_url}/git/refs"
        payload = json.dumps({
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {"status": "CREATED", "ref": data["ref"]}
        except urllib.error.HTTPError as e:
            if e.code == 422:
                # Branch already exists
                return {"status": "EXISTS", "ref": f"refs/heads/{branch_name}"}
            error_body = e.read().decode("utf-8")
            return {"status": "ERROR", "message": f"HTTP {e.code}: {error_body}"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def create_pull_request(
        self,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = DEFAULT_BRANCH,
        draft: bool = False,
    ) -> Dict[str, Any]:
        """Submit a Pull Request via GitHub REST API."""
        url = f"{self.base_url}/pulls"
        payload = json.dumps({
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
            "draft": draft,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "status": "SUCCESS",
                    "prNumber": data.get("number"),
                    "prUrl": data.get("html_url"),
                    "state": data.get("state"),
                }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            return {"status": "ERROR", "statusCode": e.code, "message": error_body}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
