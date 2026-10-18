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

    def get_repo_default_branch(self) -> str:
        """Fetch repository default branch name (e.g. main, master, develop)."""
        req = urllib.request.Request(self.base_url, headers=self._headers())
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("default_branch", DEFAULT_BRANCH)
        except Exception:
            return DEFAULT_BRANCH

    def get_default_branch_sha(self, branch: Optional[str] = None) -> Optional[str]:
        """Fetch the latest commit SHA of the base branch."""
        target_branch = branch or self.get_repo_default_branch()
        url = f"{self.base_url}/git/ref/heads/{target_branch}"
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["object"]["sha"]
        except Exception:
            return None

    def create_branch(self, branch_name: str, base_branch: Optional[str] = None) -> Dict[str, Any]:
        """Create a new git ref (branch) from the base branch commit SHA."""
        target_base = base_branch or self.get_repo_default_branch()
        base_sha = self.get_default_branch_sha(target_base)
        if not base_sha:
            return {"status": "ERROR", "message": f"Could not find SHA for branch '{target_base}'"}

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
        base_branch: Optional[str] = None,
        draft: bool = False,
    ) -> Dict[str, Any]:
        """Submit a Pull Request via GitHub REST API."""
        target_base = base_branch or self.get_repo_default_branch()
        url = f"{self.base_url}/pulls"
        payload = json.dumps({
            "title": title,
            "body": body,
            "head": head_branch,
            "base": target_base,
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

    def update_file_content(
        self,
        file_path: str,
        content: str,
        commit_message: str,
        branch: str,
    ) -> Dict[str, Any]:
        """Commit an updated file directly to a branch via GitHub API."""
        url = f"{self.base_url}/contents/{file_path}?ref={branch}"
        headers = self._headers()
        file_sha = None
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                file_sha = data.get("sha")
        except Exception:
            pass

        payload_dict = {
            "message": commit_message,
            "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
            "branch": branch,
        }
        if file_sha:
            payload_dict["sha"] = file_sha

        put_url = f"{self.base_url}/contents/{file_path}"
        put_req = urllib.request.Request(
            put_url,
            data=json.dumps(payload_dict).encode("utf-8"),
            headers=headers,
            method="PUT",
        )
        try:
            with urllib.request.urlopen(put_req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {"status": "SUCCESS", "commitSha": data.get("commit", {}).get("sha")}
        except urllib.error.HTTPError as e:
            return {"status": "ERROR", "message": e.read().decode("utf-8")}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
