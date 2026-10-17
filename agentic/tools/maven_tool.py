"""
Maven CLI & Dependency Tree Parser Tool.
Executes Maven resolution and build commands, parsing dependency trees into graph entities.
"""

import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional


class MavenTool:
    def __init__(self, maven_cmd: Optional[str] = None):
        self.maven_cmd = maven_cmd or self._find_maven()

    def _find_maven(self) -> str:
        """Find the mvn executable on the system."""
        # 1. Check PATH
        mvn = shutil.which("mvn") or shutil.which("mvn.cmd")
        if mvn:
            return mvn

        # 2. Known default Windows installations
        default_paths = [
            r"C:\Program Files\Apache\apache-maven-3.9.6\bin\mvn.cmd",
            r"C:\Program Files\Apache\apache-maven-3.9.5\bin\mvn.cmd",
            r"C:\ProgramData\chocolatey\bin\mvn.cmd",
        ]
        for p in default_paths:
            if os.path.exists(p):
                return p

        return "mvn"

    def is_available(self) -> bool:
        try:
            res = subprocess.run([self.maven_cmd, "--version"], capture_output=True, text=True, timeout=10)
            return res.returncode == 0
        except Exception:
            return False

    def parse_dependency_tree_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parses `mvn dependency:tree` text into structured direct and transitive dependency lists.
        Format example line:
          [INFO] +- org.springframework.boot:spring-boot-starter-web:jar:2.7.0:compile
          [INFO] |  +- commons-io:commons-io:jar:2.1.0:compile
        """
        lines = raw_output.splitlines()
        direct_deps = []
        current_direct = None

        # Regex to capture Maven coordinate: groupId:artifactId:type:version[:scope]
        dep_pattern = re.compile(
            r"(?:\[INFO\]\s+)?([+|\\|\s-]+)\s+([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)(?::([a-zA-Z0-9._-]+))?"
        )

        for line in lines:
            match = dep_pattern.search(line)
            if not match:
                continue

            indent_prefix = match.group(1)
            group_id = match.group(2)
            artifact_id = match.group(3)
            # group(4) is packaging (jar, war)
            version = match.group(5)
            scope = match.group(6) or "compile"

            dep_data = {
                "groupId": group_id,
                "artifactId": artifact_id,
                "version": version,
                "scope": scope,
                "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}",
            }

            # If indent indicates top-level (direct dependency)
            is_direct = (
                indent_prefix.strip().startswith("+-")
                or indent_prefix.strip().startswith("\\-")
            ) and "|" not in indent_prefix

            if is_direct:
                current_direct = dict(dep_data)
                current_direct["transitive_dependencies"] = []
                direct_deps.append(current_direct)
            elif current_direct is not None:
                current_direct["transitive_dependencies"].append(dep_data)

        return {"direct_dependencies": direct_deps}

    def run_dependency_tree(self, project_dir: str) -> Dict[str, Any]:
        """Run `mvn dependency:tree` in the given directory and return parsed tree."""
        cmd = [self.maven_cmd, "dependency:tree", "-Dtokens=whitespace"]
        res = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            return {"status": "ERROR", "stderr": res.stderr, "direct_dependencies": []}

        parsed = self.parse_dependency_tree_output(res.stdout)
        parsed["status"] = "SUCCESS"
        return parsed

    def run_test_suite(self, project_dir: str) -> Dict[str, Any]:
        """Run `mvn test` in the project directory and parse results."""
        cmd = [self.maven_cmd, "test"]
        res = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True, timeout=180)

        # Parse test summary: Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
        summary_pattern = re.compile(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)")
        matches = summary_pattern.findall(res.stdout)

        total_run = sum(int(m[0]) for m in matches)
        total_failures = sum(int(m[1]) for m in matches)
        total_errors = sum(int(m[2]) for m in matches)

        success = (res.returncode == 0) and (total_failures == 0) and (total_errors == 0)

        return {
            "status": "PASSED" if success else "FAILED",
            "returnCode": res.returncode,
            "testsRun": total_run,
            "failures": total_failures,
            "errors": total_errors,
            "stdoutSnippet": res.stdout[-1000:] if res.stdout else "",
        }
