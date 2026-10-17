"""
Agent 4: Code Remediator
------------------------
Task: Generates target file modifications for manifests (e.g. pom.xml) and application
      source code. Handles both direct version bumps and transitive overrides via
      <dependencyManagement>. Prepares atomic branch diffs.
Output: Branch diff and modified file artifacts.
"""

from typing import Any, Dict, List
from agentic.agents.base_agent import BaseAgent
from agentic.graph_service import GraphService
from agentic.llm import LLMClient


class CodeRemediatorAgent(BaseAgent):
    def __init__(self, graph_service: GraphService, llm: LLMClient):
        super().__init__(
            name="Agent 4: Code Remediator",
            role="Manifest & Code Transformation",
            graph_service=graph_service,
            llm=llm,
        )

    def remediate(self, execution_plan: Dict[str, Any], manifest_content: str = "") -> Dict[str, Any]:
        """
        Executes code & manifest remediation based on Agent 3's execution plan.
        """
        remediation_items = execution_plan.get("remediationPlan", [])
        self.log_step(f"Generating code and manifest patches for {len(remediation_items)} items...")

        diffs = []
        modified_files = []

        for item in remediation_items:
            cve_id = item["cveId"]
            purl = item["vulnerablePackage"]
            target_version = item["targetVersion"]
            action_type = item["actionType"]

            # Parse maven coordinates from purl: pkg:maven/groupId/artifactId@version
            # e.g., pkg:maven/commons-io/commons-io@2.1.0
            clean_purl = purl.replace("pkg:maven/", "")
            coords, old_version = clean_purl.split("@")
            parts = coords.split("/")
            group_id = parts[0]
            artifact_id = parts[1] if len(parts) > 1 else parts[0]

            self.log_step(f"Remediating {group_id}:{artifact_id} ({old_version} -> {target_version})")

            # Generate unified diff representation for manifest
            if action_type == "DIRECT_VERSION_BUMP":
                diff_text = f"""--- a/pom.xml
+++ b/pom.xml
@@ -42,7 +42,7 @@
     <dependency>
         <groupId>{group_id}</groupId>
         <artifactId>{artifact_id}</artifactId>
-        <version>{old_version}</version>
+        <version>{target_version}</version>
     </dependency>
"""
                patch_explanation = (
                    f"Direct dependency bump for {group_id}:{artifact_id} from {old_version} to {target_version} "
                    f"to mitigate {cve_id}."
                )
            else:
                diff_text = f"""--- a/pom.xml
+++ b/pom.xml
@@ -88,6 +88,15 @@
+    <dependencyManagement>
+        <dependencies>
+            <dependency>
+                <groupId>{group_id}</groupId>
+                <artifactId>{artifact_id}</artifactId>
+                <version>{target_version}</version>
+            </dependency>
+        </dependencies>
+    </dependencyManagement>
"""
                patch_explanation = (
                    f"Transitive dependency pinning via <dependencyManagement> for {group_id}:{artifact_id}:{target_version} "
                    f"to eliminate transitive vulnerability {cve_id} while preserving direct dependency trees."
                )

            diffs.append({
                "targetFile": "pom.xml",
                "cveId": cve_id,
                "actionType": action_type,
                "diff": diff_text,
                "explanation": patch_explanation,
            })
            modified_files.append("pom.xml")

            # Check if any CodeSymbols need API migrations
            affected_symbols = item.get("affectedSymbols", [])
            if affected_symbols:
                self.log_step(f"Analyzing {len(affected_symbols)} application symbols for breaking changes...")
                symbol_prompt = f"""
                Library {group_id}:{artifact_id} was upgraded from {old_version} to {target_version}.
                The following code symbols call this library:
                {affected_symbols}

                If any deprecated or removed APIs in {target_version} are known, produce refactored code guidelines.
                Otherwise state that binary compatibility is expected.
                """
                api_migration_note = self.llm.generate(symbol_prompt)
                diffs.append({
                    "targetFile": "src/main/java/...",
                    "cveId": cve_id,
                    "actionType": "API_COMPATIBILITY_NOTE",
                    "diff": "",
                    "explanation": api_migration_note,
                })

            self.log_success(f"Generated remediation patch for {cve_id}")

        return {
            "status": "PATCHES_READY",
            "modifiedFiles": list(set(modified_files)),
            "patches": diffs,
        }
