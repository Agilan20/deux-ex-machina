# AI Dependency Remediation Agent System

Autonomous multi-agent system powered by **FalkorDB** to identify, analyze, and remediate dependency vulnerabilities within software repositories.

Directly implements [`ai_dependency_remediation_agent_guide.md`](../ai_dependency_remediation_agent_guide.md).

---

## Architecture Overview

```
+--------------------+      +------------------------+      +------------------------+
| GitHub Repository  | ---> |  Dependency Scanner &  | ---> | FalkorDB Code Graph    |
|   (User Input)     |      |    Snyk Security CLI   |      | (Packages, CVEs, APIs) |
+--------------------+      +------------------------+      +------------------------+
                                                                         |
                                                                         v
+--------------------+      +------------------------+      +------------------------+
|  GitHub Draft PR   | <--- | Build/Test Validation  | <--- |  Multi-Agent Network   |
|  & Audit Evidence  |      |  & Rescan Workbench    |      | (Planner & Remediator) |
+--------------------+      +------------------------+      +------------------------+
```

---

## Multi-Agent Network

| Agent | Module | Role |
| :--- | :--- | :--- |
| **Agent 1: Dependency Analyst** | `agents/dependency_analyst.py` | Ingests repository structure, direct & transitive dependencies, code symbols, and test mappings into FalkorDB. |
| **Agent 2: Vulnerability Analyst** | `agents/vulnerability_analyst.py` | Ingests Snyk / CVE security advisories and attaches `AFFECTED_BY` edges to `PackageVersion` nodes. |
| **Agent 3: Upgrade Planner** | `agents/upgrade_planner.py` | Runs Cypher queries on FalkorDB to determine transitive paths, blast radius, and API usage; uses LLM to plan low-risk upgrade strategy. |
| **Agent 4: Code Remediator** | `agents/code_remediator.py` | Generates manifest diffs (direct bump vs `<dependencyManagement>` override) and code refactoring patches. |
| **Agent 5: Validator & PR Agent** | `agents/validator_pr.py` | Validates build/tests, verifies CVE eradication in FalkorDB, and drafts GitHub PR with full audit evidence. |
| **Central Orchestrator** | `orchestrator.py` | Coordinates the 5-agent pipeline end-to-end. |

---

## FalkorDB Graph Schema

### Node Labels
* `Repository`: `name`, `url`, `branch`
* `Manifest`: `path`, `type`
* `Package`: `groupId`, `artifactId`
* `PackageVersion`: `version`, `purl`
* `Vulnerability`: `cveId`, `severity`, `cvssScore`, `title`
* `CodeSymbol`: `qualifiedName`, `file`, `line`
* `Test`: `name`, `filePath`
* `UpgradeCandidate`: `targetVersion`, `status`

### Relationships
* `(Repository)-[:CONTAINS]->(Manifest)`
* `(Manifest)-[:DECLARES]->(PackageVersion)`
* `(PackageVersion)-[:DEPENDS_ON]->(PackageVersion)` (Transitive hierarchy)
* `(PackageVersion)-[:AFFECTED_BY]->(Vulnerability)`
* `(CodeSymbol)-[:USES_API]->(PackageVersion)`
* `(UpgradeCandidate)-[:BREAKS_COMPATIBILITY_WITH]->(PackageVersion)`
* `(UpgradeCandidate)-[:VALIDATED_BY]->(Test)`
* `(Test)-[:TESTS]->(CodeSymbol)`

---

---

## Specialized Agent Tools

| Tool | Module | Description |
| :--- | :--- | :--- |
| **GitHub REST Tool** | `tools/github_tool.py` | Creates remediation branches and publishes Draft Pull Requests via GitHub API. |
| **Maven Resolution Tool** | `tools/maven_tool.py` | Executes `mvn dependency:tree` and parses dependency trees into graph entities; runs `mvn test`. |
| **Vulnerability Scanner Tool** | `tools/scanner_tool.py` | Queries live vulnerability advisories (OSV / CVE) and executes Snyk CLI scans. |

---

## How to Run

1. Make sure your virtual environment is active:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```

2. Run the pipeline against FalkorDB:
   ```powershell
   python -m agentic.run_pipeline
   ```

3. To publish an actual Pull Request on GitHub:
   ```powershell
   python -m agentic.run_pipeline --publish-pr --repo Agilan20/deux-ex-machina
   ```
