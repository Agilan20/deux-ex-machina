# AI Dependency Remediation Agent System Specification

## 1. Vision & Architecture Overview

The **AI Dependency Remediation Agent** is an autonomous multi-agent system designed to identify, analyze, and remediate dependency vulnerabilities within software repositories. Unlike conventional scanners that simply list vulnerabilities, this system uses **FalkorDB** to construct a graph-based representation of direct/transitive dependencies, vulnerability advisories, and source code API references. This allows the system to determine the exact **blast radius** of an upgrade, modify code appropriately, and validate changes before opening a pull request.

```
+------------------+     +------------------------+     +------------------------+
| GitHub Repository| --> |  Dependency Scanner &  | --> | FalkorDB Code Graph    |
|   (User Input)   |     |    Snyk Security CLI   |     | (Packages, CVEs, APIs) |
+------------------+     +------------------------+     +------------------------+
                                                                     |
                                                                     v
+------------------+     +------------------------+     +------------------------+
| GitHub Draft PR  | <-- | Build/Test Validation  | <-- | Multi-Agent Network    |
| & Audit Evidence |     |  & Rescan Workbench    |     | (Planner & Remediator) |
+------------------+     +------------------------+     +------------------------+
```

---

## 2. FalkorDB Graph Schema Design

To accurately model impact, library versions must be treated as distinct graph entities with precise provenance tracking.

### Node Definitions

| Node Label | Key Properties | Example |
| :--- | :--- | :--- |
| **`Repository`** | `name`, `url`, `branch` | `payment-service` |
| **`Manifest`** | `path`, `type` | `pom.xml` |
| **`Package`** | `groupId`, `artifactId` | `org.apache.commons` |
| **`PackageVersion`** | `version`, `purl` | `commons-io:2.1.0` |
| **`Vulnerability`** | `cveId`, `severity`, `cvssScore` | `CVE-2023-1234` |
| **`CodeSymbol`** | `qualifiedName`, `file`, `line` | `PaymentClient.process()` |
| **`Test`** | `name`, `filePath` | `PaymentClientTest` |
| **`UpgradeCandidate`**| `targetVersion`, `status` | `commons-io:2.11.0` |

### Relationship Definitions

* **`(Repository)-[:CONTAINS]->(Manifest)`**
* **`(Manifest)-[:DECLARES]->(PackageVersion)`**
* **`(PackageVersion)-[:DEPENDS_ON]->(PackageVersion)`** *(Transitive relationships)*
* **`(PackageVersion)-[:AFFECTED_BY]->(Vulnerability)`**
* **`(CodeSymbol)-[:USES_API]->(PackageVersion)`**
* **`(UpgradeCandidate)-[:BREAKS_COMPATIBILITY_WITH]->(PackageVersion)`**
* **`(UpgradeCandidate)-[:VALIDATED_BY]->(Test)`**

---

## 3. Multi-Agent Architecture

The remediation pipeline operates through specialized, single-responsibility agents coordinated by a central orchestrator.

```
       +-------------------------------------------------------+
       |                 Central Orchestrator                  |
       +-------------------------------------------------------+
           |               |               |               |
           v               v               v               v
   +---------------+ +---------------+ +---------------+ +---------------+
   | Agent 1:      | | Agent 2:      | | Agent 3:      | | Agent 4 & 5:  |
   | Dependency    | | Vulnerability | | Upgrade       | | Code Fixer    |
   | Analyst       | | Analyst       | | Planner       | | & Validator   |
   +---------------+ +---------------+ +---------------+ +---------------+
```

### Agent Roles & Responsibilities

1. **Agent 1: Dependency Analyst**
   * **Task:** Clone target repository, run package-manager resolution commands (e.g., `mvn dependency:tree`), and populate FalkorDB with direct and transitive package hierarchies.
   * **Output:** Initial Dependency Graph.

2. **Agent 2: Vulnerability Analyst**
   * **Task:** Execute Snyk CLI scans via MCP / JSON tool interfaces, map CVE findings to target `PackageVersion` nodes, and enrich graph with fix targets.
   * **Output:** Vulnerability-annotated graph findings.

3. **Agent 3: Upgrade Planner**
   * **Task:** Execute Cypher queries on FalkorDB to determine the transitive path, blast radius, and API usage. Draft an ordered, low-risk upgrade strategy.
   * **Output:** Remediation Execution Plan JSON.

4. **Agent 4: Code Remediator**
   * **Task:** Create a dedicated git branch, update manifest files (`pom.xml`, lockfiles), and rewrite application code if breaking API changes occur.
   * **Output:** Branch diff / modified source files.

5. **Agent 5: Validation & PR Agent**
   * **Task:** Execute local builds and test suites, re-run security scans to confirm CVE eradication, and submit a detailed Pull Request via GitHub REST API.
   * **Output:** Published PR link with validation proof.

---

## 4. FalkorDB Query Engine Examples

### Query 1: Find the direct dependency responsible for bringing in a transitive vulnerability

```cypher
MATCH (m:Manifest)-[:DECLARES]->(direct:PackageVersion)
MATCH path = (direct)-[:DEPENDS_ON*0..5]->(transitive:PackageVersion)
MATCH (transitive)-[:AFFECTED_BY]->(v:Vulnerability)
WHERE v.cveId = 'CVE-2023-1234'
RETURN direct.purl AS DirectDependency, 
       transitive.purl AS VulnerablePackage, 
       [n IN nodes(path) | n.purl] AS DependencyChain
```

### Query 2: Compute impact blast radius on application code

```cypher
MATCH (v:Vulnerability {cveId: 'CVE-2023-1234'})<-[:AFFECTED_BY]-(pkg:PackageVersion)
MATCH (sym:CodeSymbol)-[:USES_API]->(pkg)
MATCH (t:Test)-[:TESTS]->(sym)
RETURN pkg.purl AS VulnerablePackage, 
       collect(DISTINCT sym.qualifiedName) AS AffectedCodeSymbols,
       collect(DISTINCT t.name) AS ImpactedTests
```

---

## 5. Technical Challenges & Mitigations

| Challenge | Mitigation Strategy |
| :--- | :--- |
| **LLM Hallucinations** | Ground all decisions in deterministic tool outputs (`mvn`, `snyk`) stored in FalkorDB. The LLM processes context, but does not invent dependencies. |
| **Breaking Transitive Upgrades** | Traverse graph paths prior to code execution. Verify API compatibility against release notes or source symbol references. |
| **Incorrect Code Editing** | Enforce a strict build and test loop. Reject diffs that break compilation or fail existing unit tests. |
| **Security Risk (Untrusted Repos)** | Run execution workers in isolated, short-lived containers with ephemeral permissions and network egress controls. |

---

## 6. MVP Implementation Roadmap (Java / Maven Focus)

1. **Stage 1 (Graph Foundation):**
   * Set up FalkorDB container.
   * Build a ingestion worker that executes `mvn dependency:tree` and parses `pom.xml` to populate package nodes and relationships.

2. **Stage 2 (Vulnerability Enrichment):**
   * Integrate Snyk CLI tool. Parse Snyk JSON output into `Vulnerability` nodes and attach `AFFECTED_BY` edges.

3. **Stage 3 (Impact Querying & Agent Integration):**
   * Implement Cypher queries to extract blast-radius context.
   * Build LLM agent prompts equipped with FalkorDB tools to plan upgrades based on retrieved graph context.

4. **Stage 4 (Remediation & GitHub Action):**
   * Implement automated pom modifications and code edits.
   * Automate test execution (`mvn test`), rescan verification, and PR creation via GitHub REST API.