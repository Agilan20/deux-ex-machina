"""
Sample Data Fixtures reflecting the domain entities in
ai_dependency_remediation_agent_guide.md:
- Repository: payment-service
- Manifest: pom.xml
- Direct & Transitive Dependencies
- Vulnerability: CVE-2023-1234 (affects commons-io:2.1.0 -> fix target 2.11.0)
- Code Symbols: PaymentClient.process(), FileStorageService.save()
- Unit Tests: PaymentClientTest, FileStorageServiceTest
"""

SAMPLE_REPO = {
    "name": "payment-service",
    "url": "https://github.com/org/payment-service",
    "branch": "main",
    "manifest_path": "pom.xml",
}

# Dependency hierarchy:
# Direct: org.springframework.boot:spring-boot-starter-web:2.7.0
# Direct: org.apache.commons:commons-lang3:3.12.0
# Transitive under spring-boot-starter-web: commons-io:commons-io:2.1.0 (VULNERABLE)
SAMPLE_DEPENDENCY_TREE = {
    "direct_dependencies": [
        {
            "groupId": "org.springframework.boot",
            "artifactId": "spring-boot-starter-web",
            "version": "2.7.0",
            "scope": "compile",
            "transitive_dependencies": [
                {
                    "groupId": "commons-io",
                    "artifactId": "commons-io",
                    "version": "2.1.0",
                    "scope": "compile",
                },
                {
                    "groupId": "com.fasterxml.jackson.core",
                    "artifactId": "jackson-databind",
                    "version": "2.13.3",
                    "scope": "compile",
                },
            ],
        },
        {
            "groupId": "org.apache.commons",
            "artifactId": "commons-lang3",
            "version": "3.12.0",
            "scope": "compile",
            "transitive_dependencies": [],
        },
    ]
}

# Snyk Security CLI scan finding (Section 2 & 4)
SAMPLE_SNYK_SCAN = {
    "ok": False,
    "packageManager": "maven",
    "vulnerabilities": [
        {
            "cveId": "CVE-2023-1234",
            "title": "Directory Traversal in commons-io via custom path normalizer",
            "severity": "HIGH",
            "cvssScore": 8.1,
            "targetPurl": "pkg:maven/commons-io/commons-io@2.1.0",
            "remediationVersion": "2.11.0",
            "disclosureDate": "2023-04-12",
        }
    ],
}

# Application code symbols calling the vulnerable library
SAMPLE_CODE_SYMBOLS = [
    {
        "qualifiedName": "PaymentClient.process()",
        "file": "src/main/java/com/company/payment/PaymentClient.java",
        "line": 45,
        "targetPurl": "pkg:maven/commons-io/commons-io@2.1.0",
    },
    {
        "qualifiedName": "FileStorageService.save()",
        "file": "src/main/java/com/company/storage/FileStorageService.java",
        "line": 112,
        "targetPurl": "pkg:maven/commons-io/commons-io@2.1.0",
    },
]

# Tests covering the affected code symbols
SAMPLE_TEST_MAPPINGS = [
    {
        "name": "PaymentClientTest",
        "filePath": "src/test/java/com/company/payment/PaymentClientTest.java",
        "testsSymbol": "PaymentClient.process()",
    },
    {
        "name": "FileStorageServiceTest",
        "filePath": "src/test/java/com/company/storage/FileStorageServiceTest.java",
        "testsSymbol": "FileStorageService.save()",
    },
]
