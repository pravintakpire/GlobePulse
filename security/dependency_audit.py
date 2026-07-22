#!/usr/bin/env python3
"""
GlobePulse Dependency Auditor
=============================
Audits Python requirements files (`requirements.txt`) and Node.js manifests (`package.json`)
for unpinned versions, outdated packages, and known security vulnerabilities (CVEs).
"""

import json
import os
import re
import subprocess
from typing import List, Dict, Any
from secret_scanner import Finding

class DependencyAuditor:
    """Audits repository dependencies for security risks and vulnerabilities."""

    # Built-in advisory database for common vulnerable package versions
    KNOWN_VULNERABLE_PACKAGES = {
        "pyyaml": [
            {"max_ver": "5.4.1", "cve": "CVE-2020-14343", "severity": "HIGH", "desc": "Arbitrary code execution via unsafe yaml loading."}
        ],
        "urllib3": [
            {"max_ver": "1.26.4", "cve": "CVE-2021-33503", "severity": "HIGH", "desc": "ReDoS vulnerability in URL parsing."}
        ],
        "requests": [
            {"max_ver": "2.25.0", "cve": "CVE-2021-33503", "severity": "MEDIUM", "desc": "Leaking auth headers on cross-domain redirect."}
        ],
        "jinja2": [
            {"max_ver": "2.11.2", "cve": "CVE-2020-28493", "severity": "HIGH", "desc": "ReDoS vulnerability in urlize filter."}
        ],
        "cryptography": [
            {"max_ver": "3.3.1", "cve": "CVE-2020-36242", "severity": "HIGH", "desc": "Buffer overflow in PKCS12 parsing."}
        ],
        "fastapi": [
            {"max_ver": "0.65.1", "cve": "CVE-2021-32677", "severity": "MEDIUM", "desc": "ReDoS via header validation."}
        ],
        "axios": [
            {"max_ver": "0.21.1", "cve": "CVE-2021-3749", "severity": "HIGH", "desc": "SSRF vulnerability in axios."}
        ]
    }

    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)

    def audit_python_requirements(self, req_file: str) -> List[Finding]:
        """Audit a Python requirements.txt file for version pinning and known vulnerabilities."""
        findings: List[Finding] = []
        if not os.path.exists(req_file):
            return findings

        rel_path = os.path.relpath(req_file, self.target_dir)

        try:
            with open(req_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("-e") or line_str.startswith("-r"):
                continue

            # Check version pinning
            if "==" not in line_str:
                pkg_name = line_str.split(">=")[0].split("<=")[0].split("~=")[0].strip()
                findings.append(Finding(
                    scanner="DependencyAuditor",
                    rule_id="DEP-001",
                    severity="MEDIUM",
                    file_path=rel_path,
                    line_number=idx,
                    description=f"Unpinned Python dependency: '{line_str}'",
                    snippet=line_str,
                    recommendation=f"Pin specific exact version using '==' (e.g. {pkg_name}==1.0.0) to prevent supply chain risks."
                ))
            else:
                parts = line_str.split("==")
                pkg_name = parts[0].strip().lower()
                version = parts[1].split(";")[0].strip()

                # Audit against advisory DB
                if pkg_name in self.KNOWN_VULNERABLE_PACKAGES:
                    for adv in self.KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                        findings.append(Finding(
                            scanner="DependencyAuditor",
                            rule_id="DEP-002",
                            severity=adv["severity"],
                            file_path=rel_path,
                            line_number=idx,
                            description=f"Known vulnerable package detected: '{pkg_name}' version '{version}' ({adv['cve']})",
                            snippet=line_str,
                            recommendation=f"Upgrade '{pkg_name}' to a version higher than '{adv['max_ver']}'. {adv['desc']}"
                        ))

        return findings

    def audit_package_json(self, pkg_file: str) -> List[Finding]:
        """Audit Node.js package.json file for wildcards and unpinned versions."""
        findings: List[Finding] = []
        if not os.path.exists(pkg_file):
            return findings

        rel_path = os.path.relpath(pkg_file, self.target_dir)

        try:
            with open(pkg_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return findings

        for section in ["dependencies", "devDependencies"]:
            if section in data and isinstance(data[section], dict):
                for pkg, ver in data[section].items():
                    if isinstance(ver, str):
                        if ver.startswith("^") or ver.startswith("~") or ver == "*" or ver.startswith(">"):
                            severity = "HIGH" if ver == "*" else "LOW"
                            findings.append(Finding(
                                scanner="DependencyAuditor",
                                rule_id="DEP-003",
                                severity=severity,
                                file_path=rel_path,
                                line_number=1,
                                description=f"Flexible/Unpinned Node.js dependency version in {section}: '{pkg}': '{ver}'",
                                snippet=f'"{pkg}": "{ver}"',
                                recommendation=f"Lock package version without '^' or '~' wildcards in production manifests."
                            ))

        return findings

    def run_external_auditors(self) -> List[Finding]:
        """Optionally invoke pip-audit if installed in the environment."""
        findings: List[Finding] = []
        try:
            res = subprocess.run(
                ["pip-audit", "-f", "json"],
                cwd=self.target_dir,
                capture_output=True,
                text=True,
                timeout=15
            )
            if res.returncode != 0 and res.stdout:
                try:
                    audit_json = json.loads(res.stdout)
                    for vul in audit_json.get("dependencies", []):
                        for cve in vul.get("vulns", []):
                            findings.append(Finding(
                                scanner="DependencyAuditor (pip-audit)",
                                rule_id=cve.get("id", "DEP-CVE"),
                                severity="HIGH",
                                file_path="requirements.txt",
                                line_number=1,
                                description=f"pip-audit found vulnerability in '{vul.get('name')}': {cve.get('description', '')[:100]}",
                                snippet=f"{vul.get('name')} {vul.get('version')}",
                                recommendation="Upgrade dependency to non-vulnerable version as indicated by pip-audit."
                            ))
                except json.JSONDecodeError:
                    pass
        except Exception:
            # External tool not installed or failed; fallback to built-in audit
            pass
        return findings

    def audit(self) -> List[Finding]:
        """Perform full dependency security audit."""
        all_findings: List[Finding] = []

        # Find requirements.txt files
        for root, dirs, files in os.walk(self.target_dir):
            if any(ex in root for ex in [".git", ".venv", "node_modules"]):
                continue
            for file in files:
                if file == "requirements.txt":
                    all_findings.extend(self.audit_python_requirements(os.path.join(root, file)))
                elif file == "package.json" and "node_modules" not in root:
                    all_findings.extend(self.audit_package_json(os.path.join(root, file)))

        # Attempt external tool enrichment
        all_findings.extend(self.run_external_auditors())
        return all_findings

if __name__ == "__main__":
    auditor = DependencyAuditor(".")
    results = auditor.audit()
    print(f"Dependency Auditor completed. Found {len(results)} findings.")
    for r in results:
        print(f"[{r.severity}] {r.file_path} - {r.description}")
