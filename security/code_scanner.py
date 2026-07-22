#!/usr/bin/env python3
"""
GlobePulse Static Code Scanner (AST & Pattern Analysis)
======================================================
Performs static analysis across Python backend files, JavaScript/TypeScript frontend code,
shell scripts, and Firestore rules for vulnerability patterns and security anti-patterns.
"""

import ast
import os
import re
from typing import List, Dict, Any, Optional
from secret_scanner import Finding

class PythonASTSecurityVisitor(ast.NodeVisitor):
    """AST Visitor searching for security anti-patterns in Python code."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def add_finding(self, rule_id: str, severity: str, node: ast.AST, description: str, snippet: str, recommendation: str):
        lineno = getattr(node, "lineno", 1)
        self.findings.append(Finding(
            scanner="CodeScanner (Python AST)",
            rule_id=rule_id,
            severity=severity,
            file_path=self.file_path,
            line_number=lineno,
            description=description,
            snippet=snippet,
            recommendation=recommendation
        ))

    def visit_Call(self, node: ast.Call):
        # 1. Command Injection: subprocess(shell=True), os.system, eval, exec
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Check eval / exec
        if func_name in ["eval", "exec"]:
            self.add_finding(
                rule_id="COD-001",
                severity="CRITICAL",
                node=node,
                description=f"Use of dynamic code execution '{func_name}()'",
                snippet=f"{func_name}(...)",
                recommendation=f"Avoid using '{func_name}()' on arbitrary inputs. Refactor using safe data structures."
            )

        # Check os.system
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "os" and node.func.attr in ["system", "popen"]:
                self.add_finding(
                    rule_id="COD-002",
                    severity="CRITICAL",
                    node=node,
                    description=f"Use of 'os.{node.func.attr}()' command execution",
                    snippet=f"os.{node.func.attr}(...)",
                    recommendation="Replace os.system with subprocess.run() passing arguments as an explicit array list."
                )

        # Check subprocess(..., shell=True)
        if func_name in ["Popen", "run", "call", "check_output"]:
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.add_finding(
                        rule_id="COD-003",
                        severity="CRITICAL",
                        node=node,
                        description=f"Subprocess call '{func_name}' executed with shell=True",
                        snippet=f"subprocess.{func_name}(..., shell=True)",
                        recommendation="Set shell=False and pass executable command arguments as a list of strings."
                    )

        # 2. Insecure Deserialization: pickle.loads, yaml.unsafe_load
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "pickle" and node.func.attr in ["loads", "load"]:
                self.add_finding(
                    rule_id="COD-004",
                    severity="CRITICAL",
                    node=node,
                    description="Use of unsafe deserialization 'pickle.loads()'",
                    snippet="pickle.loads(...)",
                    recommendation="Avoid loading untrusted pickle streams. Use JSON or Protocol Buffers."
                )
            elif node.func.value.id in ["yaml", "PyYAML"] and node.func.attr in ["unsafe_load", "load"]:
                # Check Loader argument if load()
                is_unsafe = node.func.attr == "unsafe_load"
                if node.func.attr == "load":
                    has_safe_loader = any(kw.arg == "Loader" and "SafeLoader" in ast.dump(kw.value) for kw in node.keywords)
                    if not has_safe_loader:
                        is_unsafe = True

                if is_unsafe:
                    self.add_finding(
                        rule_id="COD-005",
                        severity="HIGH",
                        node=node,
                        description="Use of unsafe YAML deserialization",
                        snippet=f"yaml.{node.func.attr}(...)",
                        recommendation="Use yaml.safe_load() instead of yaml.load() or yaml.unsafe_load()."
                    )

        # 3. Weak Cryptography: hashlib.md5, hashlib.sha1
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in ["md5", "sha1"]:
                self.add_finding(
                    rule_id="COD-006",
                    severity="MEDIUM",
                    node=node,
                    description=f"Use of weak hash function 'hashlib.{node.func.attr}()'",
                    snippet=f"hashlib.{node.func.attr}()",
                    recommendation="Upgrade weak hashing algorithm to SHA-256 or SHA-512 for cryptographic integrity."
                )

        self.generic_visit(node)


class CodeScanner:
    """Static analysis code scanner for Python, JS/TS, Firestore Rules, and Shell scripts."""

    EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "security"}

    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)

    def scan_python_ast(self, file_path: str) -> List[Finding]:
        """Parse and visit Python files using AST analysis."""
        findings: List[Finding] = []
        rel_path = os.path.relpath(file_path, self.target_dir)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content, filename=file_path)
            visitor = PythonASTSecurityVisitor(rel_path)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass
        except Exception:
            pass

        # Additional Regex Checks on Python Code
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for idx, line in enumerate(lines, start=1):
                # Check binding to 0.0.0.0 in uvicorn / flask
                if re.search(r"host\s*=\s*['\"]0\.0\.0\.0['\"]", line):
                    findings.append(Finding(
                        scanner="CodeScanner (Python)",
                        rule_id="COD-007",
                        severity="LOW",
                        file_path=rel_path,
                        line_number=idx,
                        description="Application bound to all network interfaces ('0.0.0.0')",
                        snippet=line.strip(),
                        recommendation="Verify production host binding configurations and use reverse proxy / firewall rules."
                    ))

                # Check Debug=True in production code
                if re.search(r"debug\s*=\s*True\b", line, re.IGNORECASE) and "test" not in file_path.lower():
                    findings.append(Finding(
                        scanner="CodeScanner (Python)",
                        rule_id="COD-008",
                        severity="MEDIUM",
                        file_path=rel_path,
                        line_number=idx,
                        description="Debug mode explicitly enabled ('debug=True')",
                        snippet=line.strip(),
                        recommendation="Ensure debug mode is disabled in production environments."
                    ))

                # Check CORS allow_origins=["*"]
                if re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", line):
                    findings.append(Finding(
                        scanner="CodeScanner (Python)",
                        rule_id="COD-009",
                        severity="MEDIUM",
                        file_path=rel_path,
                        line_number=idx,
                        description="Wildcard CORS policy ('allow_origins=[\"*\"]') detected",
                        snippet=line.strip(),
                        recommendation="Restrict allowed origins to trusted web domains in production CORS settings."
                    ))
        except Exception:
            pass

        return findings

    def scan_javascript(self, file_path: str) -> List[Finding]:
        """Scan JavaScript / TypeScript files for frontend vulnerabilities."""
        findings: List[Finding] = []
        rel_path = os.path.relpath(file_path, self.target_dir)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, line in enumerate(lines, start=1):
                # 1. DOM XSS via dangerouslySetInnerHTML
                if "dangerouslySetInnerHTML" in line:
                    findings.append(Finding(
                        scanner="CodeScanner (JavaScript)",
                        rule_id="COD-010",
                        severity="HIGH",
                        file_path=rel_path,
                        line_number=idx,
                        description="Use of 'dangerouslySetInnerHTML' in React component",
                        snippet=line.strip(),
                        recommendation="Sanitize HTML content with DOMPurify prior to rendering, or use safe text nodes."
                    ))

                # 2. eval() in JS
                if re.search(r"\beval\s*\(", line):
                    findings.append(Finding(
                        scanner="CodeScanner (JavaScript)",
                        rule_id="COD-011",
                        severity="CRITICAL",
                        file_path=rel_path,
                        line_number=idx,
                        description="Use of JavaScript 'eval()'",
                        snippet=line.strip(),
                        recommendation="Avoid eval(). Parse structured payloads with JSON.parse()."
                    ))

                # 3. document.write
                if "document.write(" in line:
                    findings.append(Finding(
                        scanner="CodeScanner (JavaScript)",
                        rule_id="COD-012",
                        severity="HIGH",
                        file_path=rel_path,
                        line_number=idx,
                        description="Use of 'document.write()'",
                        snippet=line.strip(),
                        recommendation="Avoid document.write() to prevent DOM injection vulnerabilities."
                    ))
        except Exception:
            pass

        return findings

    def scan_firestore_rules(self, file_path: str) -> List[Finding]:
        """Scan firestore.rules for permissive access policies."""
        findings: List[Finding] = []
        rel_path = os.path.relpath(file_path, self.target_dir)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for idx, line in enumerate(lines, start=1):
                line_str = line.strip()
                # Check for blanket allow read, write: if true;
                if re.search(r"allow\s+(read|write|create|update|delete)(\s*,\s*(read|write|create|update|delete))*\s*:\s*if\s+true\s*;", line_str):
                    findings.append(Finding(
                        scanner="CodeScanner (Firestore Rules)",
                        rule_id="COD-013",
                        severity="CRITICAL",
                        file_path=rel_path,
                        line_number=idx,
                        description="Permissive Firestore security rule: unconditionally allowing operations ('if true;')",
                        snippet=line_str,
                        recommendation="Enforce authentication and resource checks (e.g. 'if request.auth != null;')."
                    ))
        except Exception:
            pass

        return findings

    def scan(self) -> List[Finding]:
        """Execute static code analysis across repository."""
        all_findings: List[Finding] = []

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".py"):
                    all_findings.extend(self.scan_python_ast(full_path))
                elif file.endswith((".js", ".ts", ".jsx", ".tsx")):
                    all_findings.extend(self.scan_javascript(full_path))
                elif file == "firestore.rules":
                    all_findings.extend(self.scan_firestore_rules(full_path))

        return all_findings

if __name__ == "__main__":
    scanner = CodeScanner(".")
    results = scanner.scan()
    print(f"Code Scanner completed. Found {len(results)} findings.")
    for f in results:
        print(f"[{f.severity}] {f.file_path}:{f.line_number} - {f.description}")
