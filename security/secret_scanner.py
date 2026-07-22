#!/usr/bin/env python3
"""
GlobePulse Secret Scanner
=========================
Multi-pattern regex and Shannon entropy scanner for detecting exposed secrets,
API keys, tokens, private keys, and hardcoded credentials across the codebase.
"""

import math
import os
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    description: str
    snippet: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
        }


class SecretScanner:
    """Scans repository files for hardcoded secrets and high-entropy credentials."""

    DEFAULT_EXCLUDES = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        "security/reports",
        "package-lock.json",
        ".globepulse.pids",
    }

    BINARY_EXTENSIONS = {
        ".png", ".jpeg", ".jpg", ".gif", ".ico", ".pdf", ".zip",
        ".tar", ".gz", ".pyc", ".so", ".dylib", ".exe", ".bin"
    }

    SECRET_RULES = [
        {
            "id": "SEC-001",
            "name": "Google / Gemini API Key",
            "pattern": r"AIzaSy[A-Za-z0-9_-]{35}",
            "severity": "CRITICAL",
            "recommendation": "Remove Google/Gemini API key. Store in GCP Secret Manager or load via environment variable GEMINI_API_KEY."
        },
        {
            "id": "SEC-002",
            "name": "AWS Access Key ID",
            "pattern": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
            "severity": "CRITICAL",
            "recommendation": "Remove AWS Access Key ID. Inject credentials via IAM roles or environment variables."
        },
        {
            "id": "SEC-003",
            "name": "AWS Secret Access Key",
            "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            "severity": "CRITICAL",
            "recommendation": "Remove hardcoded AWS secret key immediately and rotate the key pair."
        },
        {
            "id": "SEC-004",
            "name": "RSA / Private Key",
            "pattern": r"-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PRIVATE)\s+KEY-----",
            "severity": "CRITICAL",
            "recommendation": "Private key exposed. Never commit private key files to source control."
        },
        {
            "id": "SEC-005",
            "name": "GitHub Token",
            "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b",
            "severity": "CRITICAL",
            "recommendation": "GitHub Personal Access Token exposed. Revoke token and load from environment."
        },
        {
            "id": "SEC-006",
            "name": "Database Connection String with Password",
            "pattern": r"(?i)(postgres|mysql|mongodb\+srv|mongodb|redis)://[^:]+:[^@]+@",
            "severity": "HIGH",
            "recommendation": "Hardcoded database URI with credentials. Move connection strings to environment configuration."
        },
        {
            "id": "SEC-007",
            "name": "JSON Web Token (JWT)",
            "pattern": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "severity": "HIGH",
            "recommendation": "Hardcoded JWT token found. Remove static tokens from code."
        },
        {
            "id": "SEC-008",
            "name": "Generic Password / Secret Assignment",
            "pattern": r"(?i)(api_key|apikey|secret_key|app_secret|db_password)\s*=\s*['\"][^'\"]{8,}['\"]",
            "severity": "HIGH",
            "recommendation": "Potential hardcoded password/secret assignment. Ensure value is populated from os.getenv()."
        },
        {
            "id": "SEC-009",
            "name": "Slack Webhook / Bot Token",
            "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "severity": "HIGH",
            "recommendation": "Exposed Slack bot token or webhook URL. Store in environment configuration."
        }
    ]

    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon Entropy of a given text string."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        occurrences = {}
        for char in text:
            occurrences[char] = occurrences.get(char, 0) + 1
        for count in occurrences.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def is_excluded(self, path: str) -> bool:
        """Check if a file or directory should be skipped."""
        rel_path = os.path.relpath(path, self.target_dir)
        parts = rel_path.split(os.sep)
        for part in parts:
            if part in self.DEFAULT_EXCLUDES:
                return True
        _, ext = os.path.splitext(path)
        if ext.lower() in self.BINARY_EXTENSIONS:
            return True
        return False

    def mask_snippet(self, secret: str) -> str:
        """Mask a secret string for safe reporting."""
        if len(secret) <= 8:
            return "*****"
        return secret[:3] + "*" * (len(secret) - 6) + secret[-3:]

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file for secret patterns and high entropy strings."""
        findings: List[Finding] = []
        if self.is_excluded(file_path):
            return findings

        # Skip example files or test files that explicitly use mock values unless real pattern matches
        is_example_file = ".example" in file_path or "mock" in file_path.lower()

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("//"):
                # Skip pure comments if they contain example strings
                if is_example_file or "example" in line_str.lower() or "your_" in line_str.lower():
                    continue

            # Check Regex Rules
            for rule in self.SECRET_RULES:
                matches = re.findall(rule["pattern"], line)
                for match in matches:
                    matched_str = match if isinstance(match, str) else match[0]
                    # Filter out placeholders
                    if any(ph in matched_str.lower() for ph in ["your_", "example", "placeholder", "fake"]):
                        continue

                    masked = self.mask_snippet(matched_str)
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    findings.append(Finding(
                        scanner="SecretScanner",
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        file_path=rel_path,
                        line_number=idx,
                        description=f"{rule['name']} detected in {rel_path}:{idx}",
                        snippet=f"Detected match: {masked}",
                        recommendation=rule["recommendation"]
                    ))

            # High Entropy Analysis for String Literals
            literals = re.findall(r"['\"]([A-Za-z0-9_-]{24,})['\"]", line)
            for lit in literals:
                # Exclude common benign strings like base64 hashes or standard uuid format
                if any(kw in line.lower() for kw in ["import", "class", "function", "const", "def", "schema", "url"]):
                    if "key" not in line.lower() and "token" not in line.lower() and "secret" not in line.lower():
                        continue
                if any(ph in lit.lower() for ph in ["example", "placeholder", "test", "your_"]):
                    continue

                entropy = self.calculate_entropy(lit)
                if entropy > 4.6:
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    masked = self.mask_snippet(lit)
                    findings.append(Finding(
                        scanner="SecretScanner",
                        rule_id="SEC-010",
                        severity="MEDIUM",
                        file_path=rel_path,
                        line_number=idx,
                        description=f"High entropy string (entropy={entropy:.2f}) detected in variable assignment",
                        snippet=f"High entropy value: {masked}",
                        recommendation="Verify if this high-entropy string is a secret or token. Move to environment if sensitive."
                    ))

        return findings

    def scan(self) -> List[Finding]:
        """Scan entire repository directory tree."""
        all_findings: List[Finding] = []
        for root, dirs, files in os.walk(self.target_dir):
            # Exclude directories in-place
            dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]
            for file in files:
                file_path = os.path.join(root, file)
                all_findings.extend(self.scan_file(file_path))
        return all_findings

if __name__ == "__main__":
    scanner = SecretScanner(".")
    results = scanner.scan()
    print(f"Secret Scanner completed. Found {len(results)} issues.")
    for res in results:
        print(f"[{res.severity}] {res.file_path}:{res.line_number} - {res.description}")
