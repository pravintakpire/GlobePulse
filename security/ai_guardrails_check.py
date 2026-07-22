#!/usr/bin/env python3
"""
GlobePulse AI Guardrails & LLM Security Analyzer
===============================================
Audits Python files for AI/LLM safety anti-patterns including prompt injection vulnerabilities,
unsanitized prompt concatenation, unsafe model output execution, and unvalidated tool calls.
"""

import ast
import os
import re
from typing import List, Dict, Any
from secret_scanner import Finding

class AIGuardrailsChecker:
    """Specialized security scanner for Gemini AI integrations and agentic pipelines."""

    EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "security"}

    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a Python file for AI/LLM security anti-patterns."""
        findings: List[Finding] = []
        rel_path = os.path.relpath(file_path, self.target_dir)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            content = "".join(lines)
        except Exception:
            return findings

        # Check if file references Gemini, OpenAI, or LLM prompt generation
        is_llm_file = any(kw in content for kw in [
            "genai", "GenerativeModel", "generate_content", "gemini", "prompt", "llm", "agent"
        ])
        if not is_llm_file:
            return findings

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if line_str.startswith("#"):
                continue

            # 1. Unsanitized Prompt Concatenation (Prompt Injection Vulnerability)
            # Detect f-strings or string addition directly feeding external variables into prompt definitions
            if ("prompt" in line_str.lower() or "user_input" in line_str.lower() or "article" in line_str.lower()) and ("=" in line_str):
                if re.search(r"f['\"].*\{[a-zA-Z0-9_]+\}.*['\"]", line_str) and not re.search(r"<(user_input|article|data|content)>", line_str):
                    # Check if variable being concatenated lacks boundary tags
                    if any(var in line_str for var in ["article", "query", "user_text", "input", "text", "content"]):
                        findings.append(Finding(
                            scanner="AIGuardrailsChecker",
                            rule_id="AI-001",
                            severity="HIGH",
                            file_path=rel_path,
                            line_number=idx,
                            description="Unsanitized user/article variable concatenated into LLM prompt template",
                            snippet=line_str,
                            recommendation="Isolate untrusted variables inside structural delimiters (e.g. '<article_content>{text}</article_content>') to mitigate prompt injection."
                        ))

            # 2. Unsafe Execution of Model Output
            if re.search(r"\b(eval|exec)\s*\(\s*.*(response|output|result|model_out).*\)", line_str, re.IGNORECASE):
                findings.append(Finding(
                    scanner="AIGuardrailsChecker",
                    rule_id="AI-002",
                    severity="CRITICAL",
                    file_path=rel_path,
                    line_number=idx,
                    description="Direct execution ('eval/exec') of raw LLM output text",
                    snippet=line_str,
                    recommendation="Never execute LLM responses as code. Parse model output into structured Pydantic models or JSON schemas."
                ))

            # 3. Unsafe JSON Parsing of Model Response without Fallback/Sanitization
            if "json.loads(" in line_str and any(kw in line_str for kw in ["response", "result", "text"]):
                # Check if wrapped in try/except or regex cleaner
                has_try_block = False
                for prev_i in range(max(0, idx - 5), idx):
                    if "try:" in lines[prev_i]:
                        has_try_block = True
                        break
                if not has_try_block:
                    findings.append(Finding(
                        scanner="AIGuardrailsChecker",
                        rule_id="AI-003",
                        severity="MEDIUM",
                        file_path=rel_path,
                        line_number=idx,
                        description="Unsafe JSON parsing of LLM response without try/except handling",
                        snippet=line_str,
                        recommendation="Wrap model JSON parsing in a try/except block to gracefully handle malformed or injected model outputs."
                    ))

            # 4. System Prompt Instruction Leakage Prevention
            if "system_instruction" in line_str and ("api_key" in line_str.lower() or "secret" in line_str.lower()):
                findings.append(Finding(
                    scanner="AIGuardrailsChecker",
                    rule_id="AI-004",
                    severity="HIGH",
                    file_path=rel_path,
                    line_number=idx,
                    description="System instruction contains references to API keys or internal secrets",
                    snippet=line_str,
                    recommendation="Remove internal secret references from system instructions to prevent prompt leak disclosure."
                ))

            # 5. Missing Gemini API Temperature / Safety Settings Controls
            if "GenerativeModel(" in line_str:
                # Check if safety_settings is specified in nearby lines
                window = "".join(lines[max(0, idx-1):min(len(lines), idx+10)])
                if "safety_settings" not in window:
                    findings.append(Finding(
                        scanner="AIGuardrailsChecker",
                        rule_id="AI-005",
                        severity="LOW",
                        file_path=rel_path,
                        line_number=idx,
                        description="Gemini GenerativeModel instantiated without explicit safety_settings",
                        snippet=line_str,
                        recommendation="Explicitly configure safety_settings (e.g., HARASSMENT, HATE_SPEECH thresholds) on GenerativeModel initialization."
                    ))

        return findings

    def scan(self) -> List[Finding]:
        """Scan repository for AI/LLM guardrail vulnerabilities."""
        all_findings: List[Finding] = []
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    all_findings.extend(self.scan_file(full_path))
        return all_findings

if __name__ == "__main__":
    checker = AIGuardrailsChecker(".")
    results = checker.scan()
    print(f"AI Guardrails Checker completed. Found {len(results)} issues.")
    for res in results:
        print(f"[{res.severity}] {res.file_path}:{res.line_number} - {res.description}")
