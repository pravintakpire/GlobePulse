#!/usr/bin/env python3
"""
GlobePulse Central Security Check Orchestrator
==============================================
Primary entry point for running the complete automated security analysis suite.
Runs Secret Scanner, Dependency Auditor, Code Scanner, and AI Guardrails Checker.

Usage:
    python security/security_check.py [--fail-on HIGH] [--output-dir security/reports]
"""

import argparse
import os
import sys
from typing import List

# Ensure security directory is in Python path for local module imports
SECURITY_DIR = os.path.dirname(os.path.abspath(__file__))
if SECURITY_DIR not in sys.path:
    sys.path.insert(0, SECURITY_DIR)

from secret_scanner import SecretScanner, Finding
from dependency_audit import DependencyAuditor
from code_scanner import CodeScanner
from ai_guardrails_check import AIGuardrailsChecker
from report_generator import ReportGenerator


def main() -> int:
    parser = argparse.ArgumentParser(
        description="GlobePulse Automated Security Analysis Framework",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Root directory path to audit"
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity level required to trigger non-zero failure exit code"
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join(SECURITY_DIR, "reports"),
        help="Directory path where report artifacts will be saved"
    )
    parser.add_argument("--skip-secrets", action="store_true", help="Skip Secret Scanner")
    parser.add_argument("--skip-deps", action="store_true", help="Skip Dependency Auditor")
    parser.add_argument("--skip-code", action="store_true", help="Skip Static Code Scanner")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI Guardrails Checker")
    parser.add_argument("--verbose", action="store_true", help="Print verbose execution progress")

    args = parser.parse_args()
    target_path = os.path.abspath(args.path)

    print("====================================================")
    print(" GlobePulse Automated Security Suite Starting...")
    print(f" Target Repository Path: {target_path}")
    print(f" Failure Threshold     : {args.fail_on}")
    print("====================================================\n")

    all_findings: List[Finding] = []

    # 1. Run Secret Scanner
    if not args.skip_secrets:
        if args.verbose:
            print("[+] Executing Secret Scanner...")
        sec_scanner = SecretScanner(target_path)
        sec_findings = sec_scanner.scan()
        all_findings.extend(sec_findings)
        print(f"[*] Secret Scanner completed: {len(sec_findings)} finding(s)")

    # 2. Run Dependency Auditor
    if not args.skip_deps:
        if args.verbose:
            print("[+] Executing Dependency Auditor...")
        dep_auditor = DependencyAuditor(target_path)
        dep_findings = dep_auditor.audit()
        all_findings.extend(dep_findings)
        print(f"[*] Dependency Auditor completed: {len(dep_findings)} finding(s)")

    # 3. Run Static Code Scanner
    if not args.skip_code:
        if args.verbose:
            print("[+] Executing Static Code Scanner...")
        code_scanner = CodeScanner(target_path)
        code_findings = code_scanner.scan()
        all_findings.extend(code_findings)
        print(f"[*] Static Code Scanner completed: {len(code_findings)} finding(s)")

    # 4. Run AI Guardrails Checker
    if not args.skip_ai:
        if args.verbose:
            print("[+] Executing AI Guardrails Checker...")
        ai_checker = AIGuardrailsChecker(target_path)
        ai_findings = ai_checker.scan()
        all_findings.extend(ai_findings)
        print(f"[*] AI Guardrails Checker completed: {len(ai_findings)} finding(s)")

    print(f"\n[*] Total security findings identified across modules: {len(all_findings)}")

    # 5. Generate Reports & Print Terminal Summary
    report_gen = ReportGenerator(all_findings, output_dir=args.output_dir)
    md_file = report_gen.generate_markdown(pass_threshold=args.fail_on)
    json_file = report_gen.generate_json()
    passed = report_gen.print_terminal_summary(pass_threshold=args.fail_on)

    print(f"[+] Markdown report generated: {md_file}")
    print(f"[+] JSON report generated    : {json_file}")

    if not passed:
        print("\n[!] Security audit failed. Please remediate the reported issues or update your fail threshold.")
        return 1

    print("\n[+] All security checks passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
