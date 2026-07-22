#!/usr/bin/env bash
# ==============================================================================
# GlobePulse Git Pre-Commit Hook
# Automatically executes security check suite before allowing git commit.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "----------------------------------------------------"
echo "Running GlobePulse Automated Pre-Commit Security Audit..."
echo "----------------------------------------------------"

# Prefer python3 in environment
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

# Execute security check orchestrator with HIGH failure threshold
"$PYTHON_CMD" "$REPO_ROOT/security/security_check.py" --fail-on HIGH --path "$REPO_ROOT"

STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo ""
    echo "======================================================================"
    echo " [ERROR] Git Commit Blocked due to Security Vulnerability Findings!"
    echo " Review the generated report in security/reports/latest_report.md"
    echo " Resolve all CRITICAL and HIGH severity issues before committing."
    echo "======================================================================"
    exit 1
fi

echo ""
echo "[SUCCESS] Pre-Commit Security Checks Passed. Proceeding with commit."
exit 0
