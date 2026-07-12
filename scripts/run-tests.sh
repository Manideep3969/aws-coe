#!/bin/bash
# ============================================================================
# AWS CoE - Local Test Runner
# Runs all validation checks locally before committing and pushing
# ============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0

run_check() {
    local name="$1"
    shift
    echo ""
    echo "${YELLOW}========================================${NC}"
    echo "${YELLOW}Running: ${name}${NC}"
    echo "${YELLOW}========================================${NC}"
    if "$@"; then
        echo "${GREEN}PASSED: ${name}${NC}"
        PASS=$((PASS + 1))
    else
        echo "${RED}FAILED: ${name}${NC}"
        FAIL=$((FAIL + 1))
    fi
}

echo "${GREEN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║    AWS CoE - Pre-Commit Test Suite      ║"
echo "  ╚══════════════════════════════════════════╝"
echo "${NC}"

# ============================================================================
# 1. Check if required tools are installed
# ============================================================================

echo "${YELLOW}Checking required tools...${NC}"

for tool in python3 pip3 git; do
    if ! command -v "$tool" &> /dev/null; then
        echo "${RED}ERROR: $tool is not installed${NC}"
        exit 1
    fi
done
echo "${GREEN}All required tools found${NC}"

# ============================================================================
# 2. Python dependency check
# ============================================================================

if [ -f "requirements-dev.txt" ]; then
    echo "${YELLOW}Installing Python dev dependencies...${NC}"
    pip3 install -q -r requirements-dev.txt 2>/dev/null || pip install -q -r requirements-dev.txt 2>/dev/null || true
fi

# ============================================================================
# 3. Terraform format check (if terraform is installed)
# ============================================================================

if command -v terraform &> /dev/null; then
    run_check "Terraform fmt" terraform fmt -recursive -check -diff .
    run_check "Terraform validate (root)" bash -c 'terraform init -backend=false && terraform validate'
else
    echo "${YELLOW}SKIPPED: Terraform not installed (install from https://developer.hashicorp.com/terraform/downloads)${NC}"
fi

# ============================================================================
# 4. TFLint (if installed)
# ============================================================================

if command -v tflint &> /dev/null; then
    run_check "TFLint" tflint --recursive
else
    echo "${YELLOW}SKIPPED: TFLint not installed (install from https://github.com/terraform-linters/tflint)${NC}"
fi

# ============================================================================
# 5. TFSec (if installed)
# ============================================================================

if command -v tfsec &> /dev/null; then
    run_check "TFSec security scan" tfsec .
else
    echo "${YELLOW}SKIPPED: TFSec not installed (install from https://github.com/aquasecurity/tfsec)${NC}"
fi

# ============================================================================
# 6. SCP Policy validation
# ============================================================================

run_check "SCP Policy JSON validation" python3 -c "
import json, os, sys
policies_dir = 'scp/policies'
errors = 0
for fname in os.listdir(policies_dir):
    if not fname.endswith('.json'):
        continue
    fpath = os.path.join(policies_dir, fname)
    try:
        with open(fpath) as f:
            policy = json.load(f)
        if policy.get('Version') != '2012-10-17':
            print(f'ERROR: {fname} has invalid Version: {policy.get(\"Version\")}')
            errors += 1
        if 'Statement' not in policy:
            print(f'ERROR: {fname} missing Statement')
            errors += 1
        else:
            print(f'  OK: {fname} - {len(policy[\"Statement\"])} statements')
    except json.JSONDecodeError as e:
        print(f'ERROR: Invalid JSON in {fname}: {e}')
        errors += 1
sys.exit(errors)
"

# ============================================================================
# 7. Python linting
# ============================================================================

run_check "Flake8 (Python linter)" python3 -m flake8 --max-line-length=120 --ignore=E203,W503 incident-response/automation/src/ || true

if command -v black &> /dev/null || python3 -m black --version &> /dev/null; then
    run_check "Black (Python formatter check)" python3 -m black --check --line-length=120 incident-response/automation/src/ || true
else
    echo "${YELLOW}SKIPPED: Black not installed${NC}"
fi

if command -v bandit &> /dev/null || python3 -m bandit --version &> /dev/null; then
    run_check "Bandit (Python security scan)" python3 -m bandit -c -ll -r incident-response/automation/src/ || true
else
    echo "${YELLOW}SKIPPED: Bandit not installed${NC}"
fi

# ============================================================================
# 8. Python unit tests
# ============================================================================

run_check "Python unit tests" python3 -m pytest tests/unit/ -v --tb=short

# ============================================================================
# 9. Pre-commit hooks (if installed)
# ============================================================================

if command -v pre-commit &> /dev/null; then
    run_check "Pre-commit hooks" pre-commit run --all-files
else
    echo "${YELLOW}SKIPPED: pre-commit not installed (pip install pre-commit && pre-commit install)${NC}"
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "${GREEN}══════════════════════════════════════════${NC}"
echo "${GREEN}  TEST SUMMARY${NC}"
echo "${GREEN}══════════════════════════════════════════${NC}"
echo "${GREEN}  PASSED: ${PASS}${NC}"
echo "${RED}  FAILED: ${FAIL}${NC}"
echo "${GREEN}══════════════════════════════════════════${NC}"

if [ $FAIL -gt 0 ]; then
    echo "${RED}  Some checks failed. Fix errors before committing.${NC}"
    exit 1
else
    echo "${GREEN}  All checks passed! Safe to commit and push.${NC}"
    exit 0
fi