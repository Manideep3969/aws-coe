#!/bin/bash
# ============================================================================
# AWS CoE - Bootstrap Script
# Creates the prerequisite S3 state bucket and related resources
# before running terraform init with a real backend.
#
# This script should be run ONCE per AWS account/region before deploying
# any Terraform infrastructure. It creates:
#   1. S3 bucket for Terraform state (with versioning, encryption, public access block)
#   2. Enables S3 state locking natively (use_lockfile = true)
#
# Prerequisites:
#   - AWS CLI v2 installed and configured with appropriate credentials
#   -jq installed (optional, for pretty output)
#   - Sufficient IAM permissions to create S3 buckets
#
# Usage:
#   ./scripts/bootstrap.sh                    # Use defaults
#   ./scripts/bootstrap.sh -b my-custom-bucket -r us-east-1 -p my-profile
#   ./scripts/bootstrap.sh --help
# ============================================================================

set -euo pipefail

# ============================================================================
# Defaults
# ============================================================================

BUCKET_NAME=""
REGION="ap-south-1"
PROFILE=""
DRY_RUN=false

# ============================================================================
# Parse arguments
# ============================================================================

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Bootstrap the AWS CoE Terraform state backend."
    echo ""
    echo "Options:"
    echo "  -b, --bucket    S3 bucket name for Terraform state (default: npci-terraform-state-<ACCOUNT_ID>)"
    echo "  -r, --region    AWS region (default: ap-south-1)"
    echo "  -p, --profile   AWS CLI profile to use"
    echo "  -n, --dry-run   Show what would be created without actually creating"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 -b my-terraform-state -r us-east-1"
    echo "  $0 -p npci-production"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--bucket)
            BUCKET_NAME="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# ============================================================================
# Colors
# ============================================================================

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# ============================================================================
# Build AWS CLI command
# ============================================================================

AWS_CMD="aws"
if [[ -n "$PROFILE" ]]; then
    AWS_CMD="aws --profile $PROFILE"
fi

# ============================================================================
# Pre-flight checks
# ============================================================================

echo "${GREEN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║     AWS CoE - Terraform Bootstrap Script        ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo "${NC}"

echo "${YELLOW}Running pre-flight checks...${NC}"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "${RED}ERROR: AWS CLI is not installed.${NC}"
    echo "Install it with: brew install awscli"
    exit 1
fi
echo "  ✅ AWS CLI found"

# Check AWS credentials
echo "${YELLOW}Checking AWS credentials...${NC}"
if ! eval "$AWS_CMD sts get-caller-identity" &> /dev/null; then
    echo "${RED}ERROR: AWS credentials not configured.${NC}"
    echo "Run: aws configure"
    if [[ -n "$PROFILE" ]]; then
        echo "  or: aws configure --profile $PROFILE"
    fi
    exit 1
fi

CALLER_IDENTITY=$(eval "$AWS_CMD sts get-caller-identity --region $REGION --output json")
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | grep -o '"Account": *"[^"]*"' | grep -o '"[0-9]*"' | tr -d '"')
USER_ARN=$(echo "$CALLER_IDENTITY" | grep -o '"Arn": *"[^"]*"' | grep -o '"arn:[^"]*"' | tr -d '"')

echo "  ✅ Authenticated as: $USER_ARN"
echo "  ✅ Account ID: $ACCOUNT_ID"

# Set default bucket name if not provided
if [[ -z "$BUCKET_NAME" ]]; then
    BUCKET_NAME="npci-terraform-state-${ACCOUNT_ID}"
fi

echo ""
echo "${YELLOW}Bootstrap Configuration:${NC}"
echo "  S3 Bucket:  $BUCKET_NAME"
echo "  Region:     $REGION"
echo "  Profile:    ${PROFILE:-default}"
echo "  Dry Run:    $DRY_RUN"
echo ""

# ============================================================================
# Check if bucket already exists
# ============================================================================

echo "${YELLOW}Checking if S3 bucket already exists...${NC}"
if eval "$AWS_CMD s3api head-bucket --bucket $BUCKET_NAME --region $REGION" 2>/dev/null; then
    echo "${GREEN}  ✅ S3 bucket '$BUCKET_NAME' already exists.${NC}"

    echo ""
    echo "${YELLOW}Verifying bucket configuration...${NC}"

    # Check versioning
    VERSIONING=$(eval "$AWS_CMD s3api get-bucket-versioning --bucket $BUCKET_NAME --region $REGION --output json 2>/dev/null" || echo "{}")
    if echo "$VERSIONING" | grep -q "Enabled"; then
        echo "  ✅ Versioning is enabled"
    else
        echo "${YELLOW}  ⚠️  Versioning is not enabled. Enabling...${NC}"
        if [[ "$DRY_RUN" == false ]]; then
            eval "$AWS_CMD s3api put-bucket-versioning --bucket $BUCKET_NAME --region $REGION --versioning-configuration Status=Enabled"
            echo "  ✅ Versioning enabled"
        fi
    fi

    # Check encryption
    ENCRYPTION=$(eval "$AWS_CMD s3api get-bucket-encryption --bucket $BUCKET_NAME --region $REGION --output json 2>/dev/null" || echo "{}")
    if echo "$ENCRYPTION" | grep -q "AES256\|aws:kms"; then
        echo "  ✅ Encryption is configured"
    else
        echo "${YELLOW}  ⚠️  Encryption is not configured. Enabling...${NC}"
        if [[ "$DRY_RUN" == false ]]; then
            eval "$AWS_CMD s3api put-bucket-encryption --bucket $BUCKET_NAME --region $REGION --server-side-encryption-configuration '{
                \"Rules\": [{
                    \"ApplyServerSideEncryptionByDefault\": {
                        \"SSEAlgorithm\": \"AES256\"
                    }
                }]
            }'"
            echo "  ✅ AES256 encryption enabled"
        fi
    fi

    # Check public access block
    PAB=$(eval "$AWS_CMD s3api get-public-access-block --bucket $BUCKET_NAME --region $REGION --output json 2>/dev/null" || echo "{}")
    if echo "$PAB" | grep -q "true"; then
        echo "  ✅ Public access block is configured"
    else
        echo "${YELLOW}  ⚠️  Public access block not configured. Enabling...${NC}"
        if [[ "$DRY_RUN" == false ]]; then
            eval "$AWS_CMD s3api put-public-access-block --bucket $BUCKET_NAME --region $REGION --public-access-block-configuration '{
                \"BlockPublicAcls\": true,
                \"IgnorePublicAcls\": true,
                \"BlockPublicPolicy\": true,
                \"RestrictPublicBuckets\": true
            }'"
            echo "  ✅ Public access block enabled"
        fi
    fi

    echo ""
    echo "${GREEN}Bucket exists and is properly configured.${NC}"
    echo ""
    echo "${YELLOW}Next steps:${NC}"
    echo "  1. Copy terraform.tfvars.example to terraform.tfvars"
    echo "  2. Fill in your account-specific values"
    echo "  3. Update main.tf backend bucket name to: $BUCKET_NAME"
    echo "  4. Run: terraform init"
    echo "  5. Run: make plan"
    echo ""
    exit 0
fi

# ============================================================================
# Create S3 bucket
# ============================================================================

echo ""
echo "${YELLOW}Creating S3 bucket: $BUCKET_NAME${NC}"

if [[ "$DRY_RUN" == true ]]; then
    echo "  [DRY RUN] Would create S3 bucket: $BUCKET_NAME"
    echo "  [DRY RUN] Would enable versioning"
    echo "  [DRY RUN] Would enable AES256 encryption"
    echo "  [DRY RUN] Would enable public access block"
    echo "  [DRY RUN] Would add bucket policy for state lockfile"
    echo ""
    echo "${GREEN}Dry run complete. No resources were created.${NC}"
    exit 0
fi

# Create bucket (region-specific handling)
if [[ "$REGION" == "us-east-1" ]]; then
    eval "$AWS_CMD s3api create-bucket --bucket $BUCKET_NAME --region $REGION"
else
    eval "$AWS_CMD s3api create-bucket --bucket $BUCKET_NAME --region $REGION --create-bucket-configuration LocationConstraint=$REGION"
fi
echo "  ✅ S3 bucket created"

# Enable versioning
echo "${YELLOW}Enabling bucket versioning...${NC}"
eval "$AWS_CMD s3api put-bucket-versioning --bucket $BUCKET_NAME --region $REGION --versioning-configuration Status=Enabled"
echo "  ✅ Versioning enabled"

# Enable encryption
echo "${YELLOW}Enabling bucket encryption...${NC}"
eval "$AWS_CMD s3api put-bucket-encryption --bucket $BUCKET_NAME --region $REGION --server-side-encryption-configuration '{
    \"Rules\": [{
        \"ApplyServerSideEncryptionByDefault\": {
            \"SSEAlgorithm\": \"AES256\"
        }
    }]
}'"
echo "  ✅ AES256 encryption enabled"

# Enable public access block
echo "${YELLOW}Enabling public access block...${NC}"
eval "$AWS_CMD s3api put-public-access-block --bucket $BUCKET_NAME --region $REGION --public-access-block-configuration '{
    \"BlockPublicAcls\": true,
    \"IgnorePublicAcls\": true,
    \"BlockPublicPolicy\": true,
    \"RestrictPublicBuckets\": true
}'"
echo "  ✅ Public access block enabled"

# Add lifecycle rule for old state versions
echo "${YELLOW}Adding lifecycle rule for state version cleanup...${NC}"
eval "$AWS_CMD s3api put-bucket-lifecycle-configuration --bucket $BUCKET_NAME --region $REGION --lifecycle-configuration '{
    \"Rules\": [{
        \"ID\": \"cleanup-old-state-versions\",
        \"Status\": \"Enabled\",
        \"Filter\": {
            \"Prefix\": \"\"
        },
        \"NoncurrentVersionTransitions\": [{
            \"NoncurrentDays\": 90,
            \"StorageClass\": \"STANDARD_IA\"
        }, {
            \"NoncurrentDays\": 180,
            \"StorageClass\": \"GLACIER\"
        }],
        \"NoncurrentVersionExpiration\": {
            \"NoncurrentDays\": 365
        }
    }]
}'"
echo "  ✅ Lifecycle rule added (old versions → IA at 90d → Glacier at 180d → Delete at 365d)"

# Tag the bucket
echo "${YELLOW}Tagging bucket...${NC}"
eval "$AWS_CMD s3api put-bucket-tagging --bucket $BUCKET_NAME --region $REGION --tagging '{
    \"TagSet\": [
        {\"Key\": \"ManagedBy\", \"Value\": \"aws-coe-terraform\"},
        {\"Key\": \"Project\", \"Value\": \"npci-security-baseline\"},
        {\"Key\": \"Purpose\", \"Value\": \"terraform-state-backend\"}
    ]
}'"
echo "  ✅ Bucket tagged"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "${GREEN}════════════════════════════════════════════════════${NC}"
echo "${GREEN}  Bootstrap Complete!${NC}"
echo "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  S3 Bucket:       $BUCKET_NAME"
echo "  Region:          $REGION"
echo "  Versioning:      Enabled"
echo "  Encryption:      AES256"
echo "  Public Access:    Blocked"
echo "  State Locking:   Native (use_lockfile = true)"
echo ""
echo "${YELLOW}Next steps:${NC}"
echo "  1. Update main.tf backend config bucket name:"
echo "     bucket = \"$BUCKET_NAME\""
echo ""
echo "  2. Copy and configure variables:"
echo "     cp terraform.tfvars.example terraform.tfvars"
echo "     # Edit terraform.tfvars with your account-specific values"
echo ""
echo "  3. Initialize Terraform:"
echo "     terraform init"
echo ""
echo "  4. Plan and apply:"
echo "     make plan"
echo "     make apply"
echo ""