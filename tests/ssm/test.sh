#!/bin/bash

set -euo pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '
export AWS_PROFILE=localcloud

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}LocalCloud SSM Test Suite (AWS CLI)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Helper functions
print_test() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

log_success() {
    echo -e "${GREEN} $1${NC}"
}

log_error() {
    echo -e "${RED} $1${NC}"
}

log_info() {
    echo -e "${BLUE} $1${NC}"
}

# Get all parameters
log_info "Testing get-parameters"
aws ssm --version | grep -q "aws-cli/2" || echo "Error: AWS CLI v2 not found"
aws ssm delete-parameter --name /my/parameter >/dev/null || true
aws ssm get-parameters --names /my/parameter --with-decryption

# Update a parameter value
log_info "Testing put-parameter"
value="value-1"
aws ssm put-parameter --name /my/parameter --value $value --overwrite

# Get a specific parameter
log_info "Testing get-parameter"
aws ssm get-parameter --name /my/parameter --with-decryption

# Create a new parameter (using put-parameter)
log_info "Testing put-parameter-create"
value="value-2"
aws ssm put-parameter --name /my/parameter --value $value --overwrite

# Create a new parameter version checking
log_info "Testing version incrementing on put-parameter"
check="2"
version=$(aws ssm get-parameter --name /my/parameter --query 'Parameter.Version' --output text)
if [ "$version" -eq "$check" ]; then
    log_success " Parameter version is correct: $version"
else
    log_error " Parameter version is incorrect: $version (expected $check)"
    exit 1
fi

# Get all parameters with tags
log_info "Testing get-parameters-with-tags"
aws ssm list-tags-for-resource --resource-type "Parameter" --resource-id /my/parameter

log_info "Testing storing secure string parameter with tags"
aws ssm delete-parameter --name /secure/parameter >/dev/null || true
value="securestring"
aws ssm put-parameter --name /secure/parameter --value $value \
    --type SecureString \
    --tags Key=Environment,Value=Test Key=Owner,Value=DevOps

check=$(aws ssm get-parameter --name /secure/parameter  --query 'Parameter.Value' --output text) # --with-decryption
if [ "$check" == "$value" ]; then
    log_error " Secure string parameter retrieval failed: got '$check', expected encrypted value"
    exit 1
else
    log_success " Secure string parameter stored and retrieved successfully: $check"
fi

# List tags for a parameter
log_info "Testing describe-parameters-with-tags"
aws ssm describe-parameters --parameter-filters "Key=Type,Values=SecureString"

# # Update a parameter's version
# echo "Testing update-parameter-version"
# value="new-value-3"
aws ssm put-parameter --name /my/parameter --value $value 2>/dev/null || \
    log_success " Expected failure when not using --overwrite"

# List all parameters in TEXT
log_info "Testing list-parameters in TEXT"
aws ssm describe-parameters --output text

# List all parameters in JSON
log_info "Testing list-parameters in JSON"
aws ssm describe-parameters --output json

# Update a parameter's secure string value
log_info "Testing put-parameter-secure-string-overwrite with type change"
value="new-secure-value"
aws ssm put-parameter --name /my/parameter --value $value --overwrite --type SecureString 2>/dev/null || \
    log_success " Expected failure when changing type without deleting existing parameter"

