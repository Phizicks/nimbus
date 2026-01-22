#!/usr/bin/env bash

set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '


IMAGE_TAG="latest"
REPOSITORY_NAME="test-ecr-repository"
IMAGE_TAG="latest"
DOCKERFILE_PATH="."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up... (exit code: $exit_code)"
    rm response.json 2>/dev/null || true
}
# trap cleanup EXIT

# Function to print colored messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

FUNCTION_NAME=ecr-python-function

function cleanup {
    aws ecr delete-repository --repository-name "${REPOSITORY_NAME}" >/dev/null  2>&1 || true
    aws lambda delete-function --function-name ${FUNCTION_NAME} >/dev/null 2>&1 || true
}
cleanup

# Create ECR repository if it doesn't exist
log_info "Creating ECR repository '${REPOSITORY_NAME}'"
ECR_URI=$(aws ecr create-repository \
    --repository-name "${REPOSITORY_NAME}" \
    2>/dev/null| jq -r '.repository.repositoryUri') || log_warn "Repository [${REPOSITORY_NAME}] might already exist"

echo "Repository : $ECR_URI"

log_info "Describe ECR repository '${REPOSITORY_NAME}'"
aws ecr describe-repositories | cat || log_warn "Failed to describe repository [${REPOSITORY_NAME}]"

log_info "Delete lambda function [${FUNCTION_NAME}'], if it exists..."
aws lambda delete-function \
  --function-name ${FUNCTION_NAME} \
  2>/dev/null || log_warn "Function [${FUNCTION_NAME}] might not exist"

log_info "Building Docker image..."
docker build -t "${REPOSITORY_NAME}:${IMAGE_TAG}" "${DOCKERFILE_PATH}"

log_info "Tagging Docker image..."
docker tag "${REPOSITORY_NAME}:${IMAGE_TAG}" "${ECR_URI}:${IMAGE_TAG}"

#log_info "Simulate login to ECR..."
aws ecr get-login-password | docker login --username AWS --password-stdin "${ECR_URI}"

log_info "Pushing Docker image to ECR..."
docker push "${ECR_URI}:${IMAGE_TAG}"

# Create function from existing image
log_info "Create AWS Python Image lambda function '${FUNCTION_NAME}'"
aws lambda create-function \
  --function-name ${FUNCTION_NAME} \
  --package-type Image \
  --code ImageUri="${ECR_URI}:${IMAGE_TAG}" \
  --role arn:aws:iam::456645664566:role/lambda-role | jq || log_warn "Failed to create function [${FUNCTION_NAME}]"

echo "Response:"
jq < response.json
