#!/usr/bin/env bash

set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '


REPOSITORY_NAME="zip-nodejs-app"
IMAGE_TAG="latest"
DOCKERFILE_PATH="."
REGISTRY_HOST="localhost:4566"

FUNCTION_NAME=nodejs-function

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
    rm function.zip 2>/dev/null || true
}
trap cleanup EXIT

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

log_info "Creating Zip archive '${FUNCTION_NAME}' -> function.zip"
rm function.zip 2>/dev/null || true
(cd src && zip ../function.zip index.js)

log_info "Deleting NodeJS lambda function '${FUNCTION_NAME}' (if it exists) "
aws lambda delete-function --function-name ${FUNCTION_NAME} 2>/dev/null || log_warn "Function '${FUNCTION_NAME}' doesn't appear to exist"

log_info "Creating NodeJS Lambda Function '${FUNCTION_NAME}'"
aws lambda create-function \
    --function-name ${FUNCTION_NAME} \
    --runtime nodejs22.x \
    --handler index.handler \
    --role arn:aws:iam::456645664566:role/nodejs-role \
    --zip-file fileb://function.zip

sleep 5

log_info "Invoking NodeJS lambda function '${FUNCTION_NAME}'"
echo "Result:"
aws lambda invoke --function-name ${FUNCTION_NAME} --cli-binary-format raw-in-base64-out --payload "{\"Records\": [ {\"test\":\"$(date)\"} ]}" response.json

echo "Response:"
jq < response.json
