set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

DOCKERFILE_PATH="."

FUNCTION_NAME=python3-function

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

# Zip it
zip function.zip lambda_function.py

log_info "Delete lambda function [${FUNCTION_NAME}']"
aws lambda delete-function \
  --function-name ${FUNCTION_NAME} \
  2>/dev/null || log_warn "Function [${FUNCTION_NAME}] might not exist"

# Create function with ZIP
aws lambda create-function \
  --function-name ${FUNCTION_NAME} \
  --runtime python3.11 \
  --handler lambda_function.handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::456645664566:role/lambda-role | cat || log_warn "Failed to create function"

# Invoke it
log_info "Invoking lambda function '${FUNCTION_NAME}' with input 'lambda_function.py'"
aws lambda invoke --function-name ${FUNCTION_NAME} --cli-binary-format raw-in-base64-out --payload '{"name":"TESTOK"}' response.json

rm function.zip 2>/dev/null
echo "Response:"
jq < response.json

