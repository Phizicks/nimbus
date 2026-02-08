#!/usr/bin/env bash

set -eu -o pipefail


REPOSITORY_NAME="test-rust-repository"
FUNCTION_NAME=ecr-rust-function
IMAGE_TAG="latest"
DOCKERFILE_PATH="."
endpoint_url=$(aws configure get endpoint_url 2>/dev/null)
ECR_URI="${endpoint_url#http://}/${REPOSITORY_NAME}"

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

# Create multi-stage Dockerfile that compiles Rust inside Docker
log_info "Creating multi-stage Dockerfile for Rust Lambda (no local Cargo required)..."
cat > Dockerfile.multi << 'EOF'
# Stage 1: Build the Rust binary using official Rust image
FROM rust:1.75-slim as builder

WORKDIR /build

# Copy your Rust project files
COPY Cargo.toml ./
COPY src ./src

# Build the release binary
RUN cargo build --release --target x86_64-unknown-linux-gnu

# Stage 2: Create the Lambda runtime image
FROM public.ecr.aws/lambda/provided:al2023

# Copy the compiled binary from builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-gnu/release/bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap

# Set the handler (Lambda will execute the bootstrap binary)
CMD [ "bootstrap" ]
EOF

# Create ECR repository if it doesn't exist
log_info "Creating ECR repository '${REPOSITORY_NAME}' if it doesn't exist..."
aws ecr create-repository \
    --repository-name "${REPOSITORY_NAME}" \
    2>/dev/null || log_warn "Repository [${REPOSITORY_NAME}] might already exist"

log_info "Describe ECR repository '${REPOSITORY_NAME}'"
aws ecr describe-repositories | cat || log_warn "Failed to describe repository [${REPOSITORY_NAME}]"

log_info "Delete lambda function [${FUNCTION_NAME}], if it exists..."
aws lambda delete-function \
  --function-name ${FUNCTION_NAME} \
  2>/dev/null || log_warn "Function [${FUNCTION_NAME}] might not exist"

log_info "Building Docker image with multi-stage build (Rust compilation happens inside Docker)..."
docker build \
    --platform linux/amd64 \
    --progress plain \
    -f Dockerfile.multi \
    -t ${REPOSITORY_NAME}:${IMAGE_TAG} \
    "${DOCKERFILE_PATH}"

log_info "Tagging Docker image..."
docker tag "${REPOSITORY_NAME}:${IMAGE_TAG}" "${ECR_URI}:${IMAGE_TAG}"

log_info "Simulate login to ECR..."
aws ecr get-login-password | docker login --username AWS --password-stdin "${ECR_URI}"

log_info "Pushing Docker image to ECR..."
docker push "${ECR_URI}:${IMAGE_TAG}"

# Create function from ECR image
log_info "Create AWS Rust Image lambda function '${FUNCTION_NAME}'"
aws lambda create-function \
  --function-name ${FUNCTION_NAME} \
  --runtime provided.al2023 \
  --package-type Image \
  --code ImageUri="${ECR_URI}:${IMAGE_TAG}" \
  --environment "Variables={ENVIRONMENT=dev,ENGINE_ROOT_LOCATION=/app/engines,SESSION_EXPIRATION_QUEUE_URL=http://localhost:4566/session-queue,SEND_TO_BIZ_METRICS_QUEUE_URL=http://localhost:4566/bix-queue,TRANSACTION_ASSETS_BUCKET_NAME=bucket,JWT_SECRET_SSM_PATH=/JWT_SECRET,IDVP_OAUTH_AUTHORIZER_FUNCTION_ARN=arn,TENANTS_USERS_TABLE_NAME=arm:aws:table-users,TENANTS_USERS_TABLE_NAME=tenant-users,TENANTS_USERS_TABLE_GSI3_INDEX_NAME=gsi3,IDVP_TRANSACTION_TABLE_NAME=tx-table,ENGINE4_FR_ENGINE_FUNCTION_ARN=arn:aws:fr-engine,SPOOF_ENGINE_FUNCTION_ARN=arn:aws:spoof-engine,ADDRESS_ENGINE_FUNCTION_ARN=arn:aws:address-engine,PROOF_OF_ADDRESS_ENGINE_FUNCTION_ARN=arn:aws:poa-engine,CERTIFICATES_ENGINE_FUNCTION_ARN=arn:aws:cert-engine,TENANT_KMS_KEY_ID=key-id}" \
  --role arn:aws:iam::456645664566:role/lambda-role || log_error "Failed to create function [${FUNCTION_NAME}]"

log_info "Cold Start: Invoking lambda function '${FUNCTION_NAME}' (Rust compiled via Docker multi-stage build)"
time aws lambda invoke --function-name ${FUNCTION_NAME} \
    --cli-binary-format raw-in-base64-out \
    --payload "{\"body\":\"$(date)\"}" response.json

echo ""
log_info "Response:"
jq < response.json

echo ""
log_info "Rust Lambda test completed successfully (no local Cargo installation required :) )"
