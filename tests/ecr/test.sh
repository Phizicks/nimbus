#!/usr/bin/env bash
set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

# Test configuration
REPOSITORY_NAME="test-ecr-repo-$(date +%s)"
REPOSITORY_NAME_2="test-ecr-repo-2-$(date +%s)"
IMAGE_TAG="latest"
IMAGE_TAG_2="v1.0.0"
DOCKERFILE_PATH="."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

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

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Test assertion functions
assert_success() {
    local test_name="$1"
    local command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "Running: $test_name"

    if eval "$command" >/dev/null 2>&1; then
        log_info "✓ PASSED: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAILED: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_failure() {
    local test_name="$1"
    local command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "Running: $test_name"

    if eval "$command" >/dev/null 2>&1; then
        log_error "✗ FAILED: $test_name (expected failure but succeeded)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        log_info "✓ PASSED: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

assert_contains() {
    local test_name="$1"
    local command="$2"
    local expected="$3"

    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "Running: $test_name"

    local output
    output=$(eval "$command" 2>&1 || true)

    if echo "$output" | grep -q "$expected"; then
        log_info "✓ PASSED: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ FAILED: $test_name"
        log_error "Expected to find: $expected"
        log_error "Got: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_not_contains() {
    local test_name="$1"
    local command="$2"
    local not_expected="$3"

    TESTS_RUN=$((TESTS_RUN + 1))
    log_test "Running: $test_name"

    local output
    output=$(eval "$command" 2>&1 || true)

    if echo "$output" | grep -q "$not_expected"; then
        log_error "✗ FAILED: $test_name"
        log_error "Did not expect to find: $not_expected"
        log_error "Got: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        log_info "✓ PASSED: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    log_info "Starting cleanup..."

    # Delete repositories
    aws ecr delete-repository --repository-name "${REPOSITORY_NAME}" --force 2>/dev/null || true
    aws ecr delete-repository --repository-name "${REPOSITORY_NAME_2}" --force 2>/dev/null || true

    # Clean up local Docker images
    docker rmi "${REPOSITORY_NAME}:${IMAGE_TAG}" 2>/dev/null || true
    docker rmi "${REPOSITORY_NAME}:${IMAGE_TAG_2}" 2>/dev/null || true

    # Remove temp files
    rm -f response.json test-image.tar 2>/dev/null || true

    log_info "Cleanup complete (exit code: $exit_code)"
}

trap cleanup EXIT

# Print test summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo "Tests Run:    $TESTS_RUN"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo "=========================================="

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    fi
}

trap 'print_summary' EXIT

# Start tests
echo "=========================================="
echo "      ECR FUNCTIONALITY TESTS"
echo "=========================================="
echo ""

# Test 1: CreateRepository
log_info "TEST SUITE 1: Repository Management"
assert_success "CreateRepository - Create first repository" \
    "aws ecr create-repository --repository-name ${REPOSITORY_NAME}"

assert_success "CreateRepository - Create second repository" \
    "aws ecr create-repository --repository-name ${REPOSITORY_NAME_2}"

# Test 2: CreateRepository - Duplicate should fail
assert_failure "CreateRepository - Duplicate repository should fail" \
    "aws ecr create-repository --repository-name ${REPOSITORY_NAME}"

# Test 3: DescribeRepositories
assert_contains "DescribeRepositories - List all repositories" \
    "aws ecr describe-repositories" \
    "$REPOSITORY_NAME"

assert_contains "DescribeRepositories - Describe specific repository" \
    "aws ecr describe-repositories --repository-names ${REPOSITORY_NAME}" \
    "repositoryUri"

# Test 4: DescribeRepositories - Non-existent should fail
assert_failure "DescribeRepositories - Non-existent repository should fail" \
    "aws ecr describe-repositories --repository-names non-existent-repo"

# Test 5: Build and push images
log_info ""
log_info "TEST SUITE 2: Image Operations"

# Get ECR URI
ECR_URI=$(aws ecr describe-repositories --repository-names "${REPOSITORY_NAME}" | jq -r '.repositories[0].repositoryUri')
log_info "Repository URI: $ECR_URI"

# Create a simple test Dockerfile if it doesn't exist
if [ ! -f "${DOCKERFILE_PATH}/Dockerfile" ]; then
    log_warn "No Dockerfile found, creating a simple test Dockerfile"
    cat > "${DOCKERFILE_PATH}/Dockerfile" << 'EOF'
FROM public.ecr.aws/lambda/python:3.11
CMD ["lambda_function.handler"]
EOF
fi

# Build image
log_info "Building Docker image..."
assert_success "Docker build - Build test image" \
    "docker build -t ${REPOSITORY_NAME}:${IMAGE_TAG} ${DOCKERFILE_PATH}"

# Tag image
log_info "Tagging Docker image..."
assert_success "Docker tag - Tag image for ECR" \
    "docker tag ${REPOSITORY_NAME}:${IMAGE_TAG} ${ECR_URI}:${IMAGE_TAG}"

# Login to ECR
log_info "Logging in to ECR..."
assert_success "GetAuthorizationToken - ECR login" \
    "aws ecr get-login-password | docker login --username AWS --password-stdin ${ECR_URI}"

# Push image
log_info "Pushing Docker image to ECR..."
assert_success "PutImage - Push image to ECR" \
    "docker push ${ECR_URI}:${IMAGE_TAG}"

# Build and push second tag
log_info "Building and pushing second tag..."
assert_success "Docker tag - Create second tag" \
    "docker tag ${REPOSITORY_NAME}:${IMAGE_TAG} ${ECR_URI}:${IMAGE_TAG_2}"

assert_success "PutImage - Push second tag" \
    "docker push ${ECR_URI}:${IMAGE_TAG_2}"

# Test 6: ListImages
log_info ""
log_info "TEST SUITE 3: Image Listing and Description"

assert_contains "ListImages - List images in repository" \
    "aws ecr list-images --repository-name ${REPOSITORY_NAME}" \
    "$IMAGE_TAG"

assert_contains "ListImages - Verify both tags exist" \
    "aws ecr list-images --repository-name ${REPOSITORY_NAME}" \
    "$IMAGE_TAG_2"

# Test 7: DescribeImages
assert_contains "DescribeImages - Describe all images" \
    "aws ecr describe-images --repository-name ${REPOSITORY_NAME}" \
    "imageTags"

assert_contains "DescribeImages - Describe specific image by tag" \
    "aws ecr describe-images --repository-name ${REPOSITORY_NAME} --image-ids imageTag=${IMAGE_TAG}" \
    "imageDigest"

# Test 8: BatchGetImage
assert_contains "BatchGetImage - Get image manifest" \
    "aws ecr batch-get-image --repository-name ${REPOSITORY_NAME} --image-ids imageTag=${IMAGE_TAG}" \
    "imageManifest"

# Test 9: BatchDeleteImage - Delete single image
log_info ""
log_info "TEST SUITE 4: Image Deletion"

assert_success "BatchDeleteImage - Delete single image by tag" \
    "aws ecr batch-delete-image --repository-name ${REPOSITORY_NAME} --image-ids imageTag=${IMAGE_TAG_2}"
# log_info "Debugging BatchDeleteImage..."
# aws ecr batch-delete-image --repository-name ${REPOSITORY_NAME} --image-ids imageTag=${IMAGE_TAG_2}
# echo $?
# exit

# Verify image was deleted
assert_not_contains "Verify image deleted from registry" \
    "aws ecr list-images --repository-name ${REPOSITORY_NAME}" \
    "$IMAGE_TAG_2"

# Test 10: BatchDeleteImage - Multiple images
# Push another tag first
docker tag ${REPOSITORY_NAME}:${IMAGE_TAG} ${ECR_URI}:v2.0.0
docker push ${ECR_URI}:v2.0.0

assert_success "BatchDeleteImage - Delete multiple images" \
    "aws ecr batch-delete-image --repository-name ${REPOSITORY_NAME} --image-ids imageTag=${IMAGE_TAG} imageTag=v2.0.0"

# Verify all images deleted
assert_not_contains "Verify first image deleted" \
    "aws ecr list-images --repository-name ${REPOSITORY_NAME}" \
    "$IMAGE_TAG"

assert_not_contains "Verify second image deleted" \
    "aws ecr list-images --repository-name ${REPOSITORY_NAME}" \
    "v2.0.0"

# Test 11: DeleteRepository - Should fail without force (if has images)
log_info ""
log_info "TEST SUITE 5: Repository Deletion"

# Push an image first
docker push ${ECR_URI}:${IMAGE_TAG}

assert_failure "DeleteRepository - Delete with images should fail without force" \
    "aws ecr delete-repository --repository-name ${REPOSITORY_NAME}"

# Test 12: DeleteRepository with force
assert_success "DeleteRepository - Delete with force flag" \
    "aws ecr delete-repository --repository-name ${REPOSITORY_NAME} --force"

# Verify repository is deleted
assert_failure "Verify repository deleted" \
    "aws ecr describe-repositories --repository-names ${REPOSITORY_NAME}"

# Test 13: Recreate repository and verify no images
log_info ""
log_info "TEST SUITE 6: Verify Clean State After Deletion"

assert_success "CreateRepository - Recreate deleted repository" \
    "aws ecr create-repository --repository-name ${REPOSITORY_NAME}"

# This is the critical test - images should NOT reappear
assert_not_contains "CRITICAL: Verify no zombie images after repository recreation" \
    "aws ecr describe-images --repository-name ${REPOSITORY_NAME}" \
    "imageTags"

# Test 14: Delete empty repository
assert_success "DeleteRepository - Delete empty repository" \
    "aws ecr delete-repository --repository-name ${REPOSITORY_NAME}"

# Test 15: Delete second repository
assert_success "DeleteRepository - Delete second test repository" \
    "aws ecr delete-repository --repository-name ${REPOSITORY_NAME_2}"

# Test 16: GetAuthorizationToken
log_info ""
log_info "TEST SUITE 7: Authorization"

assert_contains "GetAuthorizationToken - Get auth token" \
    "aws ecr get-authorization-token" \
    "authorizationToken"

echo ""
log_info "All test suites completed!"
