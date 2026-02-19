#!/usr/bin/env bash

set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

# Test configuration
SECRET_NAME="test-secret"
SECRET_VALUE="my-test-password-123"
UPDATED_VALUE="my-updated-password-456"
JSON_SECRET_VALUE='{"username":"admin","password":"secret123"}'
BINARY_SECRET_VALUE="binary-data-content"
LAMBDA_ARN=""

ENDPOINT_URL=$(aws configure get endpoint_url)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
CURRENT_TEST_NAME=""
CURRENT_TEST_HAS_CHECKS=false

cleanup() {
    local exit_code=$?

    echo ""
    log_info "Cleaning up... [ECODE: $exit_code]"

    # Clean up Lambda function and role
    aws lambda delete-function --function-name test-rotation-lambda >/dev/null 2>&1 || true

    # Clean up test resources using AWS CLI
    aws secretsmanager delete-secret --secret-id "${SECRET_NAME}" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "${SECRET_NAME}-json" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "${SECRET_NAME}-binary" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "${SECRET_NAME}-rotation" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "${SECRET_NAME}-policy" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "duplicate-test" --force-delete >/dev/null 2>&1 || true
    aws secretsmanager delete-secret --secret-id "my-test-password-123" --force-delete >/dev/null 2>&1 || true
    rm -f response.json lambda-function.zip 2>/dev/null || true
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

# Start a new test
start_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
    CURRENT_TEST_NAME="$1"
    CURRENT_TEST_HAS_CHECKS=false
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Mark current test as passed
pass_test() {
    if [ -z "$CURRENT_TEST_NAME" ]; then
        log_warn "pass_test called without active test"
        return
    fi
    TESTS_PASSED=$((TESTS_PASSED + 1))
    CURRENT_TEST_NAME=""
    CURRENT_TEST_HAS_CHECKS=false
}

# Mark current test as failed
fail_test() {
    if [ -z "$CURRENT_TEST_NAME" ]; then
        log_warn "fail_test called without active test"
        return
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
    CURRENT_TEST_NAME=""
    CURRENT_TEST_HAS_CHECKS=false
}

# Check command success and track for test
check_success() {
    local description="$1"
    CURRENT_TEST_HAS_CHECKS=true

    if [ $? -eq 0 ]; then
        log_info "✓ ${description}"
        return 0
    else
        log_error "✗ ${description}"
        fail_test
        return 1
    fi
}

# Check if haystack contains needle
check_contains() {
    local haystack="$1"
    local needle="$2"
    local description="$3"
    CURRENT_TEST_HAS_CHECKS=true

    if echo "${haystack}" | grep -q "${needle}"; then
        log_info "✓ ${description}"
        return 0
    else
        log_error "✗ ${description}"
        log_error "  Expected to find: ${needle}"
        log_error "  In: ${haystack}"
        fail_test
        return 1
    fi
}

# Check equality
check_equals() {
    local actual="$1"
    local expected="$2"
    local description="$3"
    CURRENT_TEST_HAS_CHECKS=true

    if [ "$actual" = "$expected" ]; then
        log_info "✓ ${description}"
        return 0
    else
        log_error "✗ ${description}"
        log_error "  Expected: ${expected}"
        log_error "  Got: ${actual}"
        fail_test
        return 1
    fi
}

# Ensure clean state by trying to delete any existing test secrets
log_info "Ensuring clean state..."
cleanup
# for secret_suffix in "" "-json" "-binary" "-rotation" "-policy"; do
#     aws secretsmanager delete-secret --secret-id "${SECRET_NAME}${secret_suffix}" --force-delete >/dev/null 2>&1 || true
# done
# aws secretsmanager delete-secret --secret-id "duplicate-test" --force-delete >/dev/null 2>&1 || true

echo ""
echo "======================================"
echo "Secrets Manager Unit Tests"
echo "======================================"
echo ""

# Test: Health check
start_test "Test 1: Secrets Manager service health check"
curl -s "$ENDPOINT_URL/health" > response.json
check_success "Secrets Manager service is healthy"
cat response.json | jq '.'
pass_test

echo ""

# Test: Create Secret (String)
start_test "Test 2: Create secret with string value"
aws secretsmanager create-secret \
    --name "${SECRET_NAME}" \
    --secret-string "${SECRET_VALUE}" \
    --description "Test secret for unit testing" \
    --tags Key=Environment,Value=test Key=Purpose,Value=unittest \
    > response.json 2>&1

check_success "Secret created successfully"
echo "Secret details:"
jq '.' < response.json
pass_test

echo ""

# Test: Get Secret Value
start_test "Test 3: Get secret value"
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Get secret value succeeded"

RETRIEVED_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${RETRIEVED_VALUE}" "${SECRET_VALUE}" "Retrieved correct secret value"

echo "Retrieved secret:"
jq '. | {ARN, Name, VersionId, SecretString}' < response.json
pass_test

echo ""

# Test: Describe Secret
start_test "Test 4: Describe secret"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe secret succeeded"

SECRET_ARN=$(jq -r '.ARN' < response.json)
check_contains "${SECRET_ARN}" "${SECRET_NAME}" "ARN contains secret name"

DESCRIPTION=$(jq -r '.Description' < response.json)
check_equals "${DESCRIPTION}" "Test secret for unit testing" "Description matches"

echo "Secret metadata:"
jq '. | {ARN, Name, CreatedDate, LastChangedDate, Description, Tags}' < response.json
pass_test

echo ""

# Test: List Secrets
start_test "Test 5: List secrets"
aws secretsmanager list-secrets \
    > response.json

check_success "List secrets succeeded"

SECRET_COUNT=$(jq '.SecretList | length' < response.json)
log_info "Found ${SECRET_COUNT} secrets"

SECRET_NAMES=$(jq -r '.SecretList[].Name' < response.json)
check_contains "${SECRET_NAMES}" "${SECRET_NAME}" "Created secret appears in list"
pass_test

echo ""

# Test: Update Secret
start_test "Test 6: Update secret value"
aws secretsmanager update-secret \
    --secret-id "${SECRET_NAME}" \
    --secret-string "${UPDATED_VALUE}" \
    --description "Updated test secret" \
    > response.json 2>&1

check_success "Update secret succeeded"

NEW_VERSION=$(jq -r '.VersionId' < response.json)
echo "New version created: ${NEW_VERSION}"
pass_test

echo ""

# Test: Get Updated Secret Value
start_test "Test 7: Get updated secret value"
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Get updated secret value succeeded"

UPDATED_RETRIEVED_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${UPDATED_RETRIEVED_VALUE}" "${UPDATED_VALUE}" "Retrieved updated secret value"
pass_test

echo ""

# Test: List Secret Version IDs
start_test "Test 8: List secret version IDs"
aws secretsmanager list-secret-version-ids \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "List secret version IDs succeeded"

VERSION_COUNT=$(jq '.Versions | length' < response.json)
log_info "Found ${VERSION_COUNT} versions"

# Should have AWSCURRENT and AWSPREVIOUS
VERSIONS=$(jq -r '.Versions[].VersionStages[]' < response.json)
check_contains "${VERSIONS}" "AWSCURRENT" "Has AWSCURRENT version"
check_contains "${VERSIONS}" "AWSPREVIOUS" "Has AWSPREVIOUS version"
pass_test

echo ""

# Test: Get Previous Version
start_test "Test 9: Get previous version value"
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    --version-stage AWSPREVIOUS \
    > response.json

check_success "Get previous version succeeded"

PREVIOUS_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${PREVIOUS_VALUE}" "${SECRET_VALUE}" "Previous version has original value"
pass_test

echo ""

# Test: Create Secret with JSON
start_test "Test 10: Create secret with JSON value"
aws secretsmanager create-secret \
    --name "${SECRET_NAME}-json" \
    --secret-string "${JSON_SECRET_VALUE}" \
    > response.json 2>&1

check_success "JSON secret created successfully"

# Get and verify JSON parsing
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}-json" \
    > response.json

JSON_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${JSON_VALUE}" "${JSON_SECRET_VALUE}" "JSON secret value preserved"

# Parse JSON to verify structure
USERNAME=$(echo "${JSON_VALUE}" | jq -r '.username')
PASSWORD=$(echo "${JSON_VALUE}" | jq -r '.password')
check_equals "${USERNAME}" "admin" "JSON username parsed correctly"
check_equals "${PASSWORD}" "secret123" "JSON password parsed correctly"
pass_test

echo ""

# Test: Put Secret Value (New Version)
start_test "Test 11: Put secret value (create new version)"
aws secretsmanager put-secret-value \
    --secret-id "${SECRET_NAME}" \
    --secret-string "third-version-value" \
    --version-stages TESTING \
    > response.json 2>&1

check_success "Put secret value succeeded"

NEW_VERSION_ID=$(jq -r '.VersionId' < response.json)
log_info "Created version: ${NEW_VERSION_ID} with stage TESTING"
pass_test

echo ""

# Test: Get Specific Version
start_test "Test 12: Get specific version by ID"
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    --version-id "${NEW_VERSION_ID}" \
    > response.json

check_success "Get specific version succeeded"

SPECIFIC_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${SPECIFIC_VALUE}" "third-version-value" "Retrieved correct version value"
pass_test

echo ""

# Test: Update Secret Version Stage
start_test "Test 13: Update secret version stage"
aws secretsmanager update-secret-version-stage \
    --secret-id "${SECRET_NAME}" \
    --version-stage AWSCURRENT \
    --move-to-version-id "${NEW_VERSION_ID}" \
    > response.json 2>&1

check_success "Update version stage succeeded"

# Verify AWSCURRENT moved
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    > response.json

CURRENT_VALUE=$(jq -r '.SecretString' < response.json)
check_equals "${CURRENT_VALUE}" "third-version-value" "AWSCURRENT now points to new version"
pass_test

echo ""

# Create ZIP file with Lambda function code
log_info "Creating Lambda function ZIP package..."
cd "$(dirname "${BASH_SOURCE[0]}")/src"
zip -q ../lambda-function.zip index.py
cd ..
log_info "Created lambda-function.zip"

# Create Lambda function
log_info "Creating Lambda function..."
aws lambda create-function \
    --function-name test-rotation-lambda \
    --runtime python3.11 \
    --role "arn:aws:iam::456645664566:role/rotate-role" \
    --handler index.lambda_handler \
    --zip-file fileb://lambda-function.zip \
    > response.json 2>&1

LAMBDA_ARN=$(jq -r '.FunctionArn' < response.json)
log_info "Created Lambda function: ${LAMBDA_ARN}"

echo ""

# Test: Enable Rotation
start_test "Test 14: Enable secret rotation"
# aws secretsmanager update-secret \
#   --secret-id "${SECRET_NAME}" \
#     --rotation-lambda-arn "${LAMBDA_ARN}" \
#     --rotation-rules AutomaticallyAfterDays=30 \
#     > response.json 2>&1
aws secretsmanager rotate-secret \
    --secret-id "${SECRET_NAME}" \
    --rotation-lambda-arn "${LAMBDA_ARN}" \
    --rotation-rules AutomaticallyAfterDays=30 \
    > response.json 2>&1

check_success "Enable rotation succeeded"
pass_test

echo ""

# Test: Describe Secret (Check Rotation)
start_test "Test 15: Describe secret with rotation enabled"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe secret with rotation succeeded"

ROTATION_ENABLED=$(jq -r '.RotationEnabled' < response.json)
check_equals "${ROTATION_ENABLED}" "true" "Rotation is enabled"

ROTATION_LAMBDA=$(jq -r '.RotationLambdaARN' < response.json)
check_equals "${ROTATION_LAMBDA}" "${LAMBDA_ARN}" "Rotation Lambda ARN is correct"

echo "Rotation details:"
jq '. | {RotationEnabled, RotationLambdaARN, RotationRules, RotationStatus}' < response.json
pass_test

echo ""

# Test: Get Rotation Policy (Note: AWS CLI may not have this command, using describe-secret instead)
start_test "Test 16: Get rotation policy"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Get rotation info succeeded"

POLICY_LAMBDA=$(jq -r '.RotationLambdaARN' < response.json)
check_equals "${POLICY_LAMBDA}" "${LAMBDA_ARN}" "Rotation policy contains Lambda ARN"

echo "Rotation policy:"
jq '. | {RotationEnabled, RotationLambdaARN, RotationRules, RotationStatus}' < response.json
pass_test

echo ""

# Test: Rotate Secret
start_test "Test 17: Rotate secret"
aws secretsmanager rotate-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json 2>&1

check_success "Rotate secret succeeded"

# Get rotated value (should be modified)
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    > response.json

ROTATED_VALUE=$(jq -r '.SecretString' < response.json)
check_contains "${ROTATED_VALUE}" "third-version-value_rotated_" "Value was rotated (contains rotation suffix)"
pass_test

echo ""

# Test: Describe Secret (Check Last Rotated)
start_test "Test 18: Describe secret after rotation"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe secret after rotation succeeded"

LAST_ROTATED=$(jq -r '.LastRotatedDate' < response.json)
if [ "${LAST_ROTATED}" != "null" ] && [ -n "${LAST_ROTATED}" ]; then
    log_info "✓ Last rotated date is set: ${LAST_ROTATED}"
else
    log_error "✗ Last rotated date not set"
    fail_test
fi
pass_test

echo ""

# Test: Cancel Rotation
start_test "Test 19: Cancel secret rotation"
aws secretsmanager cancel-rotate-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json 2>&1

check_success "Cancel rotation succeeded"
pass_test

echo ""

# Test: Verify Rotation Disabled
start_test "Test 20: Verify rotation is disabled"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe secret after canceling rotation succeeded"

ROTATION_ENABLED_AFTER=$(jq -r '.RotationEnabled' < response.json)
if [ "${ROTATION_ENABLED_AFTER}" = "null" ] || [ "${ROTATION_ENABLED_AFTER}" = "false" ]; then
    log_info "✓ Rotation is disabled"
else
    log_error "✗ Rotation is still enabled"
    fail_test
fi
pass_test

echo ""

# Test: Put Resource Policy
start_test "Test 21: Put resource policy"
POLICY_DOCUMENT='{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::123456789012:role/test-role"
        },
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "*"
    }]
}'

aws secretsmanager put-resource-policy \
    --secret-id "${SECRET_NAME}" \
    --resource-policy "${POLICY_DOCUMENT}" \
    > response.json 2>&1

check_success "Put resource policy succeeded"
pass_test

echo ""

# Test: Get Resource Policy
start_test "Test 22: Get resource policy"
aws secretsmanager get-resource-policy \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Get resource policy succeeded"

POLICY_CONTENT=$(jq -r '.ResourcePolicy' < response.json)
check_contains "${POLICY_CONTENT}" "secretsmanager:GetSecretValue" "Policy contains expected permission"
pass_test

echo ""

# Test: Delete Resource Policy
start_test "Test 23: Delete resource policy"
aws secretsmanager delete-resource-policy \
    --secret-id "${SECRET_NAME}" \
    > response.json 2>&1

check_success "Delete resource policy succeeded"
pass_test

echo ""

# Test: Schedule Secret Deletion
start_test "Test 24: Schedule secret deletion"
aws secretsmanager delete-secret \
    --secret-id "${SECRET_NAME}" \
    --recovery-window-in-days 7 \
    > response.json 2>&1

check_success "Schedule deletion succeeded"

DELETION_DATE=$(jq -r '.DeletionDate' < response.json)
if [ "${DELETION_DATE}" != "null" ] && [ -n "${DELETION_DATE}" ]; then
    log_info "✓ Deletion scheduled for: ${DELETION_DATE}"
else
    log_error "✗ Deletion date not set"
    fail_test
fi
pass_test

echo ""

# Test: Describe Deleted Secret
start_test "Test 25: Describe deleted secret"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe deleted secret succeeded"

DELETED_DATE=$(jq -r '.DeletedDate' < response.json)
if [ "${DELETED_DATE}" != "null" ] && [ -n "${DELETED_DATE}" ]; then
    log_info "✓ Secret shows as deleted: ${DELETED_DATE}"
else
    log_error "✗ Secret does not show as deleted"
    fail_test
fi
pass_test

echo ""

# Test: List Secrets (Include Deleted)
start_test "Test 26: List secrets including deleted"
aws secretsmanager list-secrets \
    > response.json

check_success "List secrets with deleted succeeded"

# Should still see our deleted secret
SECRET_NAMES=$(jq -r '.SecretList[].Name' < response.json)
check_contains "${SECRET_NAMES}" "${SECRET_NAME}" "Deleted secret appears in list"
pass_test

echo ""

# Test: Restore Secret
start_test "Test 27: Restore deleted secret"
aws secretsmanager restore-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json 2>&1

check_success "Restore secret succeeded"
pass_test

echo ""

# Test: Verify Secret Restored
start_test "Test 28: Verify secret is restored"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Describe restored secret succeeded"

DELETED_DATE_AFTER=$(jq -r '.DeletedDate' < response.json)
if [ "${DELETED_DATE_AFTER}" = "null" ] || [ -z "${DELETED_DATE_AFTER}" ]; then
    log_info "✓ Secret is restored (no deletion date)"
else
    log_error "✗ Secret still shows as deleted"
    fail_test
fi

# Verify we can still get the value
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    > response.json

check_success "Can retrieve value from restored secret"
pass_test

echo ""

# Test: Force Delete Secret
start_test "Test 29: Force delete secret"
aws secretsmanager delete-secret \
    --secret-id "${SECRET_NAME}" \
    --force-delete \
    > response.json 2>&1

check_success "Force delete succeeded"
pass_test

echo ""

# Test: Verify Secret Permanently Deleted
start_test "Test 30: Verify secret is permanently deleted"
sleep 2  # Give it a moment
if aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}" \
    > response.json 2>&1; then
    log_error "✗ Secret still exists after force delete"
    fail_test
else
    log_info "✓ Secret permanently deleted"
    pass_test
fi

echo ""

# Test: Binary Secret
start_test "Test 31: Create and retrieve binary secret"
echo -n "${BINARY_SECRET_VALUE}" | base64 > binary_data.b64
BINARY_B64=$(cat binary_data.b64)

aws secretsmanager create-secret \
    --name "${SECRET_NAME}-binary" \
    --secret-binary "${BINARY_B64}" \
    > response.json 2>&1

check_success "Binary secret created successfully"

# Get binary secret
aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}-binary" \
    > response.json

check_success "Get binary secret succeeded"

RETRIEVED_BINARY=$(jq -r '.SecretBinary' < response.json)
if [ -n "${RETRIEVED_BINARY}" ]; then
    log_info "✓ Binary secret retrieved"
    # Decode and verify
    echo "${RETRIEVED_BINARY}" | base64 -d > decoded_binary.txt
    DECODED_CONTENT=$(cat decoded_binary.txt)
    check_equals "${DECODED_CONTENT}" "${BINARY_SECRET_VALUE}" "Binary content matches"
else
    log_error "✗ No binary data retrieved"
    fail_test
fi
pass_test

echo ""

# Test: Tag Resource
start_test "Test 32: Tag secret"
aws secretsmanager tag-resource \
    --secret-id "${SECRET_NAME}-binary" \
    --tags Key=NewTag,Value=NewValue \
    > response.json 2>&1

check_success "Tag resource succeeded"
pass_test

echo ""

# Test: Untag Resource
start_test "Test 33: Untag secret"
aws secretsmanager untag-resource \
    --secret-id "${SECRET_NAME}-binary" \
    --tag-keys NewTag \
    > response.json 2>&1

check_success "Untag resource succeeded"
pass_test

echo ""

# Test: List Tags
start_test "Test 34: List tags for secret"
aws secretsmanager describe-secret \
    --secret-id "${SECRET_NAME}-binary" \
    > response.json

check_success "Describe secret for tags succeeded"

TAG_COUNT=$(jq '.Tags | length' < response.json)
log_info "Secret has ${TAG_COUNT} tags"
pass_test

echo ""

# Clean up binary test
aws secretsmanager delete-secret --secret-id "${SECRET_NAME}-binary" --force-delete >/dev/null 2>&1 || true
rm -f binary_data.b64 decoded_binary.txt 2>/dev/null || true

# Test: Error Cases
start_test "Test 35: Error handling - get non-existent secret"
if aws secretsmanager get-secret-value \
    --secret-id "non-existent-secret" \
    > response.json 2>&1; then
    log_error "✗ Should have failed for non-existent secret"
    fail_test
else
    log_info "✓ Correctly failed for non-existent secret"
    pass_test
fi

echo ""

# Test: Error Cases - Create duplicate secret
start_test "Test 36: Error handling - create duplicate secret"
aws secretsmanager create-secret \
    --name "duplicate-test" \
    --secret-string "value1" \
    > response.json 2>&1

if aws secretsmanager create-secret \
    --name "duplicate-test" \
    --secret-string "value2" \
    > response.json 2>&1; then
    log_error "✗ Should have failed for duplicate secret"
    fail_test
else
    log_info "✓ Correctly failed for duplicate secret"
    pass_test
fi

# Clean up
aws secretsmanager delete-secret --secret-id "duplicate-test" --force-delete >/dev/null 2>&1 || true

echo ""

# Print test summary
echo ""
echo "======================================"
echo "Test Summary"
echo "======================================"
echo -e "Tests Run:    ${BLUE}${TESTS_RUN}${NC}"
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo "======================================"

if [ ${TESTS_FAILED} -gt 0 ]; then
    exit 1
fi
