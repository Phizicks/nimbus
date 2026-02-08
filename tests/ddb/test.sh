#!/usr/bin/env bash

set -eu -o pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

# Test configuration
TABLE_NAME="test-dynamodb-table"
GSI_NAME="test-gsi"
BACKUP_NAME="test-backup"
LAMBDA_NAME="ddb-esm-test"
QUEUE_NAME="ddb-esm-result-queue"
QUEUE_URL="http://localhost:9324/456645664566/$QUEUE_NAME"
HANDLER_FILE="../lambda/nodejs/src/events.js"
endpoint_url=$(aws configure get endpoint_url 2>/dev/null)

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

    # Clean up test resources
    uuid=$(aws lambda list-event-source-mappings --function-name $LAMBDA_NAME 2>/dev/null | \
        jq -r ".EventSourceMappings[].UUID" 2>/dev/null)
    [ "$uuid" ] && aws lambda delete-event-source-mapping --uuid $uuid 2>/dev/null || true

    aws dynamodb delete-table --table-name "${TABLE_NAME}" 2>/dev/null || true
    aws dynamodb delete-table --table-name "${TABLE_NAME}-copy" 2>/dev/null || true

    aws sqs delete-queue --queue-url $QUEUE_URL 2>/dev/null || true

    aws lambda delete-function --function-name $LAMBDA_NAME 2>/dev/null || true

    rm -f response.json item.json 2>/dev/null || true
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

# Initial cleanup
log_info "Performing initial cleanup..."
cleanup

echo ""
echo "======================================"
echo "DynamoDB Unit Tests"
echo "======================================"
echo ""

# Test: Health check
start_test "Test 1: DynamoDB service health check"
curl -s $endpoint_url/debug/dynamodb-status > response.json
check_success "DynamoDB service is healthy"
cat response.json | jq '.'
pass_test

echo ""

# Test: Create Table
start_test "Test 2: Create DynamoDB table"
aws dynamodb create-table \
    --table-name "${TABLE_NAME}" \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
        AttributeName=timestamp,AttributeType=N \
    --key-schema \
        AttributeName=id,KeyType=HASH \
        AttributeName=timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Environment,Value=test Key=Purpose,Value=unittest \
    > response.json 2>&1

check_success "Table created successfully"
echo "Table details:"
jq '.Table | {TableName, TableStatus, KeySchema, AttributeDefinitions}' < response.json
pass_test

echo ""

# Test: List Tables
start_test "Test 3: List DynamoDB tables"
aws dynamodb list-tables > response.json
check_success "List tables succeeded"

TABLE_LIST=$(jq -r '.TableNames[]' < response.json)
check_contains "${TABLE_LIST}" "${TABLE_NAME}" "Created table appears in list"
pass_test

echo ""

# Test: Describe Table
start_test "Test 4: Describe DynamoDB table"
aws dynamodb describe-table \
    --table-name "${TABLE_NAME}" \
    > response.json

check_success "Describe table succeeded"
echo "Table description:"
jq '.Table | {TableName, TableStatus, ItemCount, TableSizeBytes}' < response.json
pass_test

echo ""

# Test: Put Item
start_test "Test 5: Put item into table"
aws dynamodb put-item \
    --table-name "${TABLE_NAME}" \
    --item '{
        "id": {"S": "test-id-001"},
        "timestamp": {"N": "1234567890"},
        "name": {"S": "Test Item"},
        "value": {"N": "42"},
        "tags": {"SS": ["test", "example", "demo"]},
        "metadata": {"M": {
            "created_by": {"S": "unittest"},
            "version": {"N": "1"}
        }}
    }' \
    > response.json 2>&1

check_success "Put item succeeded"
pass_test

echo ""

# Test: Get Item
start_test "Test 6: Get item from table"
aws dynamodb get-item \
    --table-name "${TABLE_NAME}" \
    --key '{
        "id": {"S": "test-id-001"},
        "timestamp": {"N": "1234567890"}
    }' \
    > response.json

check_success "Get item succeeded"

ITEM_NAME=$(jq -r '.Item.name.S' < response.json)
check_contains "${ITEM_NAME}" "Test Item" "Item has correct data"

echo "Retrieved item:"
jq '.Item' < response.json
pass_test

echo ""

# Test: Update Item
start_test "Test 7: Update item"
aws dynamodb update-item \
    --table-name "${TABLE_NAME}" \
    --key '{
        "id": {"S": "test-id-001"},
        "timestamp": {"N": "1234567890"}
    }' \
    --update-expression "SET #v = :val, #n = :name" \
    --expression-attribute-names '{
        "#v": "value",
        "#n": "name"
    }' \
    --expression-attribute-values '{
        ":val": {"N": "100"},
        ":name": {"S": "Updated Item"}
    }' \
    --return-values ALL_NEW \
    > response.json 2>&1

check_success "Update item succeeded"

UPDATED_VALUE=$(jq -r '.Attributes.value.N' < response.json)
check_contains "${UPDATED_VALUE}" "100" "Item was updated correctly"
pass_test

echo ""

# Test: Batch Write Items
start_test "Test 8: Batch write items"
aws dynamodb batch-write-item \
    --request-items "{
        \"${TABLE_NAME}\": [
            {
                \"PutRequest\": {
                    \"Item\": {
                        \"id\": {\"S\": \"batch-001\"},
                        \"timestamp\": {\"N\": \"1000000001\"},
                        \"name\": {\"S\": \"Batch Item 1\"}
                    }
                }
            },
            {
                \"PutRequest\": {
                    \"Item\": {
                        \"id\": {\"S\": \"batch-002\"},
                        \"timestamp\": {\"N\": \"1000000002\"},
                        \"name\": {\"S\": \"Batch Item 2\"}
                    }
                }
            },
            {
                \"PutRequest\": {
                    \"Item\": {
                        \"id\": {\"S\": \"batch-003\"},
                        \"timestamp\": {\"N\": \"1000000003\"},
                        \"name\": {\"S\": \"Batch Item 3\"}
                    }
                }
            }
        ]
    }" \
    > response.json 2>&1

check_success "Batch write succeeded"
pass_test

echo ""

# Test: Batch Get Items
start_test "Test 9: Batch get items"
aws dynamodb batch-get-item \
    --request-items "{
        \"${TABLE_NAME}\": {
            \"Keys\": [
                {
                    \"id\": {\"S\": \"batch-001\"},
                    \"timestamp\": {\"N\": \"1000000001\"}
                },
                {
                    \"id\": {\"S\": \"batch-002\"},
                    \"timestamp\": {\"N\": \"1000000002\"}
                }
            ]
        }
    }" \
    > response.json

check_success "Batch get succeeded"

ITEM_COUNT=$(jq ".Responses.\"${TABLE_NAME}\" | length" < response.json)
check_equals "${ITEM_COUNT}" "2" "Retrieved correct number of items"
pass_test

echo ""

# Test: Query
start_test "Test 10: Query items"
aws dynamodb query \
    --table-name "${TABLE_NAME}" \
    --key-condition-expression "id = :id" \
    --expression-attribute-values '{
        ":id": {"S": "test-id-001"}
    }' \
    > response.json

check_success "Query succeeded"

QUERY_COUNT=$(jq '.Count' < response.json)
check_contains "${QUERY_COUNT}" "1" "Query returned expected items"
pass_test

echo ""

# Test: Scan
start_test "Test 11: Scan table"
aws dynamodb scan \
    --table-name "${TABLE_NAME}" \
    --filter-expression "begins_with(id, :prefix)" \
    --expression-attribute-values '{
        ":prefix": {"S": "batch"}
    }' \
    > response.json

check_success "Scan succeeded"

SCAN_COUNT=$(jq '.Count' < response.json)
log_info "Scan found ${SCAN_COUNT} items with prefix 'batch'"
pass_test

echo ""

# Test: Conditional Update (should succeed)
start_test "Test 12: Conditional update (positive case)"
aws dynamodb update-item \
    --table-name "${TABLE_NAME}" \
    --key '{
        "id": {"S": "test-id-001"},
        "timestamp": {"N": "1234567890"}
    }' \
    --update-expression "SET #v = :newval" \
    --condition-expression "#v = :oldval" \
    --expression-attribute-names '{
        "#v": "value"
    }' \
    --expression-attribute-values '{
        ":newval": {"N": "200"},
        ":oldval": {"N": "100"}
    }' \
    > response.json 2>&1

check_success "Conditional update succeeded"
pass_test

echo ""

# Test: Conditional Update (should fail)
start_test "Test 13: Conditional update (negative case - should fail)"
if aws dynamodb update-item \
    --table-name "${TABLE_NAME}" \
    --key '{
        "id": {"S": "test-id-001"},
        "timestamp": {"N": "1234567890"}
    }' \
    --update-expression "SET #v = :newval" \
    --condition-expression "#v = :oldval" \
    --expression-attribute-names '{
        "#v": "value"
    }' \
    --expression-attribute-values '{
        ":newval": {"N": "300"},
        ":oldval": {"N": "999"}
    }' \
    > response.json 2>&1; then
    log_error "✗ Conditional update should have failed"
    fail_test
else
    log_info "✓ Conditional update correctly failed"
    pass_test
fi

echo ""

# Test: Delete Item
start_test "Test 14: Delete item"
aws dynamodb delete-item \
    --table-name "${TABLE_NAME}" \
    --key '{
        "id": {"S": "batch-003"},
        "timestamp": {"N": "1000000003"}
    }' \
    --return-values ALL_OLD \
    > response.json

check_success "Delete item succeeded"

DELETED_ITEM=$(jq -r '.Attributes.name.S' < response.json)
check_contains "${DELETED_ITEM}" "Batch Item 3" "Correct item was deleted"
pass_test

echo ""

# Test: Batch Delete Items
start_test "Test 15: Batch delete items"
aws dynamodb batch-write-item \
    --request-items "{
        \"${TABLE_NAME}\": [
            {
                \"DeleteRequest\": {
                    \"Key\": {
                        \"id\": {\"S\": \"batch-001\"},
                        \"timestamp\": {\"N\": \"1000000001\"}
                    }
                }
            },
            {
                \"DeleteRequest\": {
                    \"Key\": {
                        \"id\": {\"S\": \"batch-002\"},
                        \"timestamp\": {\"N\": \"1000000002\"}
                    }
                }
            }
        ]
    }" \
    > response.json 2>&1

check_success "Batch delete succeeded"
pass_test

echo ""

# Test: List Tags
start_test "Test 16: List table tags"
TABLE_ARN=$(aws dynamodb describe-table --table-name "${TABLE_NAME}" | jq -r '.Table.TableArn')
aws dynamodb list-tags-of-resource \
    --resource-arn "${TABLE_ARN}" \
    > response.json

check_success "List tags succeeded"

TAG_COUNT=$(jq '.Tags | length' < response.json)
log_info "Found ${TAG_COUNT} tags on table"
pass_test

echo ""

# Test: Update Table (add tags)
start_test "Test 17: Tag resource"
aws dynamodb tag-resource \
    --resource-arn "${TABLE_ARN}" \
    --tags Key=NewTag,Value=NewValue \
    > response.json 2>&1

check_success "Tag resource succeeded"
pass_test

echo ""

# Test: Delete Table
start_test "Test 18: Delete DynamoDB table"
aws dynamodb delete-table \
    --table-name "${TABLE_NAME}" \
    > response.json

check_success "Delete table succeeded"

echo "Deleted table:"
jq '.TableDescription | {TableName, TableStatus}' < response.json
pass_test

echo ""

# Test: Verify table deleted
start_test "Test 19: Verify table is deleted"
sleep 2  # Give it a moment to delete
aws dynamodb list-tables > response.json

TABLE_LIST=$(jq -r '.TableNames[]' < response.json)
if echo "${TABLE_LIST}" | grep -q "${TABLE_NAME}"; then
    log_error "✗ Table still appears in list after deletion"
    fail_test
else
    log_info "✓ Table successfully removed from list"
    pass_test
fi

echo ""

# Test: DDB Streaming test
start_test "Test 20: DDB Streaming test"

QUEUE_URL=$(aws sqs create-queue \
  --queue-name "$QUEUE_NAME" \
  --query 'QueueUrl' --output text)

zip -j /tmp/lambda.zip "$HANDLER_FILE" >/dev/null

# Creating Streaming lambda function tester
log_info "Creating test function $LAMBDA_NAME"
aws lambda create-function \
    --function-name "$LAMBDA_NAME" \
    --runtime nodejs22.x \
    --handler events.handler \
    --zip-file fileb:///tmp/lambda.zip \
    --role arn:aws:iam::456645664566:role/lambda-ex \
    --environment Variables="{RESULT_QUEUE_URL=$QUEUE_URL}" >/dev/null

log_info "Creating DDB table $TABLE_NAME"
aws dynamodb create-table \
    --table-name "${TABLE_NAME}" \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
        AttributeName=timestamp,AttributeType=N \
    --key-schema \
        AttributeName=id,KeyType=HASH \
        AttributeName=timestamp,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Environment,Value=test Key=Purpose,Value=unittest \
    --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES \
    > response.json 2>&1

STREAM_ARN=$(aws dynamodb describe-table \
  --table-name "$TABLE_NAME" \
  --query 'Table.LatestStreamArn' \
  --output text)

log_info "Creating ESM mapping for Lambda function ${LAMBDA_NAME}"
aws lambda create-event-source-mapping \
  --function-name "$LAMBDA_NAME" \
  --event-source-arn "$STREAM_ARN" \
  --starting-position LATEST \
  --batch-size 1 >/dev/null || echo "(Mapping may already exist.)"

log_info "Triggering DynamoDB change"
aws dynamodb put-item \
    --table-name $TABLE_NAME \
    --item "{
        \"id\": {\"S\": \"stream-test-1\"},
        \"timestamp\": {\"N\": \"$(date +%s)\"},
        \"data\": {\"S\": \"event-test\"}
    }"
aws dynamodb put-item \
    --table-name $TABLE_NAME \
    --item "{
        \"id\": {\"S\": \"stream-test-2\"},
        \"timestamp\": {\"N\": \"$(date +%s)\"},
        \"data\": {\"S\": \"event-test-2\"}
    }"

log_info "Waiting for SQS to receive message..."
for i in {1..12}; do
  MSGS=$(aws sqs receive-message --queue-url "$QUEUE_URL" \
    --max-number-of-messages 1 --wait-time-seconds 1 \
    --query 'Messages[0].Body' --output text || true)
  if [[ "$MSGS" != "None" && -n "$MSGS" ]]; then
    log_info "✓ Received message from Lambda:"
    echo "$MSGS" | jq .
    pass_test
    break
  fi
  sleep 5
done

if [[ "$MSGS" == "None" || -z "$MSGS" ]]; then
  log_error "✗ No message received after 60s"
  fail_test
fi

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
