#!/usr/bin/env bash

# CloudWatch Logs API Test Suite
# Tests all CloudWatch Logs functionality with proper error handling

set -eu

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

# Configuration
FUNCTION_NAME="${1:-logs-function}"
TEST_LOG_GROUP="/test/cloudwatch/logs"
TEST_LOG_STREAM="test-stream-$(date +%s)"

# Helper functions
print_test() {
    echo -e "\n${BLUE}[TEST $((TESTS_RUN + 1))]${NC} $1"
    TESTS_RUN=$((TESTS_RUN + 1))
}

print_success() {
    echo -e "${GREEN}✓ PASS${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

run_test() {
    local test_name="$1"
    shift
    print_test "$test_name"

    if "$@" 2>&1; then
        print_success "$test_name"
        return 0
    else
        print_fail "$test_name"
        return 1
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up test resources..."
    aws logs delete-log-group --log-group-name "$TEST_LOG_GROUP" 2>/dev/null || true
}

# trap cleanup EXIT

# =============================================================================
# TEST SUITE
# =============================================================================
cleanup

# -----------------------------------------------------------------------------
# Test 1: Create Log Group
# -----------------------------------------------------------------------------
test_create_log_group() {
    local result
    result=$(aws logs create-log-group \
        --log-group-name "$TEST_LOG_GROUP" 2>&1)

    if [ $? -eq 0 ]; then
        return 0
    else
        echo "Error: $result"
        return 1
    fi
}

cat > index.js << 'EOF'
exports.handler = async (event) => {
  console.log("Log Test Started");
  console.log("Received:", event);
  return { statusCode: 200 };
};
EOF
zip -j ./lambda_function.zip ./index.js
rm ./index.js
aws lambda delete-function --function-name "$FUNCTION_NAME" 2>/dev/null || true
aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime nodejs22.x \
    --role arn:aws:iam::000000000000:role/lambda-role \
    --logging-config LogGroup=$TEST_LOG_GROUP \
    --handler index.handler \
    --zip-file fileb://./lambda_function.zip &>/dev/null || true

# echo -e "${BLUE}==================================================================${NC}"
# echo -e "${BLUE}CloudWatch Logs API Test Suite${NC}"
# echo -e "${BLUE}==================================================================${NC}"


# -----------------------------------------------------------------------------
# Test 2: Create Log Group (Duplicate - Should Fail)
# -----------------------------------------------------------------------------
test_create_duplicate_log_group() {
    local result
    result=$(aws logs create-log-group \
        --log-group-name "$TEST_LOG_GROUP" 2>&1)

    # Should fail with ResourceAlreadyExistsException
    if echo "$result" | grep -q "ResourceAlreadyExistsException\|already exists"; then
        return 0
    else
        echo "Expected ResourceAlreadyExistsException, got: $result"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 3: Describe Log Groups
# -----------------------------------------------------------------------------
test_describe_log_groups() {
    local result
    result=$(aws logs describe-log-groups \
        --log-group-name-prefix "$TEST_LOG_GROUP" \
        --output json)

    if echo "$result" | jq -e ".logGroups[] | select(.logGroupName == \"$TEST_LOG_GROUP\")" > /dev/null; then
        return 0
    else
        echo "Log group not found in describe-log-groups output"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 4: Create Log Stream
# -----------------------------------------------------------------------------
test_create_log_stream() {
    local result
    result=$(aws logs create-log-stream \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" 2>&1)

    if [ $? -eq 0 ]; then
        return 0
    else
        echo "Error: $result"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 5: Create Log Stream (Duplicate - Should Fail)
# -----------------------------------------------------------------------------
test_create_duplicate_log_stream() {
    local result
    result=$(aws logs create-log-stream \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" 2>&1)

    if echo "$result" | grep -q "ResourceAlreadyExistsException\|already exists"; then
        return 0
    else
        echo "Expected ResourceAlreadyExistsException, got: $result"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 6: Describe Log Streams
# -----------------------------------------------------------------------------
test_describe_log_streams() {
    local result
    result=$(aws logs describe-log-streams \
        --log-group-name "$TEST_LOG_GROUP" \
        --output json)

    if echo "$result" | jq -e ".logStreams[] | select(.logStreamName == \"$TEST_LOG_STREAM\")" > /dev/null; then
        return 0
    else
        echo "Log stream not found in describe-log-streams output"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 7: Put Log Events
# -----------------------------------------------------------------------------
test_put_log_events() {
    local timestamp=$(date +%s)000
    local result

    result=$(aws logs put-log-events \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" \
        --log-events \
            "timestamp=$timestamp,message=Test message 1" \
            "timestamp=$((timestamp + 1)),message=Test message 2" \
            "timestamp=$((timestamp + 2)),message=ERROR: Test error message" \
        --output json 2>&1)

    if [ $? -eq 0 ] && echo "$result" | jq -e '.nextSequenceToken' > /dev/null; then
        return 0
    else
        echo "Error putting log events: $result"
        return 1
    fi
}

# Give logs time to be indexed
sleep 5

# -----------------------------------------------------------------------------
# Test 8: Get Log Events
# -----------------------------------------------------------------------------
test_get_log_events() {
    local result
    result=$(aws logs get-log-events \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" \
        --output json)

    local event_count
    event_count=$(echo "$result" | jq '.events | length')

    if [ "$event_count" -ge 3 ]; then
        print_info "Found $event_count log events"
        echo "$result"
        return 0
    else
        echo "Expected at least 3 events, found $event_count"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 9: Get Log Events with Time Range
# -----------------------------------------------------------------------------
test_get_log_events_time_range() {
    local start_time=$(date -d '1 hour ago' +%s)000
    local end_time=$(date +%s)000
    local result

    result=$(aws logs get-log-events \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" \
        --start-time "$start_time" \
        --end-time "$end_time" \
        --output json)

    if echo "$result" | jq -e '.events | length > 0' > /dev/null; then
        return 0
    else
        echo "No events found in time range"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 10: Filter Log Events
# -----------------------------------------------------------------------------
test_filter_log_events() {
    local result
    result=$(aws logs filter-log-events \
        --log-group-name "$TEST_LOG_GROUP" \
        --filter-pattern "ERROR" \
        --output json)

    local filtered_count
    filtered_count=$(echo "$result" | jq '.events | length')

    if [ "$filtered_count" -ge 1 ]; then
        print_info "Found $filtered_count events matching 'ERROR'"
        return 0
    else
        echo "Expected at least 1 event matching 'ERROR', found $filtered_count"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 11: Filter Log Events with Specific Stream
# -----------------------------------------------------------------------------
test_filter_log_events_specific_stream() {
    local result
    result=$(aws logs filter-log-events \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-names "$TEST_LOG_STREAM" \
        --output json)

    if echo "$result" | jq -e '.events | length > 0' > /dev/null; then
        return 0
    else
        echo "No events found for specific stream"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 12: Delete Log Stream
# -----------------------------------------------------------------------------
test_delete_log_stream() {
    local result
    result=$(aws logs delete-log-stream \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name "$TEST_LOG_STREAM" 2>&1)

    if [ $? -eq 0 ]; then
        return 0
    else
        echo "Error deleting log stream: $result"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 13: Verify Log Stream Deleted
# -----------------------------------------------------------------------------
test_verify_stream_deleted() {
    local result
    result=$(aws logs describe-log-streams \
        --log-group-name "$TEST_LOG_GROUP" \
        --log-stream-name-prefix "$TEST_LOG_STREAM" \
        --output json)

    local stream_count
    stream_count=$(echo "$result" | jq '.logStreams | length')

    if [ "$stream_count" -eq 0 ]; then
        return 0
    else
        echo "Stream still exists after deletion"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 14: Delete Log Group
# -----------------------------------------------------------------------------
test_delete_log_group() {
    local result
    result=$(aws logs delete-log-group \
        --log-group-name "$TEST_LOG_GROUP" 2>&1)

    if [ $? -eq 0 ]; then
        return 0
    else
        echo "Error deleting log group: $result"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Test 15: Verify Log Group Deleted
# -----------------------------------------------------------------------------
test_verify_group_deleted() {
    local result
    result=$(aws logs describe-log-groups \
        --log-group-name-prefix "$TEST_LOG_GROUP" \
        --output json)

    local group_count
    group_count=$(echo "$result" | jq '.logGroups | length')

    if [ "$group_count" -eq 0 ]; then
        return 0
    else
        echo "Log group still exists after deletion"
        return 1
    fi
}

run_test "Create log group: $TEST_LOG_GROUP" test_create_log_group
run_test "Create duplicate log group (should fail)" test_create_duplicate_log_group
run_test "Describe log groups: $TEST_LOG_GROUP" test_describe_log_groups
run_test "Create log stream: $TEST_LOG_STREAM" test_create_log_stream
run_test "Create duplicate log stream (should fail)" test_create_duplicate_log_stream
run_test "Describe log streams: $TEST_LOG_STREAM" test_describe_log_streams
run_test "Put log events: $TEST_LOG_GROUP/$TEST_LOG_STREAM" test_put_log_events
run_test "Get log events: $TEST_LOG_GROUP/$TEST_LOG_STREAM" test_get_log_events
run_test "Get log events with time range" test_get_log_events_time_range
run_test "Filter log events by pattern" test_filter_log_events
run_test "Filter log events for specific stream" test_filter_log_events_specific_stream
run_test "Delete log stream: $TEST_LOG_GROUP/$TEST_LOG_STREAM" test_delete_log_stream
run_test "Verify log stream deleted: $TEST_LOG_STREAM" test_verify_stream_deleted
run_test "Delete log group: $TEST_LOG_GROUP" test_delete_log_group
run_test "Verify log group deleted: $TEST_LOG_GROUP" test_verify_group_deleted

# =============================================================================
# LAMBDA FUNCTION TESTS (if function exists)
# =============================================================================

echo -e "\n${BLUE}==================================================================${NC}"
echo -e "${BLUE}Lambda Function CloudWatch Logs Tests${NC}"
echo -e "${BLUE}==================================================================${NC}"

# Check if function exists
if aws lambda get-function --function-name "$FUNCTION_NAME" &>/dev/null; then
    print_info "Testing with Lambda function: $FUNCTION_NAME"

    # -----------------------------------------------------------------------------
    # Test 16: Lambda Function Log Group Exists (stupid test, LG was deleted in  last 2 tests)
    # -----------------------------------------------------------------------------
    test_lambda_log_group() {
        local result
        result=$(aws logs describe-log-groups \
            --log-group-name-prefix "$TEST_LOG_GROUP" \
            --output json)

        if echo "$result" | jq -e ".logGroups[] | select(.logGroupName == \"$TEST_LOG_GROUP\")" > /dev/null; then
            return 0
        else
            echo "Lambda log group not found"
            return 1
        fi
    }

    # -----------------------------------------------------------------------------
    # Test 17: Invoke Lambda and Check Logs
    # -----------------------------------------------------------------------------
    test_lambda_invoke_logs() {
        local payload='{"test": "CloudWatch Logs Test"}'

        # Invoke function
        aws lambda invoke --function-name $FUNCTION_NAME \
            --cli-binary-format raw-in-base64-out \
            --payload '{"test": "CloudWatch Logs Test"}' \
            lambda-response.json

        aws lambda invoke \
            --function-name "$FUNCTION_NAME" \
            --cli-binary-format raw-in-base64-out \
            --payload "$payload" \
            lambda-response.json

        sleep 3  # Wait for logs to be written

        # Get most recent log stream
        local stream_name
        stream_name=$(aws logs describe-log-streams \
            --log-group-name "$TEST_LOG_GROUP" \
            --order-by LastEventTime \
            --descending \
            --max-items 1 \
            --output json | jq -r '.logStreams[0].logStreamName')

        if [ -z "$stream_name" ] || [ "$stream_name" = "null" ]; then
            echo "No log streams found"
            return 1
        fi

        # Get logs from stream
        local events
        events=$(aws logs get-log-events \
            --log-group-name "$TEST_LOG_GROUP" \
            --log-stream-name "$stream_name" \
            --output json | jq '.events | length')

        if [ "$events" -gt 0 ]; then
            print_info "Found $events log events in stream $stream_name"
            return 0
        else
            echo "No log events found"
            return 1
        fi
    }

    # -----------------------------------------------------------------------------
    # Test 18: Lambda Invoke with LogType=Tail
    # -----------------------------------------------------------------------------
    test_lambda_invoke_with_tail() {

        local payload='{"test": "LogType Tail Test"}'
        local response_file="/tmp/lambda-response-tail-$$.json"

        # Invoke with LogType=Tail
        local result
        result=$(aws lambda invoke \
            --function-name "$FUNCTION_NAME" \
            --cli-binary-format raw-in-base64-out \
            --payload "$payload" \
            --log-type Tail \
            --output json \
            "$response_file" 2>&1)

        # AWS CLI returns the metadata (including LogResult) to stdout
        # The function response goes to the file
        local log_result
        log_result=$(echo  "$result" | jq -r '.LogResult // empty')

        if [ -z "$log_result" ]; then
            echo "LogResult not found in response"
            echo "Full response: $result"
            rm -f "$response_file"
            return 1
        fi

        # Decode base64 logs
        local decoded
        decoded=$(echo "$log_result" | base64 --decode 2>&1)

        if [ $? -ne 0 ]; then
            echo "Failed to decode LogResult"
            echo "LogResult value: $log_result"
            rm -f "$response_file"
            return 1
        fi

        if [ -n "$decoded" ]; then
            print_info "Decoded logs preview:"
            echo "$decoded" | head -n 5
            rm -f "$response_file"
            return 0
        else
            echo "Decoded logs are empty"
            rm -f "$response_file"
            return 1
        fi
    }

    # -----------------------------------------------------------------------------
    # Test 19: Filter Lambda Logs
    # -----------------------------------------------------------------------------
    test_filter_lambda_logs() {
        local result
        result=$(aws logs filter-log-events \
            --log-group-name "$TEST_LOG_GROUP" \
            --start-time $(date -d '1 hour ago' +%s)000 \
            --output json)

        local event_count
        event_count=$(echo "$result" | jq '.events | length')

        if [ "$event_count" -gt 0 ]; then
            print_info "Found $event_count events in last hour"
            return 0
        else
            echo "No events found in last hour"
            return 1
        fi
    }

    # run_test "Lambda function log group exists: $TEST_LOG_GROUP" test_lambda_log_group
    run_test "Invoke Lambda and check logs" test_lambda_invoke_logs
    run_test "Lambda invoke with LogType=Tail" test_lambda_invoke_with_tail
    run_test "Filter Lambda function logs" test_filter_lambda_logs

else
    print_info "Lambda function '$FUNCTION_NAME' not found, skipping Lambda tests"
fi

# =============================================================================
# TEST SUMMARY
# =============================================================================

echo -e "\n${BLUE}==================================================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo -e "Total Tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
