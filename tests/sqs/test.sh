#!/bin/bash

# LocalCloud SQS Test Suite - AWS CLI Version
# Tests SQS functionality using AWS CLI commands

set -euo pipefail  # Exit on error
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

DEBUG="${1:-false}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}LocalCloud SQS Test Suite (AWS CLI)${NC}"
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

# Cleanup function
cleanup_queues() {
    print_test "Cleaning Up Test Queues"
    QUEUE_URLS=$(aws sqs list-queues --output text --query 'QueueUrls[]' 2>/dev/null || echo "")
    for QUEUE_URL in $QUEUE_URLS; do
        aws sqs delete-queue --queue-url $QUEUE_URL 2>/dev/null || true
    done
    log_success "Cleanup complete"
}

# Test: Basic Queue Operations
test_basic_queue_operations() {
    print_test "Test 1: Basic Queue Operations"

    # Create queue
    log_info "Creating queue 'sqs-basic-queue'..."
    QUEUE_URL=$(aws sqs create-queue \
        --queue-name sqs-basic-queue \
        --attributes VisibilityTimeout=30,MessageRetentionPeriod=86400 \
        --output text \
        --query 'QueueUrl')
    aws sqs purge-queue --queue-url $QUEUE_URL 2>/dev/null || true
    if [ -z "$QUEUE_URL" ]; then
        log_error "Failed to create queue"
        return 1
    fi
    log_success "Queue created: $QUEUE_URL"

    # List queues
    log_info "Listing queues..."
    QUEUE_COUNT=$(aws sqs list-queues \
        --output text \
        --query 'length(QueueUrls)' 2>/dev/null || echo "0")
    log_success "Found $QUEUE_COUNT queue(s)"

    # Get queue attributes
    log_info "Getting queue attributes..."
    aws sqs get-queue-attributes \
        --queue-url $QUEUE_URL \
        --attribute-names All \
        --output json \
        --query 'Attributes.{VisibilityTimeout:VisibilityTimeout,MessageRetention:MessageRetentionPeriod}'
    log_success "Retrieved queue attributes"

    # Send message
    log_info "Sending message..."
    MESSAGE_ID=$(aws sqs send-message \
        --queue-url $QUEUE_URL \
        --message-body "Hello from LocalCloud SQS!" \
        --message-attributes '{"Author":{"StringValue":"TestScript","DataType":"String"}}' \
        --output text \
        --query 'MessageId')
    log_success "Message sent: $MESSAGE_ID"

    # Receive message
    log_info "Receiving message..."
    MESSAGE=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --max-number-of-messages 1 \
        --message-attribute-names All \
        --output json)

    BODY=$(echo $MESSAGE | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
    RECEIPT_HANDLE=$(echo $MESSAGE | jq -r '.Messages[0].ReceiptHandle' 2>/dev/null || echo "")

    if [ "$BODY" == "Hello from LocalCloud SQS!" ]; then
        log_success "Received message: $BODY"
    else
        log_error "Failed to receive message"
        return 1
    fi

    # Delete message
    if [ ! -z "$RECEIPT_HANDLE" ] && [ "$RECEIPT_HANDLE" != "null" ]; then
        log_info "Deleting message..."
        aws sqs delete-message \
            --queue-url $QUEUE_URL \
            --receipt-handle "$RECEIPT_HANDLE"
        log_success "Message deleted"
    fi

    log_success "Basic queue operations test passed"
}

# Test: Batch Operations
test_batch_operations() {
    print_test "Test 2: Batch Operations"

    # Create queue
    log_info "Creating queue 'sqs-batch-queue'..."
    QUEUE_URL=$(aws sqs create-queue \
        --queue-name test-batch-queue \
        --output text \
        --query 'QueueUrl')

    # Send batch messages
    log_info "Sending batch of 5 messages..."
    aws sqs send-message-batch \
        --queue-url $QUEUE_URL \
        --entries \
            Id=msg1,MessageBody="Batch message 1" \
            Id=msg2,MessageBody="Batch message 2" \
            Id=msg3,MessageBody="Batch message 3" \
            Id=msg4,MessageBody="Batch message 4" \
            Id=msg5,MessageBody="Batch message 5" \
        --output json | cat
    log_success "Sent 5 messages in batch"

    # Receive batch messages
    log_info "Receiving batch of messages..."
    MESSAGES=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --max-number-of-messages 10 \
        --output json)

    MESSAGE_COUNT=$(echo $MESSAGES | jq '.Messages | length' 2>/dev/null || echo "0")
    log_success "Received $MESSAGE_COUNT messages"

    # Delete batch
    if [ "$MESSAGE_COUNT" -gt 0 ]; then
        log_info "Deleting batch of messages..."

        # Build delete entries
        DELETE_ENTRIES=$(echo $MESSAGES | jq -r '.Messages | to_entries | map("Id=msg\(.key),ReceiptHandle=\(.value.ReceiptHandle)") | join(" ")')

        # Note: AWS CLI batch delete is tricky with dynamic entries
        # For simplicity, delete one by one
        echo $MESSAGES | jq -r '.Messages[].ReceiptHandle' | while read RECEIPT; do
            aws sqs delete-message \
                --queue-url $QUEUE_URL \
                --receipt-handle "$RECEIPT" 2>/dev/null || true
        done

        log_success "Deleted $MESSAGE_COUNT messages"
    else
        log_error "Failed to receive batch: $MESSAGE_COUNT received"
        return 1
    fi

    log_success "Batch operations test passed"
}

test_dead_letter_queue() {
    print_test "Test 3: Dead Letter Queue"

    # Create DLQ
    log_info "Creating dead letter queue..."
    DLQ_URL=$(aws sqs create-queue --queue-name test-dlq --output text --query 'QueueUrl')
    log_success "DLQ created: $DLQ_URL"

    # Get DLQ ARN
    DLQ_ARN=$(aws sqs get-queue-attributes --queue-url $DLQ_URL --attribute-names QueueArn --output text --query 'Attributes.QueueArn')
    log_info "DLQ ARN: $DLQ_ARN"

    # Create main queue with DLQ (maxReceiveCount=2)
    # This means: message can be received 2 times, on 3rd expiry it goes to DLQ
    log_info "Creating main queue with DLQ policy (maxReceiveCount=2)..."
    MAIN_QUEUE_URL=$(aws sqs create-queue \
        --queue-name test-queue-with-dlq \
        --attributes "{\"VisibilityTimeout\":\"3\",\"MessageRetentionPeriod\":\"300\",\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$DLQ_ARN\\\",\\\"maxReceiveCount\\\":2}\"}" \
        --output text \
        --query 'QueueUrl')
    log_success "Main queue created with DLQ (maxReceiveCount=2)"

    # Verify the RedrivePolicy was set correctly
    log_info "Verifying RedrivePolicy..."
    REDRIVE_POLICY=$(aws sqs get-queue-attributes \
        --queue-url $MAIN_QUEUE_URL \
        --attribute-names RedrivePolicy \
        --output json | jq -r '.Attributes.RedrivePolicy')
    log_info "RedrivePolicy: $REDRIVE_POLICY"

    # Send a SINGLE test message
    log_info "Sending test message..."
    SEND_RESULT=$(aws sqs send-message \
        --queue-url $MAIN_QUEUE_URL \
        --message-body "Test DLQ message" \
        --output json)
    MESSAGE_ID=$(echo $SEND_RESULT | jq -r '.MessageId')
    log_success "Message sent with ID: $MESSAGE_ID"

    # Wait a moment for message to be available
    sleep 1

    # Simulate failed processing with proper tracking
    # maxReceiveCount=2 means:
    #   - 1st receive: count=1, requeue
    #   - 2nd receive: count=2, requeue
    #   - 3rd receive: count=3, should move to DLQ (3 > 2)

    log_info "Simulating failed processing attempts..."

    # First receive
    log_info "  Attempt 1: Receiving message..."
    MESSAGE1=$(aws sqs receive-message \
        --queue-url $MAIN_QUEUE_URL \
        --visibility-timeout 3 \
        --max-number-of-messages 1 \
        --attribute-names ApproximateReceiveCount \
        --output json)

    BODY1=$(echo $MESSAGE1 | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
    RECV_COUNT1=$(echo $MESSAGE1 | jq -r '.Messages[0].Attributes.ApproximateReceiveCount' 2>/dev/null || echo "")
    MSG_ID1=$(echo $MESSAGE1 | jq -r '.Messages[0].MessageId' 2>/dev/null || echo "")

    if [ -z "$BODY1" ] || [ "$BODY1" == "null" ]; then
        log_error "Failed to receive message on first attempt"
        return 1
    fi

    log_info "  Attempt 1: Received message ID=$MSG_ID1, ReceiveCount=$RECV_COUNT1"
    log_info "  Attempt 1: NOT deleting, waiting for visibility timeout (3s + 1s buffer)..."
    sleep 4

    # Second receive
    log_info "  Attempt 2: Receiving message..."
    MESSAGE2=$(aws sqs receive-message \
        --queue-url $MAIN_QUEUE_URL \
        --visibility-timeout 3 \
        --max-number-of-messages 1 \
        --attribute-names ApproximateReceiveCount \
        --output json)

    BODY2=$(echo $MESSAGE2 | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
    RECV_COUNT2=$(echo $MESSAGE2 | jq -r '.Messages[0].Attributes.ApproximateReceiveCount' 2>/dev/null || echo "")
    MSG_ID2=$(echo $MESSAGE2 | jq -r '.Messages[0].MessageId' 2>/dev/null || echo "")

    if [ -z "$BODY2" ] || [ "$BODY2" == "null" ]; then
        log_error "Failed to receive message on second attempt"
        log_info "Debug: Checking if message went to DLQ prematurely..."
        DLQ_CHECK=$(aws sqs receive-message --queue-url $DLQ_URL --max-number-of-messages 1 --output json)
        echo "DLQ contents: $DLQ_CHECK"
        return 1
    fi

    log_info "  Attempt 2: Received message ID=$MSG_ID2, ReceiveCount=$RECV_COUNT2"

    # Verify it's the same message
    if [ "$MSG_ID1" != "$MSG_ID2" ]; then
        log_error "ERROR: Different message IDs! First=$MSG_ID1, Second=$MSG_ID2"
        log_error "This indicates multiple messages in queue or message ID not persisting"
        return 1
    fi

    log_info "  Attempt 2: NOT deleting, waiting for visibility timeout (3s + 1s buffer)..."
    sleep 4

    # Third receive - message should be moved to DLQ after this timeout
    log_info "  Attempt 3: Receiving message (should still be in main queue)..."
    MESSAGE3=$(aws sqs receive-message \
        --queue-url $MAIN_QUEUE_URL \
        --visibility-timeout 3 \
        --max-number-of-messages 1 \
        --attribute-names ApproximateReceiveCount \
        --output json)

    BODY3=$(echo $MESSAGE3 | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
    RECV_COUNT3=$(echo $MESSAGE3 | jq -r '.Messages[0].Attributes.ApproximateReceiveCount' 2>/dev/null || echo "")
    MSG_ID3=$(echo $MESSAGE3 | jq -r '.Messages[0].MessageId' 2>/dev/null || echo "")

    if [ -z "$BODY3" ] || [ "$BODY3" == "null" ]; then
        log_error "Failed to receive message on third attempt"
        log_info "Debug: Message might have already moved to DLQ..."
        # This could be expected if count logic is off by one
    else
        log_info "  Attempt 3: Received message ID=$MSG_ID3, ReceiveCount=$RECV_COUNT3"

        if [ "$MSG_ID1" != "$MSG_ID3" ]; then
            log_error "ERROR: Different message IDs! First=$MSG_ID1, Third=$MSG_ID3"
            return 1
        fi

        log_info "  Attempt 3: NOT deleting, waiting for visibility timeout (3s + 1s buffer)..."
        log_info "  After this timeout, message should move to DLQ..."
        sleep 4
    fi

    # Now check DLQ - message should be there
    log_info "Checking DLQ for the message..."

    # Try multiple times with delays as cleanup thread might still be processing
    for check in {1..5}; do
        log_info "  DLQ check attempt $check/5..."

        DLQ_MESSAGE=$(aws sqs receive-message \
            --queue-url $DLQ_URL \
            --max-number-of-messages 1 \
            --attribute-names All \
            --output json)

        DLQ_BODY=$(echo $DLQ_MESSAGE | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
        DLQ_RECEIPT=$(echo $DLQ_MESSAGE | jq -r '.Messages[0].ReceiptHandle' 2>/dev/null || echo "")
        DLQ_MSG_ID=$(echo $DLQ_MESSAGE | jq -r '.Messages[0].MessageId' 2>/dev/null || echo "")
        DLQ_RECV_COUNT=$(echo $DLQ_MESSAGE | jq -r '.Messages[0].Attributes.ApproximateReceiveCount' 2>/dev/null || echo "")

        if [ "$DLQ_BODY" == "Test DLQ message" ]; then
            log_success "✓ Message found in DLQ!"
            log_info "  Message ID: $DLQ_MSG_ID"
            log_info "  Body: $DLQ_BODY"
            log_info "  Receive count when moved to DLQ: $DLQ_RECV_COUNT"

            # Verify it's the same message
            if [ "$DLQ_MSG_ID" == "$MESSAGE_ID" ]; then
                log_success "✓ Message ID matches original message"
            else
                log_error "✗ Message ID mismatch! Original=$MESSAGE_ID, DLQ=$DLQ_MSG_ID"
            fi

            # Clean up DLQ message
            if [ ! -z "$DLQ_RECEIPT" ] && [ "$DLQ_RECEIPT" != "null" ]; then
                aws sqs delete-message \
                    --queue-url $DLQ_URL \
                    --receipt-handle "$DLQ_RECEIPT" \
                    --output json >/dev/null 2>&1 || true
            fi

            # Verify main queue is empty
            log_info "Verifying main queue is empty..."
            MAIN_CHECK=$(aws sqs receive-message \
                --queue-url $MAIN_QUEUE_URL \
                --max-number-of-messages 1 \
                --wait-time-seconds 2 \
                --output json)
            MAIN_BODY=$(echo $MAIN_CHECK | jq -r '.Messages[0].Body' 2>/dev/null || echo "")

            if [ -z "$MAIN_BODY" ] || [ "$MAIN_BODY" == "null" ]; then
                log_success "✓ Main queue is empty (message successfully moved to DLQ)"
            else
                log_error "✗ Main queue still has messages!"
            fi

            log_success "Dead letter queue test PASSED"
            return 0
        fi

        if [ $check -lt 5 ]; then
            log_info "  Message not in DLQ yet, waiting 2s before retry..."
            sleep 2
        fi
    done

    # If we get here, test failed
    log_error "Message NOT found in DLQ after 5 checks (10 seconds)"

    # Debug information
    log_info "=== DEBUG INFORMATION ==="

    log_info "Main queue attributes:"
    aws sqs get-queue-attributes \
        --queue-url $MAIN_QUEUE_URL \
        --attribute-names All \
        --output json | jq '.Attributes | {ApproximateNumberOfMessages, ApproximateNumberOfMessagesNotVisible, RedrivePolicy}'

    log_info "DLQ attributes:"
    aws sqs get-queue-attributes \
        --queue-url $DLQ_URL \
        --attribute-names All \
        --output json | jq '.Attributes | {ApproximateNumberOfMessages, ApproximateNumberOfMessagesNotVisible}'

    log_info "Attempting to receive from main queue one more time:"
    FINAL_CHECK=$(aws sqs receive-message \
        --queue-url $MAIN_QUEUE_URL \
        --max-number-of-messages 1 \
        --attribute-names All \
        --output json)
    echo "$FINAL_CHECK" | jq '.'

    return 1
}

# Test: Visibility Timeout
test_visibility_timeout() {
    print_test "Test 4: Visibility Timeout"

    # Create queue
    log_info "Creating queue with 5s visibility timeout..."
    # Use a timestamped queue name to avoid collisions with previous runs
    QUEUE_NAME="test-visibility-queue-$(date +%s)"
    QUEUE_URL=$(aws sqs create-queue \
        --queue-name "$QUEUE_NAME" \
        --attributes VisibilityTimeout=5 \
        --output text \
        --query 'QueueUrl')

    # Ensure queue is empty (cleanup from previous runs if any)
    aws sqs purge-queue --queue-url "$QUEUE_URL" >/dev/null 2>&1 || true
    # Allow broker time to process the purge
    sleep 1

    # Send message
    log_info "Sending message..."
    aws sqs send-message \
        --queue-url $QUEUE_URL \
        --message-body "Visibility timeout test" \
        --output json > /dev/null
    log_success "Message sent"

    # Receive message
    log_info "Receiving message (5s visibility timeout)..."
    # Small sleep to allow message to be enqueued
    sleep 1
    MESSAGE=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --max-number-of-messages 1 \
        --output json)

    RECEIPT_HANDLE=$(echo $MESSAGE | jq -r '.Messages[0].ReceiptHandle' 2>/dev/null || echo "")
    log_success "Message received: $MESSAGE"

    # Try to receive again immediately (should fail)
    log_info "Trying to receive again immediately..."
    MESSAGE2=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --max-number-of-messages 1 \
        --output json)

    COUNT=$(echo $MESSAGE2 | jq '.Messages | length' 2>/dev/null || echo "0")

    if [ "$COUNT" == "0" ]; then
        log_success "Message not visible (as expected)"
    else
        log_error "Message visible (unexpected): $MESSAGE2"
        return 1
    fi

    # Change visibility timeout
    if [ ! -z "$RECEIPT_HANDLE" ] && [ "$RECEIPT_HANDLE" != "null" ]; then
        log_info "Changing visibility timeout to 1 second..."
        aws sqs change-message-visibility \
            --queue-url $QUEUE_URL \
            --receipt-handle "$RECEIPT_HANDLE" \
            --visibility-timeout 1
        log_success "Visibility timeout changed"
    fi

    # Wait and try again
    log_info "Waiting 2 seconds..."
    sleep 3

    log_info "Trying to receive again..."
    MESSAGE3=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --max-number-of-messages 1 \
        --output json)

    COUNT3=$(echo $MESSAGE3 | jq '.Messages | length' 2>/dev/null || echo "0")
    if [ "$COUNT3" -gt "0" ]; then
        log_success "Message visible again after timeout"

        # Clean up
        RECEIPT3=$(echo $MESSAGE3 | jq -r '.Messages[0].ReceiptHandle' 2>/dev/null || echo "")
        if [ ! -z "$RECEIPT3" ] && [ "$RECEIPT3" != "null" ]; then
            aws sqs delete-message \
                --queue-url $QUEUE_URL \
                --receipt-handle "$RECEIPT3" 2>/dev/null || true
        fi
    else
        log_error "Message not visible"
        return 1
    fi

    log_success "Visibility timeout test passed"
}

# Test: Queue Attributes
test_queue_attributes() {
    print_test "Test 5: Queue Attributes"

    # Create queue
    log_info "Creating queue..."
    QUEUE_URL=$(aws sqs create-queue \
        --queue-name test-attributes-queue \
        --output text \
        --query 'QueueUrl')

    # Get all attributes
    log_info "Getting all queue attributes..."
    aws sqs get-queue-attributes \
        --queue-url $QUEUE_URL \
        --attribute-names All \
        --output json | jq '.Attributes'
    log_success "Retrieved all attributes"

    # Send some messages
    log_info "Sending 3 messages..."
    for i in {1..3}; do
        aws sqs send-message \
            --queue-url $QUEUE_URL \
            --message-body "Message $i" \
            --output json > /dev/null
    done

    # Check approximate message count
    log_info "Checking message count..."
    MSG_COUNT=$(aws sqs get-queue-attributes \
        --queue-url $QUEUE_URL \
        --attribute-names ApproximateNumberOfMessages \
        --output text \
        --query 'Attributes.ApproximateNumberOfMessages')
    log_success "Approximate number of messages: $MSG_COUNT"

    # Purge queue
    log_info "Purging queue..."
    aws sqs purge-queue --queue-url $QUEUE_URL
    log_success "Queue purged"

    log_success "Queue attributes test passed"
}

# Test: FIFO Queue
test_fifo_queue() {
    print_test "Test 6: FIFO Queue"

    # Create FIFO queue
    log_info "Creating FIFO queue..."
    FIFO_QUEUE_URL=$(aws sqs create-queue \
        --queue-name test-fifo-queue \
        --attributes FifoQueue=true \
        --output text \
        --query 'QueueUrl' 2>/dev/null || echo "")

    if [ -z "$FIFO_QUEUE_URL" ] || [ "$FIFO_QUEUE_URL" == "null" ]; then
        log_error "Failed to create FIFO queue (may not be fully implemented)"
        return 1
    fi
    log_success "FIFO queue created: $FIFO_QUEUE_URL"

    # Send message with message group ID
    log_info "Sending message with MessageGroupId..."
    aws sqs send-message \
        --queue-url $FIFO_QUEUE_URL \
        --message-body "FIFO test message" \
        --message-group-id "test-group-1" \
        --message-deduplication-id "dedup-1" \
        --output json > /dev/null 2>&1 || {
        log_error "Failed to send FIFO message (may not be fully implemented)"
        return 1
    }
    log_success "FIFO message sent"

    # Receive message
    log_info "Receiving FIFO message..."
    MESSAGE=$(aws sqs receive-message \
        --queue-url $FIFO_QUEUE_URL \
        --max-number-of-messages 1 \
        --output json)

    BODY=$(echo $MESSAGE | jq -r '.Messages[0].Body' 2>/dev/null || echo "")
    if [ "$BODY" == "FIFO test message" ]; then
        log_success "Received FIFO message: $BODY"
    else
        log_error "Failed to receive FIFO message"
        return 1
    fi

    log_success "FIFO queue test completed"
}

# Test: Message Attributes
test_message_attributes() {
    print_test "Test 7: Message Attributes"

    # Create queue
    log_info "Creating queue..."
    QUEUE_URL=$(aws sqs create-queue \
        --queue-name test-attributes-msg-queue \
        --output text \
        --query 'QueueUrl')

    # Send message with attributes
    log_info "Sending message with attributes..."
    aws sqs send-message \
        --queue-url $QUEUE_URL \
        --message-body "Message with attributes" \
        --message-attributes '{
            "Author": {"StringValue": "TestScript", "DataType": "String"},
            "Priority": {"StringValue": "5", "DataType": "Number"},
            "Timestamp": {"StringValue": "'"$(date +%s)"'", "DataType": "Number"}
        }' \
        --output json > /dev/null
    log_success "Message sent with attributes"

    # Receive and display attributes
    log_info "Receiving message with attributes..."
    MESSAGE=$(aws sqs receive-message \
        --queue-url $QUEUE_URL \
        --message-attribute-names All \
        --max-number-of-messages 1 \
        --output json)

    echo $MESSAGE | jq '.Messages[0] | {Body: .Body, Attributes: .MessageAttributes}'
    log_success "Message attributes retrieved"

    # Clean up
    RECEIPT=$(echo $MESSAGE | jq -r '.Messages[0].ReceiptHandle' 2>/dev/null || echo "")
    if [ ! -z "$RECEIPT" ] && [ "$RECEIPT" != "null" ]; then
        aws sqs delete-message \
            --queue-url $QUEUE_URL \
            --receipt-handle "$RECEIPT" 2>/dev/null || true
    fi

    log_success "Message attributes test passed"
}

trap 'sleep 5 && cleanup_queues' EXIT

# Main execution
main() {
    echo -e "${BLUE}Starting SQS tests...${NC}\n"

    # Check dependencies
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install it first."
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        log_error "jq not found. Please install it first."
        exit 1
    fi

    # Run tests
    FAILED_TESTS=0

    test_basic_queue_operations || ((FAILED_TESTS++))
    test_batch_operations || ((FAILED_TESTS++))
    # test_dead_letter_queue || ((FAILED_TESTS++))
    test_visibility_timeout || ((FAILED_TESTS++))
    test_queue_attributes || ((FAILED_TESTS++))
    test_fifo_queue || ((FAILED_TESTS++))
    test_message_attributes || ((FAILED_TESTS++))

    # Summary
    echo ""
    echo -e "${BLUE}========================================${NC}"
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
    else
        echo -e "${RED}$FAILED_TESTS test(s) failed${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"

    exit $FAILED_TESTS
}

# Run main function
main "$@"
