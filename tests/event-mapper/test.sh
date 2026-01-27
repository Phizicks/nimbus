#!/usr/bin/env bash

set -euo pipefail
export PS4='# ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]-main()}() - [${SHLVL},${BASH_SUBSHELL},$?] '

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cleanup() {
  aws sqs delete-queue --queue-url http://localhost:9324/456645664566/esm-basic-queue 2>/dev/null || true
  aws sqs delete-queue --queue-url http://localhost:9324/456645664566/esm-result-queue 2>/dev/null || true
  aws lambda delete-function --function-name esm-lambda-test 2>/dev/null || true
  uuid=$(aws lambda list-event-source-mappings | jq -r '.EventSourceMappings[] | select(.FunctionArn == "arn:aws:lambda:ap-southeast-2:456645664566:function:esm-lambda-test").UUID')
  aws lambda delete-event-source-mapping --uuid $uuid 2>/dev/null || true
  rm response.json 2>/dev/null || true
  rm -f function.zip
}
# trap cleanup EXIT

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

cleanup

cd ../lambda/nodejs/
mkdir -p src

# Simple forwarding Lambda
(cd src && zip ../function.zip events.js)

print_test "Setting up SQS queues"
# Create queues
log_info "Creating source queue..."
queue_url=$(aws sqs create-queue \
  --queue-name esm-basic-queue \
  --attributes VisibilityTimeout=2,MessageRetentionPeriod=300 \
  --output text)
queue_arn=$(aws sqs get-queue-attributes --queue-url $queue_url --attribute-names QueueArn --output text --query 'Attributes.QueueArn')
log_success "Created source queue: $queue_url with ARN: $queue_arn"

result_queue_url=$(aws sqs create-queue \
  --queue-name esm-result-queue \
  --attributes VisibilityTimeout=2,MessageRetentionPeriod=300 \
  --output text)
result_queue_arn=$(aws sqs get-queue-attributes --queue-url $queue_url --attribute-names QueueArn --output text --query 'Attributes.QueueArn')
log_success "Created result queue: $result_queue_url with ARN: $result_queue_arn"

log_info "Creating Lambda function..."
aws lambda delete-function --function-name esm-lambda-test 2>/dev/null || true
result=$(aws lambda create-function \
  --function-name esm-lambda-test \
  --runtime nodejs22.x \
  --handler events.handler \
  --role arn:aws:iam::456645664566:role/nodejs-role \
  --zip-file fileb://function.zip \
  --environment Variables="{RESULT_QUEUE_URL=$result_queue_url,AWS_ENDPOINT_URL_SQS=http://api:4566}") || true
log_success "Created Lambda function: esm-lambda-test"
set -x
# Ensure mapping exists
log_info "Setting up Event Source Mapping from SQS to Lambda..."

esm_uuid=$(aws lambda list-event-source-mappings --function-name esm-lambda-test | jq -r ".EventSourceMappings[]? | select(.EventSourceArn==\"$queue_arn\") | .UUID")
[ -n "$esm_uuid" ] && aws lambda delete-event-source-mapping --uuid $esm_uuid || true

# Create new
esm_uuid=$(aws lambda create-event-source-mapping \
  --event-source-arn "$queue_arn" \
  --function-name esm-lambda-test \
  --batch-size 1 \
  --enabled | jq -r '.UUID')
log_success "Created new ESM (enabled)"

sleep 5
echo "--------------------------------------------------------"

# Send test message
log_info "Sending test message to source queue..."
aws sqs send-message --queue-url "$queue_url" --message-body "Hello EMS Lambda" --output json
log_success "Sent test message to source queue."

# Wait and verify result
log_info "Waiting for message in result queue..."
for i in {1..10}; do
  msg=$(aws sqs receive-message --queue-url "$result_queue_url" --max-number-of-messages 1 --wait-time-seconds 1 2>/dev/null || true)
  receipt_handle=$(echo "$msg" | jq -r '.Messages[0].ReceiptHandle')
  body=$(echo "$msg" | jq -r '.Messages[0].Body')

  if [[ "$body" == "Hello EMS Lambda" ]]; then
    aws sqs delete-message \
      --queue-url "$result_queue_url" \
      --receipt-handle "$receipt_handle"

    log_success "SUCCESS: Received expected message in result queue: $body"
    # Successful exit
    echo ""
    echo "Cleaning up..."
    aws lambda update-event-source-mapping --uuid $esm_uuid --no-enabled
    exit 0
  fi
  sleep 1
done

log_error "FAILURE: No matching message found in result queue."
exit 1
