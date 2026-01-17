#!/bin/bash

# --- Configuration ---
LOG_GROUP_NAME="/test/MyTestLogGroup"
LOG_STREAM_NAME="test-stream-$(date +%Y%m%d%H%M%S)"
REGION="ap-southeast-2"

# Ensure jq is installed
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install it (e.g., 'sudo apt install jq' or 'brew install jq')."
    exit 1
fi

# Function to handle errors
handle_error() {
    echo "Error on line ${1}: ${BASH_COMMAND}"
    cleanup
    exit 1
}
#trap 'handle_error $LINENO' ERR

# Function to clean up resources
cleanup() {
    echo "--- Cleaning up resources ---"
    # Note: Deleting a log group also permanently deletes all associated archived log events.
    aws logs delete-log-group --log-group-name "$LOG_GROUP_NAME" --region "$REGION"
    echo "Log group '$LOG_GROUP_NAME' deleted."
    # Clean up the temporary log events file
    rm -f log_events.json
}

# Register the cleanup function to run on EXIT or INT (Ctrl+C)
trap cleanup EXIT INT

echo "--- Starting AWS CloudWatch Logs Test Script ---"

# 1. Create Log Group
echo "Creating log group: $LOG_GROUP_NAME in region $REGION"
aws logs create-log-group --log-group-name "$LOG_GROUP_NAME" --region "$REGION"
echo "Log group created."

# 2. Create Log Stream
echo "Creating log stream: $LOG_STREAM_NAME"
aws logs create-log-stream --log-group-name "$LOG_GROUP_NAME" --log-stream-name "$LOG_STREAM_NAME" --region "$REGION"
echo "Log stream created."

# 3. Generate and stream logs
echo "Generating and putting log events..."
TIMESTAMP=$(($(date +%s%3N))) # Current epoch time in milliseconds
cat <<EOF > log_events.json
[
  { "timestamp": $TIMESTAMP, "message": "Test Event 1: Hello AWS CLI" },
  { "timestamp": $(($TIMESTAMP + 1)), "message": "Test Event 2: Another log entry" }
]
EOF

# Use 'put-log-events' to stream the generated logs
PUT_RESPONSE=$(aws logs put-log-events \
    --log-group-name "$LOG_GROUP_NAME" \
    --log-stream-name "$LOG_STREAM_NAME" \
    --log-events file://log_events.json \
    --region "$REGION")

NEXT_SEQUENCE_TOKEN=$(echo "$PUT_RESPONSE" | jq -r '.nextSequenceToken')
echo "Log events put successfully. Next sequence token: $NEXT_SEQUENCE_TOKEN"

# 4. Verify logs were streamed (optional)
echo "Verifying logs in the stream..."
aws logs get-log-events \
    --log-group-name "$LOG_GROUP_NAME" \
    --log-stream-name "$LOG_STREAM_NAME" \
    --region "$REGION" --output text --query 'events[*].message'

echo "--- Test script finished, starting cleanup ---"

exit

api-1  | 2026-01-09 03:23:16 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=CreateLogGroup
api-1  | 2026-01-09 03:23:17 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=CreateLogStream
api-1  | 2026-01-09 03:23:18 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=PutLogEvents
api-1  | 2026-01-09 03:23:19 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=GetLogEvents
api-1  | 2026-01-09 03:23:20 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=DeleteLogGroup
api-1  | 2026-01-09 03:23:23 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=DescribeLogGroups
api-1  | 2026-01-09 03:23:26 [INFO] aws_api.handle_request:2273 | Routing to SQS handler: Operation=ListQueues
api-1  | 2026-01-09 03:23:27 [INFO] aws_api.handle_request:2464 | Routing to Log handler: Operation=DescribeLogGroups

