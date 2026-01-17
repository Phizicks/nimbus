#!/bin/bash

QUEUE_URL_SEND="http://localhost:9324/000000000000/ems-basic-queue"
QUEUE_URL_RESULT="http://localhost:9324/000000000000/ems-result-queue"

# Send a test message
aws sqs send-message \
  --queue-url "$QUEUE_URL_SEND" \
  --message-body '{"Records": [{"Body": "1-1 test 1"}]}' \
  --output json

# Poll and delete messages in batch
for i in {1..10}; do
    msgs=$(aws sqs receive-message \
        --queue-url "$QUEUE_URL_RESULT" \
        --max-number-of-messages 10 \
        --wait-time-seconds 1 \
        --output json)

    count=$(echo "$msgs" | jq -r '.Messages | length // 0')

    if [ "$count" -gt 0 ]; then
        echo "Received $count messages:"
        echo "$msgs" | jq -r '.Messages[].Body'

        # Delete messages one by one (simpler approach)
        echo "$msgs" | jq -r '.Messages[] | .ReceiptHandle' | while read -r receipt; do
            aws sqs delete-message \
                --queue-url "$QUEUE_URL_RESULT" \
                --receipt-handle "$receipt"
        done
        exit
    else
        echo "No messages received, retrying..."
        sleep 3
    fi

done
echo "Test completed."
