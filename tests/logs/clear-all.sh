#!/usr/bin/env bash

set -euo pipefail

# Optionally, set AWS profile and region
AWS_REGION=${AWS_REGION:-ap-southeast-2}

echo "Listing all CloudWatch log groups"
LOG_GROUPS=$(aws logs describe-log-groups \
  --region "$AWS_REGION" \
  --query 'logGroups[].logGroupName' \
  --output text)

if [[ -z "$LOG_GROUPS" ]]; then
  echo "No log groups found."
  exit 0
fi

for GROUP in $LOG_GROUPS; do
  echo "Processing log group: $GROUP"

  # Paginate through streams to handle large numbers
  NEXT_TOKEN=""
  while true; do
    if [[ -n "$NEXT_TOKEN" ]]; then
      RESPONSE=$(aws logs describe-log-streams \
        --log-group-name "$GROUP" \
        --region "$AWS_REGION" \
        --next-token "$NEXT_TOKEN" \
        --output json)
    else
      RESPONSE=$(aws logs describe-log-streams \
        --log-group-name "$GROUP" \
        --region "$AWS_REGION" \
        --output json)
    fi

    STREAMS=$(echo "$RESPONSE" | jq -r '.logStreams[].logStreamName')
    NEXT_TOKEN=$(echo "$RESPONSE" | jq -r '.nextToken // empty')

    if [[ -z "$STREAMS" ]]; then
      echo "  No log streams found in $GROUP"
      break
    fi

    for STREAM in $STREAMS; do
      echo "  Deleting log stream: $STREAM"
      aws logs delete-log-stream \
        --log-group-name "$GROUP" \
        --log-stream-name "$STREAM" \
        --region "$AWS_REGION" \
        >/dev/null &
    done

    wait  # wait for background deletions to finish before next page

    [[ -z "$NEXT_TOKEN" ]] && break
  done
  aws logs delete-log-group --log-group-name "$GROUP"
done

echo "All log streams cleared."

