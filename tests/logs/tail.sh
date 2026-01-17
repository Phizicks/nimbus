#!/usr/bin/env bash

timestamp=0
lasttime=0

while true; do
    while read timestamp message; do
        echo -e "${message}"
        lasttime=$((timestamp + 1))
    done  < <(aws logs filter-log-events --log-group-name "/aws/lambda/nodejs-function" --start-time $lasttime | jq -r '.events[]| [.timestamp, .message]| @tsv')
    sleep 2
done

