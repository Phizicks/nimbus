#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(dirname "$(realpath "$0")")"
TESTS_DIR="$ROOT_DIR"

success=0
fail=0
total=0

GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${YELLOW}=== Running AWS Subsystem Tests ===${RESET}"

while IFS= read -r filepath; do
    total=$((total + 1))
    test_dir="$(dirname "$filepath")"
    test_name="${test_dir#$TESTS_DIR/}"

    echo -e "\n${YELLOW}▶ Running: ${test_name}${RESET}"
    ( cd "$test_dir" && ./test.sh )
    status=$?

    if [ $status -eq 0 ]; then
        echo -e "${GREEN}✔ SUCCESS:${RESET} ${test_name}"
        success=$((success + 1))
    else
        echo -e "${RED}✖ FAIL:${RESET} ${test_name}"
        fail=$((fail + 1))
    fi
done < <(find "$TESTS_DIR" -type f -name test.sh | sort)

echo -e "\n${YELLOW}=== Test Summary ===${RESET}"
echo -e "${GREEN}Success: $success${RESET}"
echo -e "${RED}Failed:  $fail${RESET}"
echo -e "Total:   $total"

if [ "$fail" -gt 0 ]; then
    exit 1
fi

