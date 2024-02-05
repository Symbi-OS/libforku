#!/bin/bash

# Path to the runner script
RUN_SPINNER_SCRIPT="./run_spinner.sh"

# Pass options to the runner script via a pipe
{
    echo "4"   # forku - create doppelganger
    sleep 1    # Adjust sleep as necessary to allow the script to process each command
    echo "2"   # Send a SIGUSR1 signal to it
    sleep 1    # Adjust sleep as necessary
    echo "4"   # forku - create doppelganger again
    sleep 1    # Adjust sleep as necessary
    echo "1"   # Kill original process
} | $RUN_SPINNER_SCRIPT

# Capture the exit code of the runner script
EXIT_CODE=$?

# Leave some space between experiment output and unit test messages
echo ""

# Define color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check the exit code and print the appropriate message
if [ $EXIT_CODE -eq 0 ]; then
    echo "------------------------------------------------"
    printf "                ${GREEN}Test passed!${NC}\n"
    echo "------------------------------------------------"
else
    echo "------------------------------------------------"
    printf "           ${RED}Test failed. Exit code: $EXIT_CODE${NC}\n"
    echo "------------------------------------------------"
    exit $EXIT_CODE
fi
