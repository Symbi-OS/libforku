#!/bin/bash

TARGET_BIN=./malloc_spinner
FORKU_UTIL=./forku_util
TARGET_CORE=0

taskset -c $TARGET_CORE $TARGET_BIN &
TARGET_PID=$!

disown $TARGET_PID

ps auxgww | grep $TARGET_PID | grep $TARGET_BIN

# Function to print the target PID
print_target_pid() {
    echo "Target PID: $TARGET_PID"
}

# Main loop for accepting commands
while true; do
    echo ""
    echo "Enter a command:"
    echo "1) Kill target pid"
    echo "2) Send a SIGUSR1 signal to it"
    echo "3) Print target pid"
    echo "4) Exit"
    read -p "> " cmd

    case $cmd in
        1)
            kill $TARGET_PID
            echo "Killed target process with PID $TARGET_PID"
            break
            ;;
        2)
            kill -SIGUSR1 $TARGET_PID
            echo "Sent SIGUSR1 to target process with PID $TARGET_PID"
            ;;
        3)
            print_target_pid
            ;;
        4)
            break
            ;;
        *)
            echo "Invalid command"
            ;;
    esac
done

echo "Exiting script."
