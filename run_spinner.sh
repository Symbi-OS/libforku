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

print_options() {
    echo ""
    echo "Enter a command:"
    echo "0) Show options"
    echo "1) Kill target pid"
    echo "2) Send a SIGUSR1 signal to it"
    echo "3) Print target pid"
    echo "4) forku - create doppelganger"
    echo "5) Exit"
}

print_options

# Main loop for accepting commands
while true; do
    if ! kill -0 $TARGET_PID 2>/dev/null; then
        echo "[*] Spinner process got killed..."
        exit 1
    fi

    read -p "> " cmd

    case $cmd in
        0)
            print_options
            ;;
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
            echo "taskset -c 0 $FORKU_UTIL $TARGET_PID"
            taskset -c 0 $FORKU_UTIL $TARGET_PID
            ;;
        5)
            break
            ;;
        *)
            echo "Invalid command"
            ;;
    esac

    sleep 0.2
done

echo "Exiting script."
