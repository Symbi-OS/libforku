#!/bin/bash

# This script requires at least one argument
if [ $# -lt 1 ]; then
    echo "Usage: $0 snapshot_path [foster_parent_shell_pid]"
    exit 1
fi

# Required parameter
SNAPSHOT_PATH=$1

# Check if SNAPSHOT_PATH is a valid file
if [ ! -f "$SNAPSHOT_PATH" ]; then
    echo "Error: The provided SNAPSHOT_PATH '$SNAPSHOT_PATH' is not a valid file."
    exit 1
fi

# Optional parameter
FOSTER_SHELL=${2:-$PPID}  # Default to the process ID of this shell if not provided

# Execute in a subshell to detect open file descriptors and perform redirection
(
    fd_info=()
    for fd in /proc/self/fd/*; do
        descriptor=$(readlink $fd)
        fd_number=$(basename $fd)

        if [[ -n $descriptor ]]; then  # Check if the descriptor is non-empty
            fd_info+=("$fd_number")
            #echo "[DEBUG] FD $fd_number -> $descriptor"
        fi
    done

    # Join array into a single string
    fd_string=$(IFS=","; echo "${fd_info[*]}")

    # Launch the snapshot
    echo "$FOSTER_SHELL/$fd_string" >> $SNAPSHOT_PATH
)

