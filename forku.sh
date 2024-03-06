#!/bin/bash

# Function to display the help menu
print_help() {
  echo "Usage: $0 <pid> <snapshot_name>"
  echo "  pid            - process id of a process to snapshot"
  echo "  snapshot_name  - name of the snapshot"
}

# Check if exactly two arguments are passed
if [ "$#" -ne 2 ]; then
  print_help
  exit 1
fi

# Check if the first argument is an integer
if ! [[ "$1" =~ ^-?[0-9]+$ ]]; then
  print_help
  exit 1
fi

# Check if the second argument is a non-empty string
if [ -z "$2" ]; then
  print_help
  exit 1
fi

SNAPSHOT_MOUNT_POINT=./sn
TARGET_PID=$1
SNAPSHOT_NAME=$2
SNAPSHOT_DIR=$SNAPSHOT_MOUNT_POINT/$TARGET_PID

mkdir -p $SNAPSHOT_DIR
cd $SNAPSHOT_DIR

touch $SNAPSHOT_NAME

