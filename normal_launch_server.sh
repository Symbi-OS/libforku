#!/bin/bash

# Get the current time in nanoseconds
start_time_ns=$(date +%s%N)

# Compute the seconds and remaining nanoseconds
start_seconds=$(($start_time_ns / 1000000000))
start_nanoseconds=$(($start_time_ns % 1000000000))

# Print the formatted start time
echo "Start time: $start_seconds.$start_nanoseconds"

# Use fork+exec to start the Python interpreter
./server.py
