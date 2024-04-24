#!/bin/python3

import socket
import signal
import os
import sys
import time

def snapshot_self():
    os.system(f'./forku.sh {os.getpid()} snap')

def mark_timestamp():
    current_time_ns = time.time_ns()

    # Calculate seconds and nanoseconds
    seconds = current_time_ns // 1000000000  # Integer division to get seconds
    nanoseconds = current_time_ns % 1000000000  # Modulo operation to get nanoseconds

    # Print in the desired format "<seconds>.<nanoseconds>"
    print(f"{seconds}.{nanoseconds:09d}")

def signal_handler(sig, frame):
    print('Exiting gracefully...')
    sys.exit(0)

def run_server(host='127.0.0.1', port=5000):
    signal.signal(signal.SIGINT, signal_handler)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        snapshot_self()
        mark_timestamp()

        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received: {data.decode()}")
                    conn.sendall(b'Message received\n')

if __name__ == "__main__":
    print(f'pid: {os.getpid()}')
    run_server()
