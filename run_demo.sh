#!/bin/bash
# ==============================================================================
# TCP Protocol Simulation - Automated Demo Script
# Compiles sender and receiver, then launches both to demonstrate
# 3-way handshake, sliding window, AIMD, error checking, and 4-way FIN termination.
# ==============================================================================

set -e

echo "=================================================="
echo "  COMPILING TCP SIMULATION PROJECT (C++17)        "
echo "=================================================="

# Compile sender and receiver with C++17 and pthread
g++ -std=c++17 -Wall -Wextra -o sender sender.cpp -lpthread
g++ -std=c++17 -Wall -Wextra -o receiver receiver.cpp

echo "[BUILD SUCCESS] sender and receiver binaries generated."
echo ""

# Start Receiver in background (acts as client, will wait for sender)
echo "=== Starting Receiver in background ==="
./receiver &
RECV_PID=$!
sleep 1

# Start Sender in foreground (acts as server)
echo "=== Starting Sender ==="
./sender

# Wait for receiver to finish printing complete received document
wait $RECV_PID

echo ""
echo "=== Demo Complete ==="
