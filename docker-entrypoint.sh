#!/bin/bash
set -e

echo "========================================"
echo "AI-Driven Network Observability Agent"
echo "========================================"
echo ""

INTERFACE=${CAPTURE_INTERFACE:-eth0}
echo "Checking interface: $INTERFACE"
if ip link show $INTERFACE >/dev/null 2>&1; then
    echo "✓ Interface $INTERFACE is available"
else
    echo "✗ Interface $INTERFACE not found"
    echo "Available interfaces:"
    ip link show
    exit 1
fi

echo ""
echo "Configuration:"
echo "  Interface: $INTERFACE"
echo "  Session Duration: ${SESSION_DURATION:-30} minutes"
echo "  LLM Enabled: ${ENABLE_LLM:-false}"
echo "  Performance Mode: ${PERFORMANCE_MODE:-false}"
echo "  Log Level: ${LOG_LEVEL:-INFO}"
echo ""

exec python3 -u src/main.py "$@"
