#!/bin/bash
#
# TA-100 Emulation Test Script
# ============================
#
# This script builds and runs the TA-100 test firmware on the m33mu emulator.
#
# What it does:
#   1. Builds the test firmware (test-ta100/app.bin)
#   2. Launches m33mu with TA-100 attached to SPI2
#   3. Firmware runs all TA-100 command tests
#   4. On success: firmware hits BKPT #0x7F (detectable for CI)
#   5. On failure: firmware halts without breakpoint
#
# Hardware Configuration:
#   CPU: stm32u585
#   SPI: SPI2
#   CS:  PB5
#   Pins: PB13(SCK), PB14(MISO), PB15(MOSI)
#
# TA-100 Commands Tested:
#   Phase 2: INFO, READ, WRITE, LOCK
#   Phase 3: RANDOM, NONCE, GENKEY, SIGN, SHA256
#
# Usage:
#   ./run_test.sh            # Normal run with output
#   ./run_test.sh --ci       # CI mode (check for BKPT #0x7F)
#   ./run_test.sh --trace    # Enable SPI and TA-100 tracing
#   ./run_test.sh --clean    # Clean build artifacts
#
# Exit codes:
#   0: All tests passed (BKPT #0x7F reached)
#   1: Build failed or tests failed
#   2: Timeout (tests didn't complete)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M33MU_ROOT="${SCRIPT_DIR}/../../.."
FIRMWARE_DIR="${SCRIPT_DIR}"
M33MU_BIN="${M33MU_ROOT}/build/m33mu"
TA100_NV_FILE="/tmp/ta100_test_nv.bin"

# Parse command line
CI_MODE=0
TRACE_MODE=0
CLEAN_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=1 ;;
        --trace) TRACE_MODE=1 ;;
        --clean) CLEAN_ONLY=1 ;;
        --help)
            head -n 30 "$0" | tail -n +2 | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN_ONLY" -eq 1 ]; then
    echo "==> Cleaning build artifacts..."
    cd "$FIRMWARE_DIR"
    make clean
    rm -f "$TA100_NV_FILE"
    echo "==> Done"
    exit 0
fi

# Build firmware
echo "==> Building TA-100 test firmware..."
cd "$FIRMWARE_DIR"
make clean
make

if [ ! -f app.bin ]; then
    echo "ERROR: Build failed - app.bin not found"
    exit 1
fi

echo "==> Firmware built: $(wc -c < app.bin) bytes"

# Prepare environment
rm -f "$TA100_NV_FILE"

# Set up tracing if requested
ENV_VARS=""
if [ "$TRACE_MODE" -eq 1 ]; then
    export M33MU_SPI_TRACE=1
    export M33MU_TA100_TRACE=1
    ENV_VARS="M33MU_SPI_TRACE=1 M33MU_TA100_TRACE=1"
    echo "==> Trace mode enabled"
fi

# Build emulator command
EMU_CMD="$M33MU_BIN \
    --cpu stm32u585 \
    --ta100:SPI2:cs=PB5:file=$TA100_NV_FILE \
    --uart-stdout \
    --timeout 10 \
    app.bin"

if [ "$CI_MODE" -eq 1 ]; then
    # CI mode: expect BKPT #0x7F
    EMU_CMD="$EMU_CMD --expect-bkpt 0x7F"
fi

echo "==> Running emulator..."
echo "    CPU: stm32u585"
echo "    TA-100: SPI2, CS=PB5"
echo "    NV file: $TA100_NV_FILE"
echo ""

# Run the emulator
if [ -n "$ENV_VARS" ]; then
    echo "==> Environment: $ENV_VARS"
fi

cd "$FIRMWARE_DIR"
set +e
eval "$EMU_CMD"
EXIT_CODE=$?
set -e

echo ""
echo "==> Emulator exit code: $EXIT_CODE"

# Check NV file was created
if [ -f "$TA100_NV_FILE" ]; then
    NV_SIZE=$(wc -c < "$TA100_NV_FILE")
    echo "==> NV file created: $NV_SIZE bytes"
fi

# Interpret exit code
if [ "$CI_MODE" -eq 1 ]; then
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo ""
        echo "========================================"
        echo "✓ ALL TESTS PASSED"
        echo "  BKPT #0x7F reached successfully"
        echo "========================================"
        exit 0
    else
        echo ""
        echo "========================================"
        echo "✗ TESTS FAILED"
        echo "  BKPT #0x7F not reached (exit=$EXIT_CODE)"
        echo "========================================"
        exit 1
    fi
else
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo ""
        echo "==> Tests completed successfully"
    else
        echo ""
        echo "==> Tests may have failed (check output above)"
    fi
    exit "$EXIT_CODE"
fi
