#!/bin/bash
set -e

# Check if cargo-llvm-cov is installed
if ! cargo llvm-cov --version &> /dev/null; then
    echo "Error: cargo-llvm-cov is not installed."
    echo "Please install it using the following command:"
    echo "    cargo install cargo-llvm-cov"
    echo ""
    echo "Alternatively, you can try 'cargo install cargo-tarpaulin' for a different coverage tool."
    exit 1
fi

# Run coverage and generate HTML report
echo "Running tests with coverage..."
cargo llvm-cov --html --open
