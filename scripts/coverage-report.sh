#!/bin/bash
# Coverage report script that excludes auto-generated code
# This provides accurate coverage metrics for production code only

set -e

# Packages to exclude from coverage (auto-generated and test mocks)
EXCLUDE_PATTERN="(pkg/api/v1alpha1|cmd/operator|internal/kms/mock)$"

# Get list of packages excluding the pattern
COVERAGE_PACKAGES=$(go list ./... | grep -v -E "${EXCLUDE_PATTERN}")

echo "Running tests with filtered coverage..."
echo "Excluding: pkg/api/v1alpha1 (generated), cmd/operator (generated), internal/kms/mock (test mock)"
echo ""

# Run tests with coverage
go test ${COVERAGE_PACKAGES} -coverprofile=coverage-filtered.out

# Display coverage summary
echo ""
echo "==================================="
echo "Production Code Coverage Summary"
echo "==================================="
go tool cover -func=coverage-filtered.out | tail -1

# Generate HTML report if requested
if [ "$1" = "--html" ]; then
    go tool cover -html=coverage-filtered.out -o coverage-filtered.html
    echo ""
    echo "HTML report generated: coverage-filtered.html"
fi

# Optionally show detailed breakdown
if [ "$1" = "--detailed" ]; then
    echo ""
    echo "==================================="
    echo "Per-Package Coverage Breakdown"
    echo "==================================="
    go tool cover -func=coverage-filtered.out | grep -E "^github.com" | awk '{print $1, $3}' | sort -t '/' -k 5
fi

echo ""
echo "Run with --html to generate HTML report"
echo "Run with --detailed to see per-package breakdown"
