#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_ip>"
  exit 1
fi

TARGET="$1"
REPORT_FILE="report_NVD-v2.txt"

# NVD function

query_nvd() {
  product="$1"
  version="$2"
	local results_limit=3

  echo "Checking $product $version in NVD..."

  # Build search link
  search=$(echo "$product $version" | sed 's/ /%20/g')
  url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$search&resultsPerPage=1"

  # Get results
  curl -s "$url" | jq -r '.vulnerabilities[]?.cve.id'
}

# Run nmap scan
SCAN_RESULTS=$(nmap -sV "$TARGET")

# Save whole scan
echo "$SCAN_RESULTS" > "$REPORT_FILE"

# Go line by line
echo "$SCAN_RESULTS" | while read -r line; do
  # Only look at open services
  if echo "$line" | grep -q "open"; then
    # Product = column 5, Version = column 6 (very simple assumption)
    product=$(echo "$line" | awk '{print $5}')
    version=$(echo "$line" | awk '{print $6}')

    if [ -n "$product" ] && [ -n "$version" ]; then
      echo "Service: $product $version" >> "$REPORT_FILE"
      query_nvd "$product" "$version" >> "$REPORT_FILE"
    fi
  fi
done

echo "Report saved to $REPORT_FILE"

