#!/bin/bash

# Require one target
if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_ip>" >&2
  exit 1
fi

TARGET=$1
REPORT_FILE="Updated_networkscan_report.txt"

# Limits for NVD lookup
MAX_NVD=3
NVD_SLEEP=1

# Check for jq
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=1
else
  HAS_JQ=0
fi

# Request NVD for CVEs
query_nvd() {
  local product=$1
  local version=$2
  local search
  local url
  search=$(printf '%s' "$product $version" | sed 's/ /%20/g')
  url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$search&resultsPerPage=3"

  if [ "$HAS_JQ" -eq 1 ]; then
    curl -s "$url" | jq -r '.vulnerabilities[]?.cve.id'
  else
    echo "(jq not found; raw JSON follows)"
    curl -s "$url"
  fi
}

# Sections
write_header() {
  echo "NETWORK SECURITY SCAN REPORT"
  echo "Target IP: $TARGET"
  echo "Date: $(date)"
  echo
}

write_ports_section() {
  echo "Open Ports & Services using nMap:"
  echo "$SCAN_RESULTS" | grep "open" || {
    echo "(Zero open ports located or failed scan)"
  }
  echo
}

write_vulns_section() {
  echo "Potential Vulnerabilities Identified:"
  echo

  echo "ID'd by nmap script:"
  echo "$SCAN_RESULTS" | grep "VULNERABLE"
  echo

  echo "Manual service version check:"
  echo "$SCAN_RESULTS" | while read -r line; do
    case "$line" in
      *"vsftpd 2.3.4"*)
        echo "[!!] vsftpd 2.3.4 has a known backdoor"
        ;;
      *"Apache httpd 2.4.49"*)
        echo "[!!] Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773)"
        ;;
    esac
  done
  echo

  echo "NVD lookups for detected services:"
  # Pull product and version from open lines, limit to MAX_NVD
  services=$(echo "$SCAN_RESULTS" | awk '/open/ {print $5, $6}' | head -n "$MAX_NVD")
  if [ -z "$services" ]; then
    echo "No services found for NVD lookup"
  else
    while read -r product version; do
      [ -z "$product" ] && continue
      [ -z "$version" ] && continue
      echo "Service: $product $version"
      query_nvd "$product" "$version"
      echo
      sleep "$NVD_SLEEP"
    done <<< "$services"
  fi
  echo
}

write_recs_section() {
  echo "Recommended Fixes:"
  echo "Update software"
  echo "Change default passwords"
  echo "Set up a firewall"
  echo
}

write_footer() {
  echo "END OF REPORT"
  echo "Created: $(date)"
}

SCAN_RESULTS=""

main() {
  SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET")

  {
    write_header
    write_ports_section
    write_vulns_section
    write_recs_section
    write_footer
  } > "$REPORT_FILE"

  echo "Report saved to $REPORT_FILE"
}

main "$@"

