#!/bin/bash

# One thing to target
if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_ip>" >&2
  exit 1
fi

TARGET=$1
REPORT_FILE="networkscan_report.txt"

# Functions for prints
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

  # One
  echo "ID'd by nmap script:"
  echo "$SCAN_RESULTS" | grep "VULNERABLE"
  echo

  # Two
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
  
  write_header >> "$REPORT_FILE"
  write_ports_section >> "$REPORT_FILE"
  write_vulns_section >> "$REPORT_FILE"
  write_recs_section >> "$REPORT_FILE"
  write_footer >> "$REPORT_FILE"

  echo "Report saved to $REPORT_FILE"
}

main "$@"

# Run scan
SCAN_RESULTS=$(nmap -sV --script vuln "$TARGET")

# Create a report
{
  write_header
  write_ports_section
  write_vulns_section
} > "$REPORT_FILE"

echo "Report saved to $REPORT_FILE"

