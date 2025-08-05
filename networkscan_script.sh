#!/bin/bash

# One thing to target
if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_ip >" >&2
  exit 1
fi

TARGET=$1
REPORT_FILE="networkscan_report.txt"

# Functions & Print Outs
write_header() {
  echo "NETWORK SECURITY SCAN REPORT"
  echo
  echo "Target IP:"
  echo "$TARGET"
  echo
}

write_ports_section() {
  echo "Open Ports & Verified Services:"
  echo 
nmap -sV "$TARGET" | grep "open"
echo
}

write_vulns_section() {
  echo "Possible Vulnerabilities:"
  echo "CVE-2023-XXX - Old Web Server"
  echo "FTP Server uses default login"
  echo
}

write_recs_section() {
  echo "Recommended Fixes":
  echo "Update software"
  echo "Change default passwords"
  echo "Set up a firewall"
  echo
}

write_footer() {
  echo "END OF REPORT"
  echo "Created: $(date)"
}

main() {
  # Start Documentations
  write_header > "$REPORT_FILE"
  write_ports_section >> "$REPORT_FILE"
  write_vulns_section >> "$REPORT_FILE"
  write_recs_section >> "$REPORT_FILE"
  write_footer >> "$REPORT_FILE"

  echo "Report saved to $REPORT_FILE"
}

# Run the script within the terminal
main "$@"

