#!/bin/bash

# Purpose of script: to speed up data collections when targetting a P.O.C.
# Make sure all runs smooth
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <target ip or hostname>" >&2
  exit 1
fi

TARGET="$1"

# Save time with install & verifications,this was a add-on I came accross. I found myself apt-get & --version often. 

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    exit 1
  fi
}

need nmap
need curl
need jq

STAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="Final_Network-Scan_report_${STAMP}.txt"
SV_TMP="sv_${STAMP}.txt"

cleanup() {
  [ -f "$SV_TMP" ] && rm -f "$SV_TMP"
}
trap cleanup EXIT

# To make reading the data more manageable.
write_header() {
  {
    echo "Network Vulnerability Scan Report"
    echo "Target: $TARGET"
    echo "Date: $(date -Iseconds)"
    echo
  } > "$REPORT"
}

# The main tool used for recon on a target system.Identifies ports & services.
# nmap -sV: runs a scan with service/version detection.
# -T4: faster timing.
# -Pn: skip host discovery, assume the host is up.
run_nmap_services() {
  {
    echo "1) Open Ports and Services"
    echo "Command: nmap -sV -T4 -Pn $TARGET"
    echo
  } >> "$REPORT"

  # Save time, the -sV output to both report and temp file (reuse  data)
  nmap -sV -T4 -Pn "$TARGET" | tee -a "$REPORT" > "$SV_TMP"
  echo >> "$REPORT"
}

# Insereted to see which OS or a firewall etc. is present.
# nmap -O: that’s the OS detection mode.
# -T4: faster timing.
# -Pn: don’t ping, assume host is up.

run_nmap_os() {
  {
    echo "2) OS Fingerprint"
    echo "Command: nmap -O -T4 -Pn $TARGET"
    echo
  } >> "$REPORT"

  if ! nmap -O -T4 -Pn "$TARGET" >> "$REPORT" 2>/dev/null; then
    echo "[note] OS detection not available" >> "$REPORT"
  fi
  echo >> "$REPORT"
}
# Nmap scan with vulnerability detection scripts, and write the results.
# --script vuln: tells Nmap to run all scripts in its “vuln” category. These check for known weaknesses like misconfigurations or outdated software.
# -sV: service/version detection, so the scripts know what they’re testing against.
# -T4: faster timing.
# -Pn: skip ping checks, assume host is up.

run_nmap_vuln() {
  {
    echo "3) Nmap NSE vuln scripts"
    echo "Command: nmap --script vuln -sV -T4 -Pn $TARGET"
    echo
  } >> "$REPORT"

  nmap --script vuln -sV -T4 -Pn "$TARGET" >> "$REPORT" 2>/dev/null || {
    echo "[note] NSE vuln run failed" >> "$REPORT"
  }
  echo >> "$REPORT"
}

# Extracted data "product|version" from one -sV line
# Handles "name/1.2.3" or "Name 1.2.3 ..." patterns
extract_product_and_version() {
  line="$1"

  # Keep only the details after: port/proto  open  service
  details="$(echo "$line" | sed -E 's#^[0-9]+/[a-z]+[[:space:]]+open[[:space:]]+[[:graph:]-]+[[:space:]]+##')"
  [ -z "$details" ] && return 1

  product=""
  version=""

  for tok in $details; do
    if [ -z "$product" ] && echo "$tok" | grep -q '/'; then
      product="${tok%%/*}"
      version="${tok#*/}"
      break
    fi

    if echo "$tok" | grep -q '[0-9]'; then
      version="$tok"
      break
    else
      if [ -z "$product" ]; then
        product="$tok"
      else
        product="$product $tok"
      fi
    fi
  done

  # Basic cleanup: strip trailing commas or parentheses from version
  version="$(echo "$version" | sed -E 's/[),;]+$//')"

  [ -n "$product" ] && [ -n "$version" ] || return 1# Extract "product|version" from one -sV line
extract_product_and_version() {
  line="$1"

  # Drop the leading port/proto/open/service fields
  details="$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}')"
  [ -z "$details" ] && return 1

  # Case 1: token like "name/version"
  if echo "$details" | grep -q '/'; then
    product="${details%%/*}"
    version="${details#*/}"
  else
    # Case 2: split into words, take first with a number as version
    for tok in $details; do
      if echo "$tok" | grep -q '[0-9]'; then
        product="${product:-${prev:-$tok}}"
        version="$tok"
        break
      fi
      prev="$tok"
    done
  fi

  [ -n "$product" ] && [ -n "$version" ] || return 1
  echo "${product}|${version}"
}

  echo "${product}|${version}"
}

# Query NVD for a product+version keyword search
# Shows CVE and CVSS v3.1 score when present
query_nvd() {
  prod="$1"
  ver="$2"

  # Respect optional API key (header "apiKey")
  header_opts=()
  if [ -n "${NVD_API_KEY-}" ]; then
    header_opts=(-H "apiKey: ${NVD_API_KEY}")
  fi

  url="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&keywordSearch=$(printf '%s%%20%s' "$prod" "$ver")"

  echo "[NVD] $prod $ver" >> "$REPORT"

  resp="$(curl -sS --connect-timeout 10 --max-time 25 "${header_opts[@]}" "$url")" || {
    echo "  note: request failed" >> "$REPORT"
    return
  }

  # Pull id and CVSS (if avaiable)
  echo "$resp" | jq -r '
    .vulnerabilities[]?.cve as $c |
    [$c.id,
     ( $c.metrics.cvssMetricV31[0].cvssData.baseScore // $c.metrics.cvssMetricV30[0].cvssData.baseScore // empty )
    ] | @tsv
  ' | awk 'NF{print}' | sort -k2,2nr 2>/dev/null | head -n 10 | while IFS=$'\t' read -r cve score; do
      if [ -n "$score" ]; then
        echo "  " "$cve" "$score" >> "$REPORT"
      else
        echo "  " "$cve" >> "$REPORT"
      fi
    done

  echo >> "$REPORT"
  sleep 1
}

write_recommendations() {
  {
    echo "4) Recommendations"
    echo
    echo "- Close unneeded services"
    echo "- Restrict by source IP"    echo "- Update software and firmware"
    echo "- Apply vendor patches"
    echo "- Enforce strong passwords and MFA"
    echo "- Remove default accounts and pages"
    echo "- Enable logging and review it"
    echo "- Place services behind a firewall"
    echo "- Use least privilege"
    echo "- Schedule regular scans"
    echo
  } >> "$REPORT"
}

write_header
echo "[info] Scanning. Output goes to $REPORT"
run_nmap_services
run_nmap_os
run_nmap_vuln
write_recommendations

echo "Report saved to $REPORT"
echo "View with: less $REPORT"


