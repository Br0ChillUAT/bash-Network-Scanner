# Project Title: Final Project: Shell Script Security Scanner

# Network Vulnerability Scanner and Report Generator

# Overview:
Input
To begin, provide a target IP address or hostname as the script’s first argument. The script uses set -euo pipefail for greater reliability:
•	-e: Exits immediately if any command fails.
•	-u: Treats unset variables as errors, preventing mistakes due to typos or omissions.
•	-o pipefail: Ensures the pipeline’s failure status reflects all commands, not just the last.
Required Tools
The script relies on nmap for scanning, with options for service detection and OS guessing. It utilizes the -sV and -O flags, along with vulnerability scanning scripts. Tool such as nMap, curl and jq might be avaible and need() will identify missing and then can apt-get install for correct.
Scanning with nmap
The script executes nmap with:
•	Service detection
•	OS guessing
•	Vulnerability scripts
Vulnerability Identification Process
•	Parses open ports and banners from nmap output.
Input
To begin, provide a target IP address or hostname as the script’s first argument. The script uses set -euo pipefail for greater reliability:
•	-e: Exits immediately if any command fails.
•	-u: Treats unset variables as errors, preventing mistakes due to typos or omissions.
•	-o pipefail: Ensures the pipeline’s failure status reflects all commands, not just the last.
Required Tools
The script relies on nmap for scanning, with options for service detection and OS guessing. It utilizes the -sV and -O flags, along with vulnerability scanning scripts. Tool such as nMap, curl and jq might be avaible and need() will identify missing and then can apt-get install for correct.
Scanning with nmap
The script executes nmap with:
•	Service detection
•	OS guessing
•	Vulnerability scripts
Vulnerability Identification Process
•	Parses open ports and banners from nmap output.
•	Extracts of product and version details where possible.
•	Queries the NVD using product and version information.
•	Reports include CVE IDs, scores, and summaries.
•	NSE script results are stored separately, then merged into the report.
Error Handling
•	Script exits if errors occur by using set -euo pipefail.
•	Missing tool detection provides clear messaging (e.g., for nmap, curl, or jq).
•	Network failures when fetching NVD data are skipped gracefully.
•	The scan process uses true to avoid halting on partial NSE errors.



Report on Structure
Each report includes:
•	Header with target and timestamp
•	Open ports and services
•	Potential vulnerabilities from the NVD
•	Findings from nmap NSE vulnerability scripts
•	Practical recommendations, when identified post scan
Limitations
•	Hosts with locked-down services may yield fewer than eight positives, which is normal and highlights security measures like firewalls or closed ports. Using scanme.nmap.org and using 127.0.01 did reflect what was viewable when conducting tests.
•	NSE vulnerability script results vary depending on service exposure and privileges.
Explanation of nmap Flags
•	-sV: Enables service and version detection
•	-O: Attempts to guess the operating system
•	--script vuln: Runs the default set of vulnerability scripts
•	--version-intensity 7: Makes version probing more aggressive
•	--reason: Shows the reasoning behind a host or port state
•	-Pn: Skips host discovery, forcing scanning
Vulnerability Identification Approach
•	Open port and banner information are used to derive product and version pairs.
•	The script queries the NVD for matching CVEs.
•	NSE vulnerability scripts test live services for known weaknesses.
•	The report presents both sets of findings for cross-reference.
Extracts of product and version details where possible.
•	Queries the NVD using product and version information.
•	Reports include CVE IDs, scores, and summaries.
•	NSE script results are stored separately, then merged into the report.
Error Handling
•	Script exits if errors occur by using set -euo pipefail.
•	Missing tool detection provides clear messaging (e.g., for nmap, curl, or jq).
•	Network failures when fetching NVD data are skipped gracefully.
•	The scan process uses true to avoid halting on partial NSE errors.

Report on Structure
Each report includes:
•	Header with target and timestamp
•	Open ports and services
•	Potential vulnerabilities from the NVD
•	Findings from nmap NSE vulnerability scripts
•	Practical recommendations, when identified post scan
Limitations
•	Hosts with locked-down services may yield fewer than eight positives, which is normal and highlights security measures like firewalls or closed ports. Using scanme.nmap.org and using 127.0.01 did reflect what was viewable when conducting tests.
•	NSE vulnerability script results vary depending on service exposure and privileges.
Explanation of nmap Flags
•	-sV: Enables service and version detection
•	-O: Attempts to guess the operating system
•	--script vuln: Runs the default set of vulnerability scripts
•	--version-intensity 7: Makes version probing more aggressive
•	--reason: Shows the reasoning behind a host or port state
•	-Pn: Skips host discovery, forcing scanning
Vulnerability Identification Approach
•	Open port and banner information are used to derive product and version pairs.
•	The script queries the NVD for matching CVEs.
•	NSE vulnerability scripts test live services for known weaknesses.
•	The report presents both sets of findings for cross-reference.
 

# Purpose/Learning:
Implement lesson learned into a more polished product.

# Current Status:
Completed, yet feel that more may be done. 

# Future Goals:
Take skill learned and keep applying into other possible sh. or venture out to python. 

# NOTE v7:

None
