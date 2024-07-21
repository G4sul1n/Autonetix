#!/bin/bash

# Declare variables
# Modify next line if necessary
MyAXURL="https://localhost:3443/api/v1"
# Add your API key in the next line
MyAPIKEY=""
FullScanProfileID="11111111-1111-1111-1111-111111111111"

# Arrays to store target and scan IDs
MyTargetIDs=()
MyScanIDs=()
MyScanVulnerabilities=""

# Functions
display_banner() {
    echo "____________  ____________________   ____________________________  __"
    echo "___    |_  / / /__  __/_  __ \__  | / /__  ____/__  __/___  _/_  |/ /"
    echo "__  /| |  / / /__  /  _  / / /_   |/ /__  __/  __  /   __  / __    / "
    echo "_  ___ / /_/ / _  /   / /_/ /_  /|  / _  /___  _  /   __/ /  _    |  "
    echo "/_/  |_\____/  /_/    \____/ /_/ |_/  /_____/  /_/    /___/  /_/|_|  "
    echo "                                                                     "
    echo "                   Created by g4su"
    echo ""
}

usage() {
    echo "Usage: $0 -d <domain1.com>,<domain2.com>,..."
    echo "       $0 -d domain1.com, domain2.com, domain3.com"
    echo "       $0 -h"
    echo ""
    echo "Options:"
    echo "  -d   Comma-separated list of domains to enumerate and scan"
    echo "  -h   Show this help message"
    exit 1
}

cleanup(){
    # Try to obtain and display vulnerabilities even if the scan is aborted
    obtain_and_display_vulnerabilities

    # Delete scans
    for id in "${MyScanIDs[@]}"; do
        curl -sS -k -X DELETE "$MyAXURL/scans/$id" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY" > /dev/null
    done

    # Delete targets
    for id in "${MyTargetIDs[@]}"; do
        curl -sS -k -X DELETE "$MyAXURL/targets/$id" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY" > /dev/null
    done
}

obtain_and_display_vulnerabilities(){
    # Ensure we have a valid scan result ID before proceeding
    for id in "${MyScanIDs[@]}"; do
        MyScanResultID=$(curl -sS -k -X GET "$MyAXURL/scans/$id/results" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY" | jq -r '.results[0].result_id')
        if [[ -n "$MyScanResultID" && "$MyScanResultID" != "null" ]]; then
            # Obtain vulnerabilities
            MyScanVulnerabilities+=$(curl -sS -k -X GET "$MyAXURL/scans/$id/results/$MyScanResultID/vulnerabilities" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY")
        else
            echo "Failed to obtain a valid scan result ID for scan ID: $id."
        fi
    done

    # Display vulnerabilities
    display_vulnerabilities
}

display_vulnerabilities(){
    echo
    echo "Scan Vulnerabilities"
    echo "===================="
    echo

    # Define colors
    GREEN='\033[0;32m'
    NC='\033[0m' # No color

    # Table header
    printf "${GREEN}%-40s %-12s %-12s %-50s${NC}\n" "Affected URL" "Severity" "Confidence" "Vulnerability Name"

    # Function to convert numerical severity to text based on Acunetix documentation
    convert_criticality() {
        case $1 in
            0) echo "informational" ;;
            1) echo "low" ;;
            2) echo "medium" ;;
            3) echo "high" ;;
            4) echo "critical" ;;
            *) echo "unknown" ;;
        esac
    }

    # Process vulnerabilities and display them in a table
    echo "$MyScanVulnerabilities" | jq -r '.vulnerabilities[] | [.vt_name, (.severity|tostring), .confidence, .affects_url] | @tsv' | while IFS=$'\t' read -r name severity confidence url; do
        severity_text=$(convert_criticality $severity)
        echo "$severity,$url,$severity_text,$confidence,$name"
    done | sort -t',' -k1,1nr | awk -F',' '{printf "%-40s %-12s %-12s %-50s\n", $2, $3, $4, $5}'
}

# Display the banner
display_banner

# Process command-line arguments manually
for arg in "$@"; do
  case $arg in
    -d)
      shift
      # Concatenate all remaining arguments into a single string
      domains_input="$*"
      break
      ;;
    -h)
      usage
      ;;
    *)
      ;;
  esac
done

# Check if domains were provided
if [ -z "$domains_input" ]; then
  usage
fi

# Remove spaces before and after commas
formatted_domains=$(echo "$domains_input" | sed 's/ *, */,/g')

# Split comma-separated domains and store them in an array
IFS=',' read -ra domains <<< "$formatted_domains"

# Iterate over each domain to enumerate subdomains and create scan targets
for domain in "${domains[@]}"; do
  # Use sublist3r to enumerate subdomains and store only the subdomain names in a variable
  subdomains_sublist=$(sublist3r -d $domain -n | awk '/[a-zA-Z0-9]+\.'$domain'/{print $1}')

  # Use aquatone-discover to enumerate subdomains and store only the subdomain names in a variable
  subdomains_aquatone=$(aquatone-discover -d $domain -t 25 | grep -oP '([a-zA-Z0-9._-]+\.)+[a-zA-Z]{2,}' | grep -v -E '(png|jpg|jpeg|gif|txt|json)$' | grep -v 'google.com' | sed 's/^1m//' | sort -u)

  # Combine and store the unique subdomains from both tools
  unique_subdomains=$(echo -e "$subdomains_aquatone\n$subdomains_sublist" | sort -u)

  # Print the found subdomains to the screen
  echo "Subdomains found for $domain:"
  echo "$unique_subdomains"

  # Add subdomains as scan targets
  for subdomain in $unique_subdomains; do
    MyTargetID=$(curl -sS -k -X POST "$MyAXURL/targets" -H "Content-Type: application/json" -H "X-Auth: $MyAPIKEY" --data "{\"address\":\"$subdomain\",\"description\":\"Subdomain of $domain\",\"type\":\"default\",\"criticality\":10}" | jq -r '.target_id')
    MyTargetIDs+=("$MyTargetID")
  done
done

# Start scans for each scan target
for id in "${MyTargetIDs[@]}"; do
  MyScanID=$(curl -sS -k -X POST "$MyAXURL/scans" -H "Content-Type: application/json" -H "X-Auth: $MyAPIKEY" --data "{\"profile_id\":\"$FullScanProfileID\",\"incremental\":false,\"schedule\":{\"disable\":false,\"start_date\":null,\"time_sensitive\":false},\"user_authorized_to_scan\":\"yes\",\"target_id\":\"$id\"}" | jq -r '.scan_id')
  MyScanIDs+=("$MyScanID")
done

# Check scan status and wait for completion
for id in "${MyScanIDs[@]}"; do
  while true; do
    MyScanStatus=$(curl -sS -k -X GET "$MyAXURL/scans/$id" -H "Accept: application/json" -H "X-Auth: $MyAPIKEY")

    if [[ "$MyScanStatus" == *"\"status\": \"processing\""* ]]; then
      echo "Scan status: Processing - waiting 30 seconds"
    elif [[ "$MyScanStatus" == *"\"status\": \"scheduled\""* ]]; then
      echo "Scan status: Scheduled - waiting 30 seconds"
    elif [[ "$MyScanStatus" == *"\"status\": \"completed\""* ]]; then
      echo "Scan status: Completed"
      # Get scan result ID
      MyScanResultID=$(echo "$MyScanStatus" | jq -r '.current_session_id')
      # Exit the loop
      break
    else
      echo "Invalid scan status: Aborting"
      # Cleanup and exit the script
      cleanup
      exit 1
    fi
    sleep 30
  done
done

# Final cleanup
cleanup
