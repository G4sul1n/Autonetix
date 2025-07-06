#!/bin/bash
#
#  Autonetix – Sub-domain Enumeration + Acunetix Scanning
#
#  CLI
#  ──────────────────────────────────────────────────────────
#   -d <domains>    Comma-separated main domains (spaces allowed)
#   -t 1-4        Speed: 1 sequential · 2 slow · 3 moderate · 4 fast (default)
#   -c            Delete scans & targets on exit / CTRL-C
#   -o <file>     Export findings to <file>.txt
#   -h            Show help
#
#  What it does
#  ──────────────────────────────────────────────────────────
#   • Sub-domain discovery (Sublist3r + Subfinder).
#   • One Acunetix target per host.
#   • Chooses scan speed, launches Full Scans, polls every 30 s.
#   • Shows a vulnerability table sorted by criticality (critical → info),
#   • Optionally exports the same table to TXT.
#   • Cleans up only if the –c flag is present.
#
###################################################################

############################
# Static configuration     #
############################
AX_URL="https://localhost:3443/api/v1"
AX_KEY="" # Add your API KEY here
FULL_SCAN_PROFILE="11111111-1111-1111-1111-111111111111"

############################
# Runtime variables        #
############################
SPEED_OPT=4
SCAN_SPEED="fast"
DO_CLEANUP=0
OUTPUT_FILE=""

TARGET_IDS=()
SCAN_IDS=()
SCAN_VULNS=""
declare -A SUB_ROOT

############################
# Helper functions         #
############################
banner() { cat <<'EOF'
____________  ____________________   ____________________________  __
___    |_  / / /__  __/_  __ \__  | / /__  ____/__  __/___  _/_  |/ /
__  /| |  / / /__  /  _  / / /_   |/ /__  __/  __  /   __  / __    /
_  ___ / /_/ / _  /   / /_/ /_  /|  / _  /___  _  /   __/ /  _    |
/_/  |_\____/  /_/    \____/ /_/ |_/  /_____/  /_/    /___/  /_/|_|
                                                                   
                  Created by g4sul1n
EOF
echo; }

usage() {
  echo "Usage: $0 -d <domain[, domain2, ...]> [-t 1-4] [-c] [-o name[.txt]]"
  echo
  echo "  -d   Main domains (spaces after commas are fine)"
  echo "  -t   Speed: 1 sequential | 2 slow | 3 moderate | 4 fast (default)"
  echo "  -c   Delete scans & targets on exit / CTRL-C"
  echo "  -o   Export findings to TXT (extension auto-added if missing)"
  echo "  -h   Show this help"
  exit 1
}

#####################################
# Clean-up (only if –c)             #
#####################################
cleanup() {
  collect_and_print_vulns
  (( DO_CLEANUP )) || return
  for id in "${SCAN_IDS[@]}";   do curl -sSk -X DELETE "$AX_URL/scans/$id"   -H "X-Auth: $AX_KEY" >/dev/null; done
  for id in "${TARGET_IDS[@]}"; do curl -sSk -X DELETE "$AX_URL/targets/$id" -H "X-Auth: $AX_KEY" >/dev/null; done
}

abort_handler() {
  echo "Aborting all scans..."
  for id in "${SCAN_IDS[@]}"; do
      curl -sSk -X POST "$AX_URL/scans/$id/abort" -H "X-Auth: $AX_KEY" >/dev/null
  done
  cleanup
  exit 1
}

#####################################
# Vulnerability reporting           #
#####################################
sev_txt(){ case $1 in 4)echo critical;;3)echo high;;2)echo medium;;1)echo low;;0)echo informational;;*)echo unknown;;esac; }

print_vulns_table() {
  echo; echo "Scan Vulnerabilities (sorted by severity)"; echo "========================================="; echo
  GREEN='\033[0;32m'; NC='\033[0m'
  printf "${GREEN}%-65s %-16s  %-12s %-50s${NC}\n" "Affected URL" "Severity" "Confidence" "Vulnerability Name"

  # Convert to TSV → sort by severity numeric (field #2) desc → pretty print
  echo "$SCAN_VULNS" \
    | jq -r '.vulnerabilities[] | [.affects_url, (.severity|tostring), .confidence, .vt_name] | @tsv' \
    | sort -t$'\t' -k2,2nr \
    | while IFS=$'\t' read -r url sev conf name; do
        printf "%-65s %-16s  %-12s %-50s\n" "$url" "$(sev_txt "$sev")" "$conf" "$name"
      done

  [[ -n $OUTPUT_FILE ]] && export_vulns_to_file
}

export_vulns_to_file() {
  local file="$OUTPUT_FILE"; [[ $file != *.txt ]] && file="${file}.txt"
  printf "%-65s %-16s  %-12s %-50s\n" "Affected URL" "Severity" "Confidence" "Vulnerability Name" > "$file"

  echo "$SCAN_VULNS" \
    | jq -r '.vulnerabilities[] | [.affects_url, (.severity|tostring), .confidence, .vt_name] | @tsv' \
    | sort -t$'\t' -k2,2nr \
    | while IFS=$'\t' read -r url sev conf name; do
        printf "%-65s %-16s  %-12s %-50s\n" "$url" "$(sev_txt "$sev")" "$conf" "$name"
      done >> "$file"
  echo "[*] Findings exported to $file"
}

collect_and_print_vulns() {
  for id in "${SCAN_IDS[@]}"; do
      res=$(curl -sSk "$AX_URL/scans/$id/results" -H "X-Auth: $AX_KEY" | jq -r '.results[0].result_id')
      [[ -n $res && $res != null ]] && \
      SCAN_VULNS+=$(curl -sSk "$AX_URL/scans/$id/results/$res/vulnerabilities" -H "X-Auth: $AX_KEY")
  done
  print_vulns_table
}

#####################################
# Main                               #
#####################################
banner
trap abort_handler INT

# ── 1. CLI parsing ────────────────────────────────────────────────
DOMAINS_RAW=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) shift; while [[ $# -gt 0 && "$1" != -* ]]; do DOMAINS_RAW+="$1 "; shift; done ;;
    -t) shift; SPEED_OPT="$1"; shift ;;
    -c) DO_CLEANUP=1; shift ;;
    -o) shift; OUTPUT_FILE="$1"; shift ;;
    -h) usage ;;
     *) shift ;;
  esac
done
[[ -z "$DOMAINS_RAW" ]] && usage
DOMAINS=$(echo "$DOMAINS_RAW" | tr -d ' ' | sed 's/^,*//;s/,*$//;s/,,*/,/g')

case "$SPEED_OPT" in
  1) SCAN_SPEED="sequential";;
  2) SCAN_SPEED="slow";;
  3) SCAN_SPEED="moderate";;
  4) SCAN_SPEED="fast";;
  *) echo "Invalid value for -t (use 1-4)"; exit 1;;
esac

[[ -n $OUTPUT_FILE ]] && echo "[*] Export file name     : $OUTPUT_FILE"
echo "[*] Domains to scan      : $DOMAINS"
echo "[*] Selected scan speed  : $SCAN_SPEED"
echo "[*] Auto-cleanup enabled : $( ((DO_CLEANUP)) && echo yes || echo no )"

# ── 2. Sub-domain enumeration ────────────────────────────────────
IFS=',' read -ra ROOTS <<< "$DOMAINS"
COMBINED=()

for root in "${ROOTS[@]}"; do
  [[ $(command -v sublist3r) ]] && s1=$(sublist3r -d "$root" -n --threads 1 2>/dev/null | awk -v d="$root" 'tolower($0)~("[a-z0-9._-]+\\."d"$"){print $1}')
  [[ $(command -v subfinder)  ]] && s2=$(subfinder  -d "$root" -silent 2>/dev/null | awk -v d="$root" 'tolower($0)~("[a-z0-9._-]+\\."d"$")')
  uniq=$(echo -e "$root\n$s1\n$s2" | sort -u)
  COMBINED+=($uniq)
  for s in $uniq; do SUB_ROOT["$s"]="$root"; done
  echo "Sub-domains found for $root:"; echo "$uniq"
done
COMBINED=($(printf "%s\n" "${COMBINED[@]}" | sort -u))

# ── 3. Target creation & speed patch ─────────────────────────────
for sub in "${COMBINED[@]}"; do
  root=${SUB_ROOT["$sub"]}
  tid=$(curl -sSk -X POST "$AX_URL/targets" \
        -H "Content-Type: application/json" -H "X-Auth: $AX_KEY" \
        --data "{\"address\":\"$sub\",\"description\":\"Subdomain of $root\",\"type\":\"default\",\"criticality\":10}" \
        | jq -r '.target_id')
  TARGET_IDS+=("$tid")
  curl -sSk -X PATCH "$AX_URL/targets/$tid/configuration" -H "Content-Type: application/json" -H "X-Auth: $AX_KEY" --data "{\"scan_speed\":\"$SCAN_SPEED\"}" >/dev/null
done

# ── 4. Launch scans ──────────────────────────────────────────────
for tid in "${TARGET_IDS[@]}"; do
  sid=$(curl -sSk -X POST "$AX_URL/scans" \
        -H "Content-Type: application/json" -H "X-Auth: $AX_KEY" \
        --data "{\"profile_id\":\"$FULL_SCAN_PROFILE\",\"incremental\":false,\"schedule\":{\"disable\":false,\"start_date\":null,\"time_sensitive\":false},\"user_authorized_to_scan\":\"yes\",\"target_id\":\"$tid\"}" \
        | jq -r '.scan_id')
  SCAN_IDS+=("$sid")
done

# ── 5. Poll scan status ─────────────────────────────────────────
for sid in "${SCAN_IDS[@]}"; do
  while true; do
    status=$(curl -sSk "$AX_URL/scans/$sid" -H "X-Auth: $AX_KEY" | jq -r '.current_session.status')
    case $status in
      processing) echo "Scan status: Processing  – waiting 30 s" ;;
      scheduled)  echo "Scan status: Scheduled   – waiting 30 s" ;;
      queued)     echo "Scan status: Queued      – waiting 30 s" ;;
      completed)  echo "Scan status: Completed";  break ;;
      failed)     echo "Scan status: Failed";     break ;;
      aborted)    echo "Scan status: Aborted";    break ;;
      *)          echo "Scan status: Unknown";    break ;;
    esac
    sleep 30
  done
done

cleanup   # delete scans/targets only if -c flag present
