#!/usr/bin/env bash
# check_tools.sh — Detect availability of Seraph tool dependencies
# Usage: bash scripts/check_tools.sh

set -euo pipefail

TOOLS=(
  nmap
  nikto
  testssl
  lynis
  openscap
  masscan
  gobuster
  sqlmap
  hydra
  whois
  dig
  theHarvester
  subfinder
  enum4linux
  ffuf
  searchsploit
  aws
)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'
BOLD='\033[1m'

available_count=0
missing_count=0

echo ""
echo -e "${BOLD}Seraph — Tool Availability Check${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "%-20s %-12s %s\n" "TOOL" "STATUS" "PATH / NOTE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for tool in "${TOOLS[@]}"; do
  path=$(command -v "$tool" 2>/dev/null || true)
  if [[ -n "$path" ]]; then
    printf "%-20s ${GREEN}%-12s${RESET} %s\n" "$tool" "FOUND" "$path"
    ((available_count++)) || true
  else
    printf "%-20s ${RED}%-12s${RESET} %s\n" "$tool" "MISSING" "not in PATH"
    ((missing_count++)) || true
  fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}${available_count} available${RESET}   ${RED}${missing_count} missing${RESET}"
echo ""

if [[ $missing_count -gt 0 ]]; then
  echo -e "${YELLOW}Tip:${RESET} Install missing tools with apt/brew/go install."
  echo "     The API endpoint GET /api/v1/settings/tools provides full details."
  echo ""
fi
