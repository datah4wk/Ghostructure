#!/bin/bash
# Ghostructure — Response Uniformity Verification Script
# Tests that all subdomains return identical responses
#
# Usage: ./verify-uniformity.sh [domain]
# Example: ./verify-uniformity.sh example.com

DOMAIN="${1:-example.com}"
SUBS="admin staging test db api jenkins grafana vault wiki mail vpn dev prod fake nonexistent randomstring123"

echo "Testing subdomain response uniformity for *.${DOMAIN}"
echo "=================================================="
echo ""

FIRST_CODE=""
FIRST_SIZE=""
PASS=0
FAIL=0

for sub in $SUBS; do
  RESULT=$(curl -sk "https://${sub}.${DOMAIN}/" \
    -w "%{http_code} %{size_download} %{time_total}" \
    -o /dev/null 2>/dev/null)

  CODE=$(echo "$RESULT" | awk '{print $1}')
  SIZE=$(echo "$RESULT" | awk '{print $2}')
  TIME=$(echo "$RESULT" | awk '{print $3}')

  if [ -z "$FIRST_CODE" ]; then
    FIRST_CODE="$CODE"
    FIRST_SIZE="$SIZE"
  fi

  if [ "$CODE" = "$FIRST_CODE" ] && [ "$SIZE" = "$FIRST_SIZE" ]; then
    STATUS="PASS"
    PASS=$((PASS + 1))
  else
    STATUS="FAIL"
    FAIL=$((FAIL + 1))
  fi

  printf "  %-20s %s %sB %ss [%s]\n" "${sub}:" "$CODE" "$SIZE" "$TIME" "$STATUS"
done

echo ""
echo "=================================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo "All responses are identical. Zero signal leakage."
else
  echo "WARNING: Response differences detected! Investigate non-uniform responses."
  exit 1
fi
