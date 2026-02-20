#!/bin/bash
# Manual verification script for Pi-hole config passthrough API
# Run this against a real Pi-hole v6 instance to verify the PATCH /api/config/{key} endpoint works

set -e

PIHOLE_URL="${PIHOLE_URL:-https://pihole.local}"
PIHOLE_PASSWORD="${PIHOLE_PASSWORD:-admin}"

echo "==> Verifying Pi-hole config API against: $PIHOLE_URL"
echo

# Step 1: Authenticate
echo "[1/4] Authenticating..."
SID=$(curl -ks -X POST "$PIHOLE_URL/api/auth" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"$PIHOLE_PASSWORD\"}" \
  | grep -o '"sid":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SID" ]; then
  echo "❌ Authentication failed. Check PIHOLE_URL and PIHOLE_PASSWORD."
  exit 1
fi
echo "✅ Authenticated (SID: ${SID:0:10}...)"
echo

# Step 2: Read current config
echo "[2/4] Reading current dns.queryLogging value..."
CURRENT=$(curl -ks "$PIHOLE_URL/api/config/dns.queryLogging" \
  -H "X-FTL-SID: $SID" \
  | grep -o '"value":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
echo "Current value: $CURRENT"
echo

# Step 3: Set a test value
NEW_VALUE=$([ "$CURRENT" = "true" ] && echo "false" || echo "true")
echo "[3/4] Setting dns.queryLogging to $NEW_VALUE..."
PATCH_RESPONSE=$(curl -ks -X PATCH "$PIHOLE_URL/api/config/dns.queryLogging" \
  -H "Content-Type: application/json" \
  -H "X-FTL-SID: $SID" \
  -d "{\"value\":\"$NEW_VALUE\"}" \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$PATCH_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
BODY=$(echo "$PATCH_RESPONSE" | grep -v "HTTP_CODE:")

if [ "$HTTP_CODE" != "200" ]; then
  echo "❌ PATCH request failed with HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi
echo "✅ PATCH successful (HTTP 200)"
echo

# Step 4: Verify the change stuck
echo "[4/4] Verifying the change..."
VERIFY=$(curl -ks "$PIHOLE_URL/api/config/dns.queryLogging" \
  -H "X-FTL-SID: $SID" \
  | grep -o '"value":"[^"]*"' | cut -d'"' -f4)

if [ "$VERIFY" = "$NEW_VALUE" ]; then
  echo "✅ Config change verified! dns.queryLogging is now $VERIFY"
else
  echo "❌ Verification failed. Expected $NEW_VALUE, got $VERIFY"
  exit 1
fi
echo

# Step 5: Restore original value
echo "[5/5] Restoring original value..."
curl -ks -X PATCH "$PIHOLE_URL/api/config/dns.queryLogging" \
  -H "Content-Type: application/json" \
  -H "X-FTL-SID: $SID" \
  -d "{\"value\":\"$CURRENT\"}" \
  -w "\nHTTP_CODE:%{http_code}" > /dev/null
echo "✅ Restored to original value: $CURRENT"
echo

echo "==================================="
echo "✅ All checks passed!"
echo "The Pi-hole config API works as expected."
echo "==================================="
