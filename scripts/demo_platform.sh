#!/bin/bash
# Demo script for SBOM Security Platform
# Shows complete workflow from upload to compliance report

set -e

BASE_URL="${API_URL:-http://localhost:8000}"
SBOM_FILE="${1:-examples/sboms/log4shell-cyclonedx.json}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SBOM Security Platform - Complete Demo                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if API is running
echo "🔍 Checking API health..."
if ! curl -s "${BASE_URL}/health" > /dev/null; then
    echo "❌ ERROR: API is not running at ${BASE_URL}"
    echo "   Start it with: docker-compose up -d"
    exit 1
fi
echo "✅ API is healthy"
echo ""

# Step 1: Upload SBOM
echo "📤 Step 1: Uploading SBOM..."
UPLOAD_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/sboms/upload" \
    -F "file=@${SBOM_FILE}")

SBOM_ID=$(echo "$UPLOAD_RESPONSE" | grep -o '"sbom_id":[0-9]*' | cut -d':' -f2)

if [ -z "$SBOM_ID" ]; then
    echo "❌ Failed to upload SBOM"
    echo "$UPLOAD_RESPONSE"
    exit 1
fi

SBOM_NAME=$(echo "$UPLOAD_RESPONSE" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
COMP_COUNT=$(echo "$UPLOAD_RESPONSE" | grep -o '"components_count":[0-9]*' | cut -d':' -f2)

echo "✅ SBOM uploaded successfully!"
echo "   ID: $SBOM_ID"
echo "   Name: $SBOM_NAME"
echo "   Components: $COMP_COUNT"
echo ""

# Step 2: Get SBOM details
echo "📋 Step 2: Retrieving SBOM details..."
SBOM_DETAILS=$(curl -s "${BASE_URL}/api/v1/sboms/${SBOM_ID}")
echo "✅ SBOM details retrieved"
echo "$SBOM_DETAILS" | python3 -m json.tool | head -20
echo ""

# Step 3: Get components
echo "📦 Step 3: Listing components..."
COMPONENTS=$(curl -s "${BASE_URL}/api/v1/sboms/${SBOM_ID}/components")
echo "✅ Components retrieved"
echo "$COMPONENTS" | python3 -m json.tool | head -30
echo ""

# Step 4: SLSA Compliance Check
echo "🔐 Step 4: Validating SLSA compliance..."
SLSA_RESULT=$(curl -s "${BASE_URL}/api/v1/compliance/${SBOM_ID}/slsa")
SLSA_LEVEL=$(echo "$SLSA_RESULT" | grep -o '"achieved_level":[0-9]*' | cut -d':' -f2)

echo "✅ SLSA Validation Complete"
echo "   Achieved Level: ${SLSA_LEVEL:-0}"
echo ""

# Step 5: NTIA Compliance Check
echo "📝 Step 5: Validating NTIA minimum elements..."
NTIA_RESULT=$(curl -s "${BASE_URL}/api/v1/compliance/${SBOM_ID}/ntia")
NTIA_COMPLIANT=$(echo "$NTIA_RESULT" | grep -o '"compliant":(true|false)' | cut -d':' -f2)
NTIA_PCT=$(echo "$NTIA_RESULT" | grep -o '"compliance_percentage":[0-9.]*' | cut -d':' -f2)

echo "✅ NTIA Validation Complete"
echo "   Compliant: ${NTIA_COMPLIANT:-false}"
echo "   Coverage: ${NTIA_PCT:-0}%"
echo ""

# Step 6: Generate HTML Report
echo "📊 Step 6: Generating compliance report..."
curl -s "${BASE_URL}/api/v1/compliance/${SBOM_ID}/report" > "/tmp/sbom_report_${SBOM_ID}.html"

echo "✅ Report generated successfully!"
echo "   Saved to: /tmp/sbom_report_${SBOM_ID}.html"
echo ""

# Step 7: Risk Scoring (optional - requires vulnerability correlation first)
echo "🎯 Step 7: Calculating risk score..."
RISK_RESULT=$(curl -s -X POST "${BASE_URL}/api/v1/risk/score/${SBOM_ID}" || echo '{}')

if echo "$RISK_RESULT" | grep -q "risk_score"; then
    RISK_SCORE=$(echo "$RISK_RESULT" | grep -o '"risk_score":[0-9.]*' | cut -d':' -f2)
    RISK_LEVEL=$(echo "$RISK_RESULT" | grep -o '"risk_level":"[^"]*"' | cut -d'"' -f4)
    echo "✅ Risk Score: ${RISK_SCORE:-N/A}/10 (${RISK_LEVEL:-unknown})"
else
    echo "⚠️  Risk scoring requires vulnerability correlation"
    echo "   Run: curl -X POST ${BASE_URL}/api/v1/vulnerabilities/correlate/<component_id>"
fi
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Demo Complete! Summary:                                     ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  SBOM ID:           $SBOM_ID                                 "
echo "║  Components:        $COMP_COUNT                              "
echo "║  SLSA Level:        ${SLSA_LEVEL:-0}                         "
echo "║  NTIA Compliant:    ${NTIA_COMPLIANT:-false}                 "
echo "║  Report:            /tmp/sbom_report_${SBOM_ID}.html         "
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "💡 Next Steps:"
echo "   1. Open report: xdg-open /tmp/sbom_report_${SBOM_ID}.html"
echo "   2. View API docs: open ${BASE_URL}/docs"
echo "   3. Correlate vulnerabilities: curl -X POST ${BASE_URL}/api/v1/vulnerabilities/correlate/<component_id>"
echo ""
