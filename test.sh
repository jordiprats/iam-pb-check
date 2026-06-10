#!/bin/bash
set -euo pipefail

BINARY="./dist/iamctl"
TESTDATA="./testdata"
TMPDIR_TEST=$(mktemp -d)

trap 'rm -rf "$TMPDIR_TEST"' EXIT

PASSED=0
FAILED=0

pass() { echo "✅ $1"; PASSED=$((PASSED + 1)); }
fail() { echo "❌ $1"; FAILED=$((FAILED + 1)); }

# -----------------------------------------------------------------------
# Build (if binary doesn't already exist)
# -----------------------------------------------------------------------
if [ ! -x "$BINARY" ]; then
  echo "Building iamctl..."
  go build -o dist/iamctl main.go
fi

VER=$($BINARY -v | head -n1)
if [[ "$VER" == *"iamctl version"* ]]; then
  pass "Version output looks correct: $VER"
else
  fail "Version output looks wrong: $VER"
  exit 1
fi

# -----------------------------------------------------------------------
# Policy validation (JSON output)
# -----------------------------------------------------------------------
echo ""
echo "=== Policy validation (JSON) ==="
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/result.json" || true
ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/result.json")
BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/result.json")
echo "Allowed actions: $ALLOWED"
echo "Blocked actions: $BLOCKED"

EXPECTED_ALLOWED=6
EXPECTED_BLOCKED=3
if [ "$ALLOWED" -ne "$EXPECTED_ALLOWED" ]; then
  fail "Expected $EXPECTED_ALLOWED allowed actions, got $ALLOWED"
else
  pass "Allowed count correct ($ALLOWED)"
fi
if [ "$BLOCKED" -ne "$EXPECTED_BLOCKED" ]; then
  fail "Expected $EXPECTED_BLOCKED blocked actions, got $BLOCKED"
else
  pass "Blocked count correct ($BLOCKED)"
fi

# -----------------------------------------------------------------------
# Table output format
# -----------------------------------------------------------------------
echo ""
echo "=== Table output format ==="
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output table "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/table_out.txt" || true
grep -q "ALLOWED" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table output has ALLOWED column" \
  || fail "Table output missing ALLOWED column"
grep -q "BLOCKED" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table output has BLOCKED column" \
  || fail "Table output missing BLOCKED column"
grep -q "ec2:DescribeInstances" "$TMPDIR_TEST/table_out.txt" \
  && pass "Table has expected action" \
  || fail "Table missing expected action"

# -----------------------------------------------------------------------
# Single action check — allowed actions
# -----------------------------------------------------------------------
echo ""
echo "=== check-action — allowed ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances correctly allowed" \
  || fail "ec2:DescribeInstances should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" s3:GetObject \
  && pass "s3:GetObject correctly allowed" \
  || fail "s3:GetObject should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" iam:GetUser \
  && pass "iam:GetUser correctly allowed" \
  || fail "iam:GetUser should be allowed"

# -----------------------------------------------------------------------
# Single action check — blocked actions
# -----------------------------------------------------------------------
echo ""
echo "=== check-action — blocked ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" ec2:RunInstances \
  && fail "ec2:RunInstances should be blocked" \
  || pass "ec2:RunInstances correctly blocked"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" iam:CreateRole \
  && fail "iam:CreateRole should be blocked" \
  || pass "iam:CreateRole correctly blocked"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" s3:PutObject \
  && fail "s3:PutObject should be blocked" \
  || pass "s3:PutObject correctly blocked"

# -----------------------------------------------------------------------
# Simple pattern matching
# -----------------------------------------------------------------------
echo ""
echo "=== Simple pattern matching ==="
"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances matches ec2:Describe*" \
  || fail "Pattern ec2:Describe* should match ec2:DescribeInstances"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:DescribeSecurityGroups \
  && pass "ec2:DescribeSecurityGroups matches ec2:Describe*" \
  || fail "Pattern ec2:Describe* should match ec2:DescribeSecurityGroups"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" s3:GetObject \
  && pass "s3:GetObject matches s3:Get*" \
  || fail "Pattern s3:Get* should match s3:GetObject"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" kinesis:PutRecord \
  && pass "kinesis:PutRecord matches kinesis:*co*" \
  || fail "Pattern kinesis:*co* should match kinesis:PutRecord"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" ec2:RunInstances \
  && fail "ec2:RunInstances should not match any pattern" \
  || pass "ec2:RunInstances correctly rejected"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" s3:PutObject \
  && fail "s3:PutObject should not match s3:Get*" \
  || pass "s3:PutObject correctly rejected"

# -----------------------------------------------------------------------
# Multi-action check-action
# -----------------------------------------------------------------------
echo ""
echo "=== Multi-action check ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" \
  ec2:DescribeInstances s3:GetObject s3:ListBucket iam:GetUser \
  && pass "All four actions correctly allowed in one invocation" \
  || fail "All four actions should be allowed"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" \
  ec2:DescribeInstances ec2:RunInstances s3:GetObject \
  && fail "Should exit non-zero because ec2:RunInstances is blocked" \
  || pass "Correctly exited non-zero when at least one action is blocked"

"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/multi_json.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/multi_json.json" > /dev/null \
  && pass "JSON summary counts correct" \
  || fail "JSON summary counts wrong"

# -----------------------------------------------------------------------
# stdin support
# -----------------------------------------------------------------------
echo ""
echo "=== stdin support ==="
cat "$TESTDATA/test-pb.json" \
  | "$BINARY" check-action --pb - ec2:DescribeInstances \
  && pass "--pb - (stdin) works for allowed action" \
  || fail "--pb - should work with stdin boundary"

cat "$TESTDATA/test-pb.json" \
  | "$BINARY" check-action --pb - ec2:RunInstances \
  && fail "ec2:RunInstances should still be blocked via stdin boundary" \
  || pass "--pb - correctly blocks action via stdin"

cat "$TESTDATA/test-policy.json" \
  | "$BINARY" check-policy --pb "$TESTDATA/test-pb.json" --output json - > "$TMPDIR_TEST/stdin_policy.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/stdin_policy.json" > /dev/null \
  && pass "Policy file via stdin produces correct counts" \
  || fail "stdin policy file produced wrong counts"

# -----------------------------------------------------------------------
# NotAction in source policy
# -----------------------------------------------------------------------
echo ""
echo "=== NotAction source policy ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-notaction-policy.json" > "$TMPDIR_TEST/notaction_result.json" || true

COUNT=$(jq '.summary.not_action_statements' "$TMPDIR_TEST/notaction_result.json")
if [ "$COUNT" -lt "1" ]; then
  fail "Expected at least 1 not_action_statements entry, got $COUNT"
else
  pass "NotAction statement correctly surfaced: $COUNT entry/entries"
fi

jq -e '.warnings | length > 0' "$TMPDIR_TEST/notaction_result.json" > /dev/null \
  && pass "Warnings array is non-empty" \
  || fail "Warnings array is empty, expected NotAction warning"

jq -r '.warnings[]' "$TMPDIR_TEST/notaction_result.json" | grep -qi "notaction" \
  && pass "NotAction mentioned in warnings" \
  || fail "NotAction not mentioned in warnings"

jq -e '.summary.skipped_deny == 1' "$TMPDIR_TEST/notaction_result.json" \
  && pass "Deny action correctly skipped" \
  || fail "Expected 1 skipped_deny"

"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  "$TESTDATA/test-notaction-policy.json" 2>&1 | tee "$TMPDIR_TEST/notaction_list.txt" || true

grep -qi "notaction\|manual review" "$TMPDIR_TEST/notaction_list.txt" \
  && pass "List output flags NotAction statements for manual review" \
  || fail "NotAction manual review note missing from list output"

# -----------------------------------------------------------------------
# Wildcard actions in source policy
# -----------------------------------------------------------------------
echo ""
echo "=== Wildcard source policy ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-wildcard-policy.json" > "$TMPDIR_TEST/wildcard_result.json" || true

jq -r '.warnings[]' "$TMPDIR_TEST/wildcard_result.json" | grep -qi "wildcard" \
  && pass "Wildcard warning present" \
  || fail "Wildcard warning missing"

W_ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/wildcard_result.json")
W_BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/wildcard_result.json")
echo "Wildcard policy: allowed=$W_ALLOWED blocked=$W_BLOCKED"

# s3:* and ec2:Describe* overlap with NotAction entries → 3 allowed (both wildcards + iam:GetUser)
# iam:CreateRole has no match in NotAction → 1 blocked
if [ "$W_ALLOWED" -ne "3" ]; then
  fail "Expected 3 allowed, got $W_ALLOWED"
else
  pass "Wildcard allowed count correct ($W_ALLOWED)"
fi
if [ "$W_BLOCKED" -ne "1" ]; then
  fail "Expected 1 blocked, got $W_BLOCKED"
else
  pass "Wildcard blocked count correct ($W_BLOCKED)"
fi

# -----------------------------------------------------------------------
# Condition and NotResource warnings
# -----------------------------------------------------------------------
echo ""
echo "=== Condition and NotResource warnings ==="
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-conditions-policy.json" > "$TMPDIR_TEST/conditions_result.json" || true

WARNINGS=$(jq '[.warnings[] | ascii_downcase]' "$TMPDIR_TEST/conditions_result.json")

echo "$WARNINGS" | grep -q "condition" \
  && pass "Condition warning present" \
  || fail "Condition warning missing"

echo "$WARNINGS" | grep -q "notresource" \
  && pass "NotResource warning present" \
  || fail "NotResource warning missing"

# -----------------------------------------------------------------------
# --policy-file flag (multi-policy merging)
# -----------------------------------------------------------------------
echo ""
echo "=== --policy-file flag ==="

# Single --policy-file (same as positional arg)
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-policy.json" \
  --output json > "$TMPDIR_TEST/pf_single.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 3' "$TMPDIR_TEST/pf_single.json" > /dev/null \
  && pass "--policy-file works as sole policy source" \
  || fail "--policy-file sole source counts wrong"

# --policy-file combined with positional arg (actions merged, deduplicated)
# test-policy.json:  ec2:DescribeInstances, ec2:DescribeSecurityGroups, ec2:CreateTags,
#                    ec2:RunInstances, s3:GetObject, s3:PutObject, s3:ListBucket,
#                    iam:GetUser, iam:CreateRole  (6 allowed, 3 blocked)
# test-extra-policy.json: s3:GetObject, s3:ListBucket (overlap),
#                         logs:DescribeLogGroups, logs:CreateLogStream (new, both blocked)
# Merged: original 9 + 2 new = 11 unique. Allowed: 6, Blocked: 3+2=5
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-extra-policy.json" \
  --output json \
  "$TESTDATA/test-policy.json" > "$TMPDIR_TEST/pf_merged.json" || true
MERGED_ALLOWED=$(jq '.summary.allowed' "$TMPDIR_TEST/pf_merged.json")
MERGED_BLOCKED=$(jq '.summary.blocked' "$TMPDIR_TEST/pf_merged.json")
if [ "$MERGED_ALLOWED" -eq 6 ] && [ "$MERGED_BLOCKED" -eq 5 ]; then
  pass "Merged policy counts correct (allowed=$MERGED_ALLOWED blocked=$MERGED_BLOCKED)"
else
  fail "Merged policy counts wrong (expected 6 allowed, 5 blocked; got allowed=$MERGED_ALLOWED blocked=$MERGED_BLOCKED)"
fi

# Verify deduplication — overlapping actions appear only once
jq '[.allowed[], .blocked[]]' "$TMPDIR_TEST/pf_merged.json" | sort | uniq -d > "$TMPDIR_TEST/pf_dups.txt"
if [ ! -s "$TMPDIR_TEST/pf_dups.txt" ]; then
  pass "No duplicate actions in merged output"
else
  fail "Found duplicate actions in merged output"
fi

# Two --policy-file flags (no positional arg)
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb.json" \
  --policy-file "$TESTDATA/test-policy.json" \
  --policy-file "$TESTDATA/test-extra-policy.json" \
  --output json > "$TMPDIR_TEST/pf_two.json" || true
jq -e '.summary.allowed == 6 and .summary.blocked == 5' "$TMPDIR_TEST/pf_two.json" > /dev/null \
  && pass "Two --policy-file flags merged correctly" \
  || fail "Two --policy-file merge counts wrong"

# No policy source at all → should error
"$BINARY" check-policy --pb "$TESTDATA/test-pb.json" 2>"$TMPDIR_TEST/no_source_err.txt" \
  && fail "Should error when no policy source specified" \
  || true
grep -qi "at least one" "$TMPDIR_TEST/no_source_err.txt" \
  && pass "Errors when no policy source specified" \
  || fail "Should error when no policy source specified"

# -----------------------------------------------------------------------
# diff subcommand
# -----------------------------------------------------------------------
echo ""
echo "=== diff subcommand ==="
"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  --output json \
  "$TESTDATA/test-diff-policy.json" > "$TMPDIR_TEST/diff_result.json" || true

GAINED=$(jq '.summary.gained' "$TMPDIR_TEST/diff_result.json")
LOST=$(jq '.summary.lost' "$TMPDIR_TEST/diff_result.json")
UNCHANGED=$(jq '.summary.unchanged' "$TMPDIR_TEST/diff_result.json")

if [ "$GAINED" -ne "2" ]; then
  fail "Expected 2 gained, got $GAINED"
else
  pass "Diff gained count correct ($GAINED)"
fi
if [ "$LOST" -ne "2" ]; then
  fail "Expected 2 lost, got $LOST"
else
  pass "Diff lost count correct ($LOST)"
fi
if [ "$UNCHANGED" -ne "4" ]; then
  fail "Expected 4 unchanged, got $UNCHANGED"
else
  pass "Diff unchanged count correct ($UNCHANGED)"
fi

jq -e '[.gained[]] | contains(["ec2:RunInstances","logs:CreateLogGroup"])' "$TMPDIR_TEST/diff_result.json" \
  && pass "gained list contains expected actions" \
  || fail "gained list wrong: $(jq '.gained' "$TMPDIR_TEST/diff_result.json")"

jq -e '[.lost[]] | contains(["iam:GetUser","s3:PutObject"])' "$TMPDIR_TEST/diff_result.json" \
  && pass "lost list contains expected actions" \
  || fail "lost list wrong: $(jq '.lost' "$TMPDIR_TEST/diff_result.json")"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  "$TESTDATA/test-diff-policy.json" \
  && fail "diff should exit non-zero because access is lost" \
  || pass "diff correctly exits non-zero when access is lost"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-old-pb.json" \
  "$TESTDATA/test-diff-policy.json" \
  && pass "diff exits zero when boundaries are identical (nothing lost)" \
  || fail "diff should exit zero when boundaries are identical"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  --output list \
  "$TESTDATA/test-diff-policy.json" > "$TMPDIR_TEST/diff_list.txt" || true

grep -q "gained\|Newly allowed" "$TMPDIR_TEST/diff_list.txt" \
  && pass "diff list output mentions gained actions" \
  || fail "diff list output missing gained section"

grep -q "lost\|No longer allowed" "$TMPDIR_TEST/diff_list.txt" \
  && pass "diff list output mentions lost actions" \
  || fail "diff list output missing lost section"

"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  "$TESTDATA/test-diff-policy.json" > "$TMPDIR_TEST/diff_unified.txt" || true

grep -q "^--- allowed by:" "$TMPDIR_TEST/diff_unified.txt" \
  && pass "diff unified output has --- header" \
  || fail "diff unified output missing --- header"

grep -q "^+++ allowed by:" "$TMPDIR_TEST/diff_unified.txt" \
  && pass "diff unified output has +++ header" \
  || fail "diff unified output missing +++ header"

grep -q "ec2:RunInstances" "$TMPDIR_TEST/diff_unified.txt" \
  && pass "diff unified output shows gained action" \
  || fail "diff unified output missing ec2:RunInstances"

grep -q "iam:GetUser" "$TMPDIR_TEST/diff_unified.txt" \
  && pass "diff unified output shows lost action" \
  || fail "diff unified output missing iam:GetUser"

"$BINARY" diff --pb "$TESTDATA/test-diff-old-pb.json" "$TESTDATA/test-diff-policy.json" \
  && fail "Should error when --pb-new is missing" \
  || pass "Correctly errors when --pb-new is missing"

# --role and policy file argument are mutually exclusive
"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" \
  --role my-role \
  "$TESTDATA/test-diff-policy.json" 2>"$TMPDIR_TEST/diff_exclusive_err.txt" \
  && fail "diff should error when --role and policy file are both specified" \
  || pass "diff correctly errors when --role and policy file are both specified"

grep -qi "mutually exclusive\|cannot" "$TMPDIR_TEST/diff_exclusive_err.txt" \
  && pass "Error message mentions mutual exclusivity" \
  || fail "Error should mention --role and file are mutually exclusive"

# No policy source → direct PB comparison (source diff mode)
"$BINARY" diff \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --pb-new "$TESTDATA/test-diff-new-pb.json" > "$TMPDIR_TEST/diff_direct_pb.txt" \
  && fail "diff --pb --pb-new (direct) should exit non-zero when differences exist" \
  || pass "diff --pb --pb-new (direct) correctly exits non-zero on differences"

grep -q "s3:PutObject" "$TMPDIR_TEST/diff_direct_pb.txt" \
  && pass "Direct PB diff shows removed action s3:PutObject" \
  || fail "Direct PB diff should show s3:PutObject"

grep -q "ec2:RunInstances" "$TMPDIR_TEST/diff_direct_pb.txt" \
  && pass "Direct PB diff shows added action ec2:RunInstances" \
  || fail "Direct PB diff should show ec2:RunInstances"

# -----------------------------------------------------------------------
# pb-check-cf SARIF output
# -----------------------------------------------------------------------
echo ""
echo "=== pb-check-cf SARIF output ==="

"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output sarif \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_sarif.json" 2>/dev/null || true

# Must be valid JSON
python3 -m json.tool "$TMPDIR_TEST/cf_sarif.json" > /dev/null 2>&1 \
  && pass "SARIF output is valid JSON" \
  || fail "SARIF output is not valid JSON"

# SARIF version field
jq -e '.version == "2.1.0"' "$TMPDIR_TEST/cf_sarif.json" > /dev/null \
  && pass "SARIF version is 2.1.0" \
  || fail "SARIF version field wrong"

# Tool driver name
jq -e '.runs[0].tool.driver.name == "iamctl"' "$TMPDIR_TEST/cf_sarif.json" > /dev/null \
  && pass "SARIF tool driver name is iamctl" \
  || fail "SARIF tool driver name wrong"

# Rules defined
jq -e '[.runs[0].tool.driver.rules[].id] | contains(["PB001","PB002","PB003"])' "$TMPDIR_TEST/cf_sarif.json" > /dev/null \
  && pass "SARIF rules PB001/PB002/PB003 defined" \
  || fail "SARIF rules missing"

# Template file appears as artifact
SARIF_URI=$(jq -r '.runs[0].artifacts[0].location.uri' "$TMPDIR_TEST/cf_sarif.json")
if [[ "$SARIF_URI" == *"test-cf-policies.yaml" ]]; then
  pass "SARIF artifact URI contains template filename"
else
  fail "SARIF artifact URI wrong: $SARIF_URI"
fi

# Two error-level results (s3:PutObject and logs:CreateLogGroup are blocked)
ERROR_COUNT=$(jq '[.runs[0].results[] | select(.level=="error")] | length' "$TMPDIR_TEST/cf_sarif.json")
if [ "$ERROR_COUNT" -eq 2 ]; then
  pass "SARIF has 2 error-level results for blocked actions"
else
  fail "Expected 2 SARIF errors, got $ERROR_COUNT"
fi

# Blocked action names appear in result messages
jq -r '.runs[0].results[].message.text' "$TMPDIR_TEST/cf_sarif.json" | grep -q "s3:PutObject" \
  && pass "SARIF result mentions s3:PutObject" \
  || fail "SARIF result missing s3:PutObject"

jq -r '.runs[0].results[].message.text' "$TMPDIR_TEST/cf_sarif.json" | grep -q "logs:CreateLogGroup" \
  && pass "SARIF result mentions logs:CreateLogGroup" \
  || fail "SARIF result missing logs:CreateLogGroup"

# Each result has a logicalLocation pointing to the CF resource
jq -e '.runs[0].results[0].locations[0].logicalLocations[0].name != null' "$TMPDIR_TEST/cf_sarif.json" > /dev/null \
  && pass "SARIF results have logicalLocations" \
  || fail "SARIF results missing logicalLocations"

# Line numbers present (yaml.Node provides line info)
jq -e '.runs[0].results[0].locations[0].physicalLocation.region.startLine > 0' "$TMPDIR_TEST/cf_sarif.json" > /dev/null \
  && pass "SARIF results include startLine from YAML" \
  || fail "SARIF results missing startLine"

# Exit code 1 when blocked actions present
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output sarif \
  "$TESTDATA/test-cf-policies.yaml" > /dev/null 2>/dev/null \
  && fail "pb-check-cf --output sarif should exit non-zero when blocked" \
  || pass "pb-check-cf --output sarif exits non-zero when blocked"

# Clean template (AnotherRole, all actions allowed) → no error results
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output sarif \
  --resource AnotherRole \
  "$TESTDATA/test-cf-template.yaml" > "$TMPDIR_TEST/cf_sarif_clean.json" 2>/dev/null || true

jq -e '[.runs[0].results[] | select(.level=="error")] | length == 0' "$TMPDIR_TEST/cf_sarif_clean.json" > /dev/null \
  && pass "SARIF has 0 errors for fully-allowed resource" \
  || fail "SARIF should have 0 errors when all actions are allowed"

# -----------------------------------------------------------------------
# --version flag
# -----------------------------------------------------------------------
echo ""
echo "=== --version flag ==="
"$BINARY" --version \
  && pass "--version flag works" \
  || fail "--version flag failed"

"$BINARY" --version | grep -qE "iamctl|version" \
  && pass "Version output looks correct" \
  || fail "Version output missing expected text"

# -----------------------------------------------------------------------
# Multi-service PB: Deny+NotAction style (wildcard false-positive fix)
# -----------------------------------------------------------------------
echo ""
echo "=== Multi-service Deny+NotAction PB ==="

# Specific allowed actions
"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances allowed by multi-service PB" \
  || fail "ec2:DescribeInstances should be allowed by multi-service PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" glue:GetDatabase \
  && pass "glue:GetDatabase allowed by multi-service PB" \
  || fail "glue:GetDatabase should be allowed by multi-service PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" logs:PutLogEvents \
  && pass "logs:PutLogEvents allowed by multi-service PB" \
  || fail "logs:PutLogEvents should be allowed by multi-service PB"

# Specific blocked actions
"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" ec2:RunInstances \
  && fail "ec2:RunInstances should be blocked by multi-service PB" \
  || pass "ec2:RunInstances correctly blocked by multi-service PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" athena:GetQueryResults \
  && fail "athena:GetQueryResults should be blocked (no athena entries in PB)" \
  || pass "athena:GetQueryResults correctly blocked by multi-service PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-multi-service.json" cloudtrail:LookupEvents \
  && fail "cloudtrail:LookupEvents should be blocked (no cloudtrail in PB)" \
  || pass "cloudtrail:LookupEvents correctly blocked by multi-service PB"

# Regression test: wildcard source action must not be falsely blocked when the
# service IS in the Deny+NotAction list (glue:* overlaps with glue entries).
cat > "$TMPDIR_TEST/wildcard-glue-athena.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["glue:*", "athena:*"],
    "Resource": "*"
  }]
}
EOF
"$BINARY" check-policy \
  --pb "$TESTDATA/test-pb-multi-service.json" \
  --output json \
  "$TMPDIR_TEST/wildcard-glue-athena.json" > "$TMPDIR_TEST/wildcard_multi.json" || true

jq -e '.blocked | map(select(startswith("glue:"))) | length == 0' "$TMPDIR_TEST/wildcard_multi.json" \
  && pass "glue:* wildcard not falsely blocked by Deny+NotAction PB (wildcard fix)" \
  || fail "glue:* should not be blocked — wildcard false-positive regression"

jq -e '.blocked | map(select(startswith("athena:"))) | length > 0' "$TMPDIR_TEST/wildcard_multi.json" \
  && pass "athena:* wildcard correctly blocked when service not in PB" \
  || fail "athena:* should be blocked (no athena entries in PB)"

# -----------------------------------------------------------------------
# Allow+NotAction style PB
# -----------------------------------------------------------------------
echo ""
echo "=== Allow+NotAction style PB ==="

"$BINARY" check-action --pb "$TESTDATA/test-pb-allow-notaction.json" s3:GetObject \
  && pass "s3:GetObject allowed by Allow+NotAction PB" \
  || fail "s3:GetObject should be allowed by Allow+NotAction PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-allow-notaction.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances allowed by Allow+NotAction PB" \
  || fail "ec2:DescribeInstances should be allowed by Allow+NotAction PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-allow-notaction.json" iam:CreateRole \
  && fail "iam:CreateRole should be blocked (iam:* in NotAction exclusion)" \
  || pass "iam:CreateRole correctly blocked by Allow+NotAction PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-allow-notaction.json" sts:AssumeRole \
  && fail "sts:AssumeRole should be blocked (explicitly in NotAction exclusion)" \
  || pass "sts:AssumeRole correctly blocked by Allow+NotAction PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-allow-notaction.json" organizations:DescribeOrganization \
  && fail "organizations:DescribeOrganization should be blocked (organizations:* in NotAction)" \
  || pass "organizations:DescribeOrganization correctly blocked by Allow+NotAction PB"

# -----------------------------------------------------------------------
# Simple allow-list PB
# -----------------------------------------------------------------------
echo ""
echo "=== Simple allow-list PB ==="

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" s3:GetObject \
  && pass "s3:GetObject allowed by simple allow-list PB" \
  || fail "s3:GetObject should be allowed by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" s3:PutObject \
  && pass "s3:PutObject allowed by simple allow-list PB" \
  || fail "s3:PutObject should be allowed by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" ec2:DescribeInstances \
  && pass "ec2:DescribeInstances allowed by simple PB (ec2:Describe*)" \
  || fail "ec2:DescribeInstances should be allowed by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" iam:GetRole \
  && pass "iam:GetRole allowed by simple PB (iam:Get*)" \
  || fail "iam:GetRole should be allowed by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" ec2:RunInstances \
  && fail "ec2:RunInstances should be blocked by simple PB" \
  || pass "ec2:RunInstances correctly blocked by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" iam:CreateRole \
  && fail "iam:CreateRole should be blocked (only iam:Get*/List* in simple PB)" \
  || pass "iam:CreateRole correctly blocked by simple PB"

"$BINARY" check-action --pb "$TESTDATA/test-pb-simple-allow.json" athena:GetQueryResults \
  && fail "athena:GetQueryResults should be blocked (no athena in simple PB)" \
  || pass "athena:GetQueryResults correctly blocked by simple PB"

# -----------------------------------------------------------------------
# merge-policies command (unified: --role / --cf-template)
# -----------------------------------------------------------------------
echo ""
echo "=== merge-policies command ==="

# Primary command
"$BINARY" merge-policies --help > /dev/null 2>&1 \
  && pass "merge-policies command is registered and --help works" \
  || fail "merge-policies --help failed"

# Backward-compatible aliases
"$BINARY" merge-role-policies --help > /dev/null 2>&1 \
  && pass "merge-role-policies alias works" \
  || fail "merge-role-policies alias not registered"

"$BINARY" mrp --help > /dev/null 2>&1 \
  && pass "mrp alias works" \
  || fail "mrp alias not registered"

"$BINARY" mp --help > /dev/null 2>&1 \
  && pass "mp alias works" \
  || fail "mp alias not registered"

"$BINARY" merge-cf-policies --help > /dev/null 2>&1 \
  && pass "merge-cf-policies alias works" \
  || fail "merge-cf-policies alias not registered"

"$BINARY" mcp --help > /dev/null 2>&1 \
  && pass "mcp alias works" \
  || fail "mcp alias not registered"

# No source → error
"$BINARY" merge-policies 2>"$TMPDIR_TEST/mp_no_source.txt" \
  && fail "merge-policies should error when no source specified" \
  || true
grep -qi "\-\-role\|--cf-template\|source" "$TMPDIR_TEST/mp_no_source.txt" \
  && pass "Error message mentions --role or --cf-template" \
  || fail "Error should mention --role or --cf-template"

# Both sources → error
"$BINARY" merge-policies --role foo --cf-template bar.yaml 2>"$TMPDIR_TEST/mp_both.txt" \
  && fail "merge-policies should error when both --role and --cf-template specified" \
  || true
grep -qi "only one\|not both" "$TMPDIR_TEST/mp_both.txt" \
  && pass "Error message mentions only one source" \
  || fail "Error should mention only one source"

# --resource without --cf-template → error
"$BINARY" merge-policies --role foo --resource Bar 2>"$TMPDIR_TEST/mp_resource_no_cf.txt" \
  && fail "merge-policies should error when --resource used without --cf-template" \
  || true
grep -qi "cf-template" "$TMPDIR_TEST/mp_resource_no_cf.txt" \
  && pass "Error message mentions --cf-template requirement for --resource" \
  || fail "Error should mention --cf-template"

# --cf-template with inline-only template (no AWS needed)
"$BINARY" merge-policies \
  --cf-template "$TESTDATA/test-cf-merge.yaml" \
  --quiet > "$TMPDIR_TEST/mp_cf_all.json" \
  && pass "merge-policies --cf-template works with inline-only template" \
  || fail "merge-policies --cf-template should work with inline-only template"

# Should produce valid JSON with statements from all resources
python3 -m json.tool "$TMPDIR_TEST/mp_cf_all.json" > /dev/null 2>&1 \
  && pass "CF merge output is valid JSON" \
  || fail "CF merge output is not valid JSON"

# 5 total statements: AppRole S3Access(2) + LogAccess(1) + WorkerRole DynamoAccess(1) + SharedPolicy(1)
STMT_COUNT=$(jq '.Statement | length' "$TMPDIR_TEST/mp_cf_all.json")
if [ "$STMT_COUNT" -eq 5 ]; then
  pass "CF merge: 5 statements from all resources"
else
  fail "Expected 5 statements, got $STMT_COUNT"
fi

# --resource filter
"$BINARY" merge-policies \
  --cf-template "$TESTDATA/test-cf-merge.yaml" \
  --resource AppRole \
  --quiet > "$TMPDIR_TEST/mp_cf_role.json" \
  && pass "merge-policies --cf-template --resource AppRole works" \
  || fail "merge-policies --cf-template --resource AppRole failed"

ROLE_STMTS=$(jq '.Statement | length' "$TMPDIR_TEST/mp_cf_role.json")
if [ "$ROLE_STMTS" -eq 3 ]; then
  pass "AppRole merge: 3 statements (S3Access 2 + LogAccess 1)"
else
  fail "Expected 3 statements for AppRole, got $ROLE_STMTS"
fi

# --ignore-deny
"$BINARY" merge-policies \
  --cf-template "$TESTDATA/test-cf-merge.yaml" \
  --resource AppRole \
  --ignore-deny \
  --quiet > "$TMPDIR_TEST/mp_cf_nodeny.json"

NODENY_STMTS=$(jq '.Statement | length' "$TMPDIR_TEST/mp_cf_nodeny.json")
if [ "$NODENY_STMTS" -eq 2 ]; then
  pass "AppRole with --ignore-deny: 2 statements (Deny removed)"
else
  fail "Expected 2 statements with --ignore-deny, got $NODENY_STMTS"
fi

jq -e '[.Statement[].Effect] | all(. == "Allow")' "$TMPDIR_TEST/mp_cf_nodeny.json" > /dev/null \
  && pass "All remaining statements are Allow" \
  || fail "Should only have Allow statements after --ignore-deny"

# --resource with unknown name → error
"$BINARY" merge-policies \
  --cf-template "$TESTDATA/test-cf-merge.yaml" \
  --resource NonExistent 2>"$TMPDIR_TEST/mp_bad_resource.txt" \
  && fail "Should error for unknown --resource" \
  || pass "merge-policies correctly errors for unknown --resource"

grep -qi "not found\|available" "$TMPDIR_TEST/mp_bad_resource.txt" \
  && pass "Error message lists available resources" \
  || fail "Error should list available resources"

# --resource for standalone policy
"$BINARY" merge-policies \
  --cf-template "$TESTDATA/test-cf-merge.yaml" \
  --resource SharedPolicy \
  --quiet > "$TMPDIR_TEST/mp_cf_standalone.json"

SP_STMTS=$(jq '.Statement | length' "$TMPDIR_TEST/mp_cf_standalone.json")
if [ "$SP_STMTS" -eq 1 ]; then
  pass "SharedPolicy merge: 1 statement"
else
  fail "Expected 1 statement for SharedPolicy, got $SP_STMTS"
fi

# -----------------------------------------------------------------------
# pb-check-cf — local inline-only templates (no AWS required)
# -----------------------------------------------------------------------
echo ""
echo "=== pb-check-cf — standalone IAM policy resources ==="

# test-cf-policies.yaml has AWS::IAM::ManagedPolicy and AWS::IAM::Policy
# with purely inline PolicyDocuments — no ManagedPolicyArns → no AWS needed.
# test-pb.json: Allow:* + Deny+NotAction[ec2:Describe*, s3:Get*, s3:List*, iam:Get*, iam:List*]
# MyManagedPolicy: s3:GetObject ✅ s3:ListBucket ✅ s3:PutObject ❌ s3:DeleteBucket→skipped
# MyInlinePolicy: ec2:DescribeInstances ✅ ec2:DescribeSecurityGroups ✅ logs:CreateLogGroup ❌

"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_policies.json" || true

# Two separate JSON blobs separated by "===..." — both resources should appear
grep -q '"MyManagedPolicy"' "$TMPDIR_TEST/cf_policies.json" \
  && grep -q '"MyInlinePolicy"' "$TMPDIR_TEST/cf_policies.json" \
  && pass "pb-check-cf produced output for both policy resources" \
  || fail "pb-check-cf should produce output for 2 policy resources"

# Test each resource individually for precise count assertions
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  --resource MyManagedPolicy \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_managed_policy.json" 2>/dev/null || true

jq -e '.resource == "MyManagedPolicy" and .summary.allowed == 2 and .summary.blocked == 1 and .summary.skipped_deny == 1' \
  "$TMPDIR_TEST/cf_managed_policy.json" > /dev/null \
  && pass "MyManagedPolicy: allowed=2 blocked=1 skipped_deny=1" \
  || fail "MyManagedPolicy counts wrong"

"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  --resource MyInlinePolicy \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_inline_policy.json" 2>/dev/null || true

jq -e '.resource == "MyInlinePolicy" and .summary.allowed == 2 and .summary.blocked == 1' \
  "$TMPDIR_TEST/cf_inline_policy.json" > /dev/null \
  && pass "MyInlinePolicy: allowed=2 blocked=1" \
  || fail "MyInlinePolicy counts wrong"

"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  "$TESTDATA/test-cf-policies.yaml" \
  && fail "pb-check-cf should exit non-zero when actions are blocked" \
  || pass "pb-check-cf correctly exits non-zero when actions are blocked"

# --resource filter for a standalone policy resource
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  --resource MyInlinePolicy \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_resource_filter.json" 2>/dev/null || true

jq -e 'type == "object"' "$TMPDIR_TEST/cf_resource_filter.json" > /dev/null \
  && pass "--resource filter returns a single JSON object" \
  || fail "--resource filter should return exactly 1 result"

jq -e '.resource == "MyInlinePolicy"' "$TMPDIR_TEST/cf_resource_filter.json" > /dev/null \
  && pass "--resource filter returned the correct resource (MyInlinePolicy)" \
  || fail "--resource filter returned unexpected resource"

# --resource filter for an inline-only IAM role (no ManagedPolicyArns → no AWS needed)
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --output json \
  --resource AnotherRole \
  "$TESTDATA/test-cf-template.yaml" > "$TMPDIR_TEST/cf_another_role.json" || true

jq -e '.resource == "AnotherRole" and .summary.allowed == 2 and .summary.blocked == 0' \
  "$TMPDIR_TEST/cf_another_role.json" > /dev/null \
  && pass "AnotherRole (inline-only): allowed=2 blocked=0" \
  || fail "AnotherRole counts wrong (expected 2 allowed, 0 blocked)"

"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --resource AnotherRole \
  "$TESTDATA/test-cf-template.yaml" \
  && pass "AnotherRole inline-only role exits zero (nothing blocked)" \
  || fail "AnotherRole should exit zero when all actions are allowed"

# --resource filter — unknown resource → error
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --resource NonExistentResource \
  "$TESTDATA/test-cf-template.yaml" 2>"$TMPDIR_TEST/cf_bad_resource.txt" \
  && fail "Should error when --resource not found" \
  || pass "pb-check-cf correctly errors for unknown --resource"

grep -qi "not found\|available" "$TMPDIR_TEST/cf_bad_resource.txt" \
  && pass "Error message mentions available resources" \
  || fail "Error message should list available resources"

# Standalone policy without --pb → error
"$BINARY" pb-check-cf \
  "$TESTDATA/test-cf-policies.yaml" 2>"$TMPDIR_TEST/cf_no_pb.txt" \
  && fail "pb-check-cf standalone policy without --pb should error" \
  || pass "pb-check-cf correctly requires --pb for standalone policies"

grep -qi "pb\|permission boundary" "$TMPDIR_TEST/cf_no_pb.txt" \
  && pass "Error message mentions --pb requirement" \
  || fail "Error message should mention --pb"

# List output format (default — no --output flag)
"$BINARY" pb-check-cf \
  --pb "$TESTDATA/test-pb.json" \
  --resource MyManagedPolicy \
  "$TESTDATA/test-cf-policies.yaml" > "$TMPDIR_TEST/cf_list_out.txt" 2>/dev/null || true

grep -qi "blocked\|not allowed" "$TMPDIR_TEST/cf_list_out.txt" \
  && pass "pb-check-cf list output mentions blocked actions" \
  || fail "pb-check-cf list output should mention blocked actions"

grep -q "s3:PutObject" "$TMPDIR_TEST/cf_list_out.txt" \
  && pass "pb-check-cf list output shows blocked action s3:PutObject" \
  || fail "pb-check-cf list output should show s3:PutObject"

grep -q "s3:GetObject\|s3:ListBucket" "$TMPDIR_TEST/cf_list_out.txt" \
  && pass "pb-check-cf list output shows allowed actions" \
  || fail "pb-check-cf list output should show allowed actions"

# Aliases
"$BINARY" check-cf --help > /dev/null 2>&1 \
  && pass "check-cf alias works" \
  || fail "check-cf alias not registered"

"$BINARY" ccf --help > /dev/null 2>&1 \
  && pass "ccf alias works" \
  || fail "ccf alias not registered"

"$BINARY" check-cloudformation --help > /dev/null 2>&1 \
  && pass "check-cloudformation alias works" \
  || fail "check-cloudformation alias not registered"

# pb-diff aliases (compare / cmp)
"$BINARY" compare --help > /dev/null 2>&1 \
  && pass "compare alias works (pb-diff)" \
  || fail "compare alias not registered"

"$BINARY" cmp --help > /dev/null 2>&1 \
  && pass "cmp alias works (pb-diff)" \
  || fail "cmp alias not registered"

# pb-check-action ca alias
"$BINARY" ca --help > /dev/null 2>&1 \
  && pass "ca alias works (pb-check-action)" \
  || fail "ca alias not registered"

# pb-check-policy cp alias
"$BINARY" cp --help > /dev/null 2>&1 \
  && pass "cp alias works (pb-check-policy)" \
  || fail "cp alias not registered"

# -----------------------------------------------------------------------
# gendocs
# -----------------------------------------------------------------------
echo ""
echo "=== gendocs ==="
"$BINARY" gendocs > /dev/null 2>&1 \
  && pass "gendocs runs without error" \
  || fail "gendocs failed"

[ -f "./docs/iamctl.md" ] \
  && pass "gendocs created docs/iamctl.md" \
  || fail "docs/iamctl.md not found after gendocs"

[ -f "./docs/iamctl_check-access.md" ] \
  && pass "gendocs created docs for check-access" \
  || fail "docs/iamctl_check-access.md not found"

# -----------------------------------------------------------------------
# AWS-requiring commands — --help smoke tests
# -----------------------------------------------------------------------
echo ""
echo "=== AWS-requiring commands (--help smoke tests) ==="

for cmd_alias in "optimize opt minimize shrink-role-policies shrink srp policy-from-role-usage pfu activity-policy policy-from-usage" \
                 "list ls role-list rl lr search-roles sr policy-list pl lp search-policies sp" \
                 "describe desc describe-role dr describe-policy dp" \
                 "pb-check-role check-role cr"; do
  primary=$(echo "$cmd_alias" | awk '{print $1}')
  "$BINARY" "$primary" --help > /dev/null 2>&1 \
    && pass "$primary is registered (--help works)" \
    || fail "$primary --help failed"
  for alias in $(echo "$cmd_alias" | awk '{$1=""; print $0}'); do
    "$BINARY" "$alias" --help > /dev/null 2>&1 \
      && pass "  alias '$alias' works" \
      || fail "  alias '$alias' not registered"
  done
done

# -----------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------
echo ""
echo "=== Edge cases ==="
"$BINARY" check-action --pb "$TESTDATA/test-pb.json" EC2:DESCRIBEINSTANCES \
  && pass "Uppercase action correctly matched (case-insensitive)" \
  || fail "Action matching should be case-insensitive"

"$BINARY" check-action --pb "$TESTDATA/patterns.json" EC2:DESCRIBEINSTANCES \
  && pass "Pattern matching is case-insensitive" \
  || fail "Pattern matching should be case-insensitive"

# JSON output has no null arrays
cat > "$TMPDIR_TEST/fully-allowed-policy.json" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
EOF
"$BINARY" check-policy \
  --pb "$TESTDATA/test-diff-old-pb.json" \
  --output json \
  "$TMPDIR_TEST/fully-allowed-policy.json" > "$TMPDIR_TEST/no_blocked.json"

jq -e '.blocked | type == "array"' "$TMPDIR_TEST/no_blocked.json" \
  && pass "blocked is [] not null" \
  || fail "blocked should be array, not null"

jq -e '.skipped_deny | type == "array"' "$TMPDIR_TEST/no_blocked.json" \
  && pass "skipped_deny is [] not null" \
  || fail "skipped_deny should be array, not null"

"$BINARY" check-action --pb "$TESTDATA/test-pb.json" totally:FakeAction \
  && fail "Unknown action should be blocked (not in boundary)" \
  || pass "Unknown action correctly blocked"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
# Go unit tests
# -----------------------------------------------------------------------
echo ""
echo "Running Go unit tests..."
if go test ./... 2>&1; then
  pass "Go unit tests"
else
  fail "Go unit tests"
fi

# -----------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Tests passed: $PASSED"
echo "  Tests failed: $FAILED"
echo "========================================"

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
