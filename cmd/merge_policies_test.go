package cmd

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/jordiprats/iamctl/pkg/cfn"
	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestMergePolicyDocs_SinglePolicy(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"OnlyPolicy": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "arn:aws:s3:::my-bucket/*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if len(merged.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(merged.Statement))
	}
	if merged.Statement[0].Effect != "Allow" {
		t.Errorf("expected Allow, got %q", merged.Statement[0].Effect)
	}
}

func TestDedupeStatements_RemovesDuplicates(t *testing.T) {
	stmt := policy.Statement{Effect: "Allow", Action: "s3:GetObject", Resource: "*"}
	statements := []policy.Statement{stmt, stmt, stmt}

	deduped := dedupeStatements(statements)

	if len(deduped) != 1 {
		t.Errorf("expected 1 unique statement, got %d", len(deduped))
	}
}

func TestDedupeStatements_KeepsDistinctStatements(t *testing.T) {
	statements := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "s3:PutObject", Resource: "*"},
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
	}

	deduped := dedupeStatements(statements)

	if len(deduped) != 3 {
		t.Errorf("expected 3 statements, got %d", len(deduped))
	}
}

func TestDedupeStatements_PreservesOrder(t *testing.T) {
	statements := []policy.Statement{
		{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"},
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"}, // duplicate of first
	}

	deduped := dedupeStatements(statements)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(deduped))
	}
	first, ok := deduped[0].Action.(string)
	if !ok || first != "ec2:RunInstances" {
		t.Errorf("expected first statement to be ec2:RunInstances, got %v", deduped[0].Action)
	}
	second, ok := deduped[1].Action.(string)
	if !ok || second != "s3:GetObject" {
		t.Errorf("expected second statement to be s3:GetObject, got %v", deduped[1].Action)
	}
}

func TestMergeAndDedupeIntegration(t *testing.T) {
	sharedStmt := policy.Statement{Effect: "Allow", Action: "sts:AssumeRole", Resource: "*"}
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "s3:GetObject", Resource: "*"}},
		},
		"PolicyB": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"}},
		},
	}

	merged := mergePolicyDocs(policies)
	deduped := policy.PolicyDocument{
		Version:   merged.Version,
		Statement: dedupeStatements(merged.Statement),
	}

	// 4 raw statements merged, but 1 is a duplicate → 3 unique
	if len(deduped.Statement) != 3 {
		t.Errorf("expected 3 unique statements after dedup, got %d", len(deduped.Statement))
	}
}

// --- Tests for mergeFromCfTemplate via collectRolePolicies (inline-only, no AWS) ---

func TestMergeFromCfTemplate_SingleRole(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}

	// Find AppRole
	var appRole *cfn.IAMRole
	for i, r := range roles {
		if r.LogicalID == "AppRole" {
			appRole = &roles[i]
			break
		}
	}
	if appRole == nil {
		t.Fatal("AppRole not found in template")
	}

	// AppRole has 2 inline policies: S3Access (2 stmts) + LogAccess (1 stmt)
	if len(appRole.Properties.InlinePolicies) != 2 {
		t.Fatalf("expected 2 inline policies, got %d", len(appRole.Properties.InlinePolicies))
	}

	// Merge inline policies only (no managed, so no AWS needed)
	allPolicies := make(map[string]policy.PolicyDocument)
	for name, doc := range appRole.Properties.InlinePolicies {
		allPolicies[appRole.LogicalID+"/"+name+" (inline)"] = doc
	}

	merged := mergePolicyDocs(allPolicies)

	// S3Access has 2 statements + LogAccess has 1 = 3 total
	if len(merged.Statement) != 3 {
		t.Errorf("expected 3 statements, got %d", len(merged.Statement))
	}
}

func TestMergeFromCfTemplate_AllResources(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}
	policies, err := cfn.ExtractIAMPolicies(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMPolicies: %v", err)
	}

	allPolicies := make(map[string]policy.PolicyDocument)

	// Collect inline policies from roles (skip managed, no AWS)
	for _, role := range roles {
		for name, doc := range role.Properties.InlinePolicies {
			allPolicies[role.LogicalID+"/"+name+" (inline)"] = doc
		}
	}
	// Collect standalone policies
	for _, pol := range policies {
		allPolicies[pol.LogicalID] = pol.PolicyDocument
	}

	merged := mergePolicyDocs(allPolicies)

	// AppRole: S3Access(2) + LogAccess(1) = 3
	// WorkerRole: DynamoAccess(1) = 1
	// SharedPolicy: 1
	// Total = 5
	if len(merged.Statement) != 5 {
		t.Errorf("expected 5 statements from all resources, got %d", len(merged.Statement))
	}
}

func TestMergeFromCfTemplate_WithIgnoreDeny(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}

	allPolicies := make(map[string]policy.PolicyDocument)
	for _, role := range roles {
		for name, doc := range role.Properties.InlinePolicies {
			allPolicies[role.LogicalID+"/"+name+" (inline)"] = doc
		}
	}

	merged := mergePolicyDocs(allPolicies)
	// Before filtering: AppRole S3Access has 1 Deny (s3:DeleteBucket)
	filtered := filterDenyStatements(merged.Statement)

	// 4 total minus 1 deny = 3
	if len(filtered) != 3 {
		t.Errorf("expected 3 statements after ignore-deny, got %d", len(filtered))
	}
	for _, s := range filtered {
		if s.Effect == "Deny" {
			t.Error("found Deny statement after filtering")
		}
	}
}

func TestMergeFromCfTemplate_ResourceFilter(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}

	// Filter to WorkerRole
	var filtered []cfn.IAMRole
	for _, r := range roles {
		if r.LogicalID == "WorkerRole" {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) != 1 {
		t.Fatalf("expected to find WorkerRole, got %d matches", len(filtered))
	}

	allPolicies := make(map[string]policy.PolicyDocument)
	for name, doc := range filtered[0].Properties.InlinePolicies {
		allPolicies[filtered[0].LogicalID+"/"+name+" (inline)"] = doc
	}

	merged := mergePolicyDocs(allPolicies)

	// WorkerRole: DynamoAccess has 1 statement
	if len(merged.Statement) != 1 {
		t.Errorf("expected 1 statement for WorkerRole only, got %d", len(merged.Statement))
	}
}

func TestMergeFromCfTemplate_StandalonePolicies(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	policies, err := cfn.ExtractIAMPolicies(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMPolicies: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("expected 1 standalone policy, got %d", len(policies))
	}
	if policies[0].LogicalID != "SharedPolicy" {
		t.Errorf("expected SharedPolicy, got %s", policies[0].LogicalID)
	}

	allPolicies := make(map[string]policy.PolicyDocument)
	for _, pol := range policies {
		allPolicies[pol.LogicalID] = pol.PolicyDocument
	}

	merged := mergePolicyDocs(allPolicies)

	if len(merged.Statement) != 1 {
		t.Errorf("expected 1 statement from SharedPolicy, got %d", len(merged.Statement))
	}
}

func TestMergeFromCfTemplate_DedupeAcrossRoles(t *testing.T) {
	// Create two roles with an identical statement to check dedup
	sharedStmt := policy.Statement{Effect: "Allow", Action: "sts:AssumeRole", Resource: "*"}
	policies := map[string]policy.PolicyDocument{
		"RoleA/common (inline)": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "s3:GetObject", Resource: "*"}},
		},
		"RoleB/common (inline)": {
			Version:   "2012-10-17",
			Statement: []policy.Statement{sharedStmt, {Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"}},
		},
	}

	merged := mergePolicyDocs(policies)
	deduped := dedupeStatements(merged.Statement)

	// 4 raw statements, 1 duplicate → 3 unique
	if len(deduped) != 3 {
		t.Errorf("expected 3 unique statements after dedup, got %d", len(deduped))
	}
}

func TestMergeFromCfTemplate_PolicyNames(t *testing.T) {
	tmpl, err := cfn.ParseTemplate(filepath.Join("..", "testdata", "test-cf-merge.yaml"))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMRoles: %v", err)
	}
	policies, err := cfn.ExtractIAMPolicies(tmpl)
	if err != nil {
		t.Fatalf("ExtractIAMPolicies: %v", err)
	}

	allPolicies := make(map[string]policy.PolicyDocument)
	for _, role := range roles {
		for name, doc := range role.Properties.InlinePolicies {
			allPolicies[role.LogicalID+"/"+name+" (inline)"] = doc
		}
	}
	for _, pol := range policies {
		allPolicies[pol.LogicalID] = pol.PolicyDocument
	}

	var names []string
	for name := range allPolicies {
		names = append(names, name)
	}
	sort.Strings(names)

	expected := []string{
		"AppRole/LogAccess (inline)",
		"AppRole/S3Access (inline)",
		"SharedPolicy",
		"WorkerRole/DynamoAccess (inline)",
	}
	if len(names) != len(expected) {
		t.Fatalf("expected %d policy keys, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("policy key %d: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestFilterDenyStatements_RemovesDenyByEffect(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
		{Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"},
		{Effect: "deny", Action: "s3:DeleteObject", Resource: "*"}, // lowercase
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 2 {
		t.Errorf("expected 2 Allow statements, got %d", len(kept))
	}
	for _, stmt := range kept {
		if stmt.Effect == "Deny" || stmt.Effect == "deny" {
			t.Errorf("Deny statement not removed: %+v", stmt)
		}
	}
}

func TestFilterDenyStatements_NoDenyStatements(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
		{Effect: "Allow", Action: "ec2:DescribeInstances", Resource: "*"},
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 2 {
		t.Errorf("expected all 2 statements preserved, got %d", len(kept))
	}
}

func TestFilterDenyStatements_AllDeny(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Deny", Action: "iam:*", Resource: "*"},
		{Effect: "Deny", Action: "s3:*", Resource: "*"},
	}

	kept := filterDenyStatements(stmts)

	if len(kept) != 0 {
		t.Errorf("expected 0 statements remaining, got %d", len(kept))
	}
}

func TestStrict_CompactsEquivalentStatements(t *testing.T) {
	// Two policies each have the same statement but with different Sids.
	// compactStatements should deduplicate them (by key-without-Sid) and clear the Sid.
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Sid: "SidA", Effect: "Allow", Action: []interface{}{"s3:GetObject"}, Resource: "*"},
			},
		},
		"PolicyB": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Sid: "SidB", Effect: "Allow", Action: []interface{}{"s3:GetObject"}, Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)
	compacted := compactStatements(merged.Statement)

	// Both statements are identical (ignoring Sid) → should collapse to 1 with Sid cleared
	if len(compacted) != 1 {
		t.Fatalf("expected 1 compacted statement, got %d", len(compacted))
	}
	if compacted[0].Sid != "" {
		t.Errorf("expected Sid cleared on duplicate, got %q", compacted[0].Sid)
	}
}

func TestStrict_NormalizesUnsortedActions(t *testing.T) {
	// compactStatements normalizes action lists: sorts and deduplicates within each statement
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:PutObject", "s3:GetObject", "s3:GetObject"}, Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)
	compacted := compactStatements(merged.Statement)

	if len(compacted) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(compacted))
	}
	actions, ok := compacted[0].Action.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} action, got %T", compacted[0].Action)
	}
	if len(actions) != 2 {
		t.Errorf("expected 2 unique actions after normalize, got %d: %v", len(actions), actions)
	}
	// Should be sorted
	if actions[0].(string) != "s3:GetObject" || actions[1].(string) != "s3:PutObject" {
		t.Errorf("expected sorted actions [s3:GetObject, s3:PutObject], got %v", actions)
	}
}

// --- Edge cases for filterDenyStatements ---

func TestFilterDenyStatements_CaseInsensitive(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "DENY", Action: "iam:*"},
		{Effect: "deny", Action: "sts:*"},
		{Effect: "Allow", Action: "s3:GetObject"},
	}
	result := filterDenyStatements(stmts)
	if len(result) != 1 {
		t.Errorf("expected 1 (case-insensitive deny), got %d", len(result))
	}
}

func TestFilterDenyStatements_EmptyInput(t *testing.T) {
	result := filterDenyStatements(nil)
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

// --- Edge cases for merge-policies validation ---

func TestMergePolicies_NoSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "merge-policies")
	if err == nil {
		t.Fatal("expected error when no source specified")
	}
}

func TestMergePolicies_BothSources(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "merge-policies", "--role", "my-role", "--cf-template", "tmpl.yaml")
	if err == nil {
		t.Fatal("expected error when both sources specified")
	}
}

func TestMergePolicies_ResourceWithoutCf(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "merge-policies", "--role", "my-role", "--resource", "MyRole")
	if err == nil {
		t.Fatal("expected error when --resource used without --cf-template")
	}
}

func TestMergePolicies_LegacyAliases(t *testing.T) {
	root := NewRootCmd("test")

	for _, alias := range []string{"mp", "merge-role-policies", "mrp", "merge-cf-policies", "mcp"} {
		cmd, _, err := root.Find([]string{alias})
		if err != nil {
			t.Fatalf("%s alias not found: %v", alias, err)
		}
		if cmd.Name() != "merge-policies" {
			t.Errorf("expected merge-policies command for alias %s, got %s", alias, cmd.Name())
		}
	}
}

// --- Edge cases for dedupeStatements ---

func TestDedupeStatements_Empty(t *testing.T) {
	result := dedupeStatements(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestDedupeStatements_SingleStatement(t *testing.T) {
	stmts := []policy.Statement{
		{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
	}
	result := dedupeStatements(stmts)
	if len(result) != 1 {
		t.Errorf("expected 1, got %d", len(result))
	}
}

// --- Edge cases for mergePolicyDocs ---

func TestMergePolicyDocs_NilStatements(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"P1": {Version: "2012-10-17"},
	}
	merged := mergePolicyDocs(policies)
	if merged.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", merged.Version)
	}
	if len(merged.Statement) != 0 {
		t.Errorf("expected 0 statements, got %d", len(merged.Statement))
	}
}

func TestMergePolicyDocs_PreservesAllFields(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"P1": {
			Version: "2012-10-17",
			Statement: []policy.Statement{{
				Sid:       "Test",
				Effect:    "Allow",
				Action:    "s3:GetObject",
				Resource:  "arn:aws:s3:::bucket/*",
				Condition: map[string]interface{}{"StringEquals": map[string]interface{}{"s3:prefix": "home/"}},
			}},
		},
	}
	merged := mergePolicyDocs(policies)
	if len(merged.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(merged.Statement))
	}
	if merged.Statement[0].Sid != "Test" {
		t.Errorf("Sid not preserved: %q", merged.Statement[0].Sid)
	}
	if merged.Statement[0].Condition == nil {
		t.Error("Condition not preserved")
	}
	if merged.Statement[0].Resource != "arn:aws:s3:::bucket/*" {
		t.Errorf("Resource not preserved: %v", merged.Statement[0].Resource)
	}
}
