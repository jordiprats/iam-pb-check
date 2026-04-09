package boundary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestEvaluatePolicy_AllowAll(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("Allow * should allow any action")
	}
}

func TestEvaluatePolicy_AllowSpecific(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("should allow s3:GetObject")
	}
	if EvaluatePolicy("ec2:RunInstances", doc) {
		t.Fatal("should not allow ec2:RunInstances")
	}
}

func TestEvaluatePolicy_DenyOverridesAllow(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", Action: []interface{}{"iam:CreateRole"}},
		},
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("explicit Deny should override Allow *")
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("non-denied action should still be allowed")
	}
}

func TestEvaluatePolicy_DenyWildcard(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", Action: "iam:*"},
		},
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("iam:* deny should block iam:CreateRole")
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("s3:GetObject should still be allowed")
	}
}

func TestEvaluatePolicy_NotActionAllow(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", NotAction: []interface{}{"iam:*"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("NotAction iam:* with Allow should allow s3:GetObject")
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("NotAction iam:* with Allow should NOT allow iam:CreateRole")
	}
}

func TestEvaluatePolicy_NotActionDeny(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"s3:GetObject"}},
		},
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("Deny NotAction [s3:GetObject] should NOT deny s3:GetObject")
	}
	if EvaluatePolicy("iam:CreateRole", doc) {
		t.Fatal("Deny NotAction [s3:GetObject] should deny iam:CreateRole")
	}
}

func TestEvaluatePolicy_NoStatements(t *testing.T) {
	doc := policy.PolicyDocument{}
	if EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("empty policy should deny everything")
	}
}

func TestEvaluatePolicy_CaseInsensitive(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "S3:GetObject"},
		},
	}
	if !EvaluatePolicy("s3:getobject", doc) {
		t.Fatal("matching should be case-insensitive")
	}
}

func TestIsActionAllowed_WithPolicy(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*"}},
			},
		},
	}
	if !IsActionAllowed("s3:GetObject", pb) {
		t.Fatal("should allow s3:GetObject")
	}
	if IsActionAllowed("iam:CreateRole", pb) {
		t.Fatal("should not allow iam:CreateRole")
	}
}

func TestIsActionAllowed_WithPatterns(t *testing.T) {
	pb := &PermissionBoundary{
		Patterns: []string{"s3:*", "ec2:Describe*"},
	}
	if !IsActionAllowed("s3:GetObject", pb) {
		t.Fatal("should allow via pattern")
	}
	if !IsActionAllowed("ec2:DescribeInstances", pb) {
		t.Fatal("should allow via pattern")
	}
	if IsActionAllowed("iam:CreateRole", pb) {
		t.Fatal("should not allow iam:CreateRole")
	}
}

func TestEvaluatePolicy_WildcardActionDenyNotAction_NoOverlap(t *testing.T) {
	// Wildcard action with NO matching service in NotAction → correctly denied
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"glue:*A*", "glue:L*", "s3:G*"}},
		},
	}
	if EvaluatePolicy("athena:BatchGet*", doc) {
		t.Fatal("athena:BatchGet* should be denied: no athena entries in NotAction")
	}
	if EvaluatePolicy("athena:Get*", doc) {
		t.Fatal("athena:Get* should be denied: no athena entries in NotAction")
	}
}

func TestEvaluatePolicy_WildcardActionDenyNotAction_WithOverlap(t *testing.T) {
	// Wildcard action whose service HAS entries in NotAction → must NOT be a false positive.
	// Policy grants glue:* but PB Deny+NotAction has specific glue: patterns.
	// glue:GetDatabase IS allowed by the PB; the whole glue:* token should not be "blocked".
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"glue:*A*", "glue:*G*", "glue:L*", "glue:S*"}},
		},
	}
	if !EvaluatePolicy("glue:*", doc) {
		t.Fatal("glue:* should NOT be reported as blocked when the PB has glue: entries in NotAction (false positive)")
	}
}

func TestEvaluatePolicy_WildcardActionDenyNotAction_ElasticacheDescribe(t *testing.T) {
	// elasticache:Describe* overlaps with elasticache:D*s → not a false positive
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"elasticache:D*s", "elasticache:L*"}},
		},
	}
	if !EvaluatePolicy("elasticache:Describe*", doc) {
		t.Fatal("elasticache:Describe* should NOT be reported as blocked when elasticache:D*s is in NotAction")
	}
}

func TestEvaluatePolicy_SpecificActionDenyNotAction_StillWorks(t *testing.T) {
	// Specific (non-wildcard) blocked actions must continue to work correctly
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"glue:*A*", "glue:L*", "s3:G*"}},
		},
	}
	if EvaluatePolicy("ec2:CreateTags", doc) {
		t.Fatal("ec2:CreateTags should be denied: not in NotAction and no ec2 overlap")
	}
	if !EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("s3:GetObject should be allowed: matches s3:G* in NotAction")
	}
}

func TestDiffPolicies(t *testing.T) {
	pbA := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*", "ec2:*"}},
			},
		},
	}
	pbB := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*", "iam:*"}},
			},
		},
	}
	actions := []string{"s3:GetObject", "ec2:RunInstances", "iam:CreateRole"}
	onlyA, onlyB := DiffPolicies(pbA, pbB, actions)
	if len(onlyA) != 1 || onlyA[0] != "ec2:RunInstances" {
		t.Fatalf("expected onlyA=[ec2:RunInstances], got %v", onlyA)
	}
	if len(onlyB) != 1 || onlyB[0] != "iam:CreateRole" {
		t.Fatalf("expected onlyB=[iam:CreateRole], got %v", onlyB)
	}
}

func TestDiffPolicies_Identical(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "*"},
			},
		},
	}
	onlyA, onlyB := DiffPolicies(pb, pb, []string{"s3:GetObject"})
	if len(onlyA) != 0 || len(onlyB) != 0 {
		t.Fatalf("identical PBs should have no diff, got A=%v B=%v", onlyA, onlyB)
	}
}

func TestLoadFromFile_PolicyVersionWrapper(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Policy == nil {
		t.Fatal("expected policy-based PB")
	}
	if pb.EvaluationMethod != "Full IAM policy evaluation" {
		t.Fatalf("unexpected method: %s", pb.EvaluationMethod)
	}
}

func TestLoadFromFile_DirectPolicy(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-policy.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Policy == nil {
		t.Fatal("expected policy-based PB")
	}
}

func TestLoadFromFile_JsonPatterns(t *testing.T) {
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "patterns.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pb.Patterns) == 0 {
		t.Fatal("expected pattern-based PB")
	}
	if pb.EvaluationMethod != "Simple pattern matching" {
		t.Fatalf("unexpected method: %s", pb.EvaluationMethod)
	}
}

func TestLoadFromFile_TextFile(t *testing.T) {
	// Create a temp text file with patterns
	tmp, err := os.CreateTemp("", "pb-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("s3:GetObject\n# comment\nec2:*\n")
	tmp.Close()

	pb, err := LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pb.Patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d: %v", len(pb.Patterns), pb.Patterns)
	}
}

func TestLoadFromFile_Nonexistent(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Allow:* + Deny+NotAction (the "minified PB" pattern)
// ---------------------------------------------------------------------------

func TestEvaluatePolicy_DenyNotAction_TableDriven(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*", Resource: "*"},
			{Effect: "Deny", Resource: "*", NotAction: []interface{}{
				// ec2: read/tag only
				"ec2:Describe*",
				"ec2:CreateTags",
				// glue: partial coverage via sub-string patterns
				"glue:*A*",
				"glue:*G*",
				"glue:L*",
				"glue:S*",
				// elasticache: describe only
				"elasticache:D*s",
				"elasticache:L*",
				// s3: get, list, job-tagging
				"s3:G*",
				"s3:List*",
				"s3:*J*",
				// iam: read only
				"iam:Get*",
				"iam:List*",
				// logs: specific actions
				"logs:CreateLogGroup",
				"logs:CreateLogStream",
				"logs:PutLogEvents",
			}},
		},
	}

	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		// --- Specific actions that ARE in NotAction → allowed ---
		{"ec2:DescribeInstances", true, "matches ec2:Describe*"},
		{"ec2:DescribeSecurityGroups", true, "matches ec2:Describe*"},
		{"ec2:CreateTags", true, "exact match in NotAction"},
		{"glue:GetDatabase", true, "matches glue:*G* (contains G)"},
		{"glue:GetTable", true, "matches glue:*G*"},
		{"glue:CreateTable", true, "matches glue:*A* (contains 'a')"},
		{"glue:StartJobRun", true, "matches glue:S*"},
		{"glue:ListCrawlers", true, "matches glue:L*"},
		{"elasticache:DescribeCacheClusters", true, "matches elasticache:D*s"},
		{"elasticache:ListTagsForResource", true, "matches elasticache:L*"},
		{"s3:GetObject", true, "matches s3:G*"},
		{"s3:GetBucketPolicy", true, "matches s3:G*"},
		{"s3:ListBuckets", true, "matches s3:List*"},
		{"s3:ListObjectsV2", true, "matches s3:List*"},
		{"iam:GetRole", true, "matches iam:Get*"},
		{"iam:ListUsers", true, "matches iam:List*"},
		{"logs:CreateLogGroup", true, "exact match"},
		{"logs:CreateLogStream", true, "exact match"},
		{"logs:PutLogEvents", true, "exact match"},

		// --- Specific actions NOT in NotAction → blocked ---
		{"ec2:DeleteTags", false, "not in NotAction"},
		{"ec2:RunInstances", false, "not in NotAction"},
		{"ec2:TerminateInstances", false, "not in NotAction"},
		{"glue:DeleteJob", false, "DeleteJob: no 'a', 'g', not L*/S* → blocked"},
		{"glue:DeleteCrawler", true, "DeleteCrawler contains 'a' → matches glue:*A* case-insensitively"},
		{"elasticache:CreateCacheCluster", false, "not in NotAction"},
		{"elasticache:DeleteCacheCluster", false, "not in NotAction"},
		{"s3:DeleteBucket", false, "not in NotAction"},
		{"s3:PutObject", true, "PutObject contains 'j' (Ob-j-ect) → matches s3:*J* case-insensitively"},
		{"iam:CreateRole", false, "not in NotAction"},
		{"iam:DeleteRole", false, "not in NotAction"},
		{"logs:DescribeLogGroups", false, "only three specific logs actions allowed"},

		// --- Services with NO entries in NotAction → always blocked ---
		{"athena:GetQueryResults", false, "no athena entries in NotAction"},
		{"athena:StartQueryExecution", false, "no athena entries in NotAction"},
		{"cloudtrail:LookupEvents", false, "no cloudtrail entries in NotAction"},
		{"cloudtrail:DescribeTrails", false, "no cloudtrail entries in NotAction"},

		// --- Wildcard grant, service HAS overlap in NotAction → NOT blocked (false-positive prevention) ---
		{"ec2:*", true, "overlaps with ec2:Describe* in NotAction"},
		{"glue:*", true, "overlaps with glue:*A* etc in NotAction"},
		{"elasticache:Describe*", true, "overlaps with elasticache:D*s"},
		{"s3:*", true, "overlaps with s3:G* (prefix s3: matches)"},
		{"iam:*", true, "overlaps with iam:Get* in NotAction"},

		// --- Wildcard grant, service has NO NotAction entries → correctly blocked ---
		{"athena:*", false, "no athena entries in NotAction → denied"},
		{"athena:Get*", false, "no athena entries in NotAction → denied"},
		{"athena:BatchGet*", false, "no athena entries in NotAction → denied"},
		{"cloudtrail:*", false, "no cloudtrail entries in NotAction → denied"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := EvaluatePolicy(tc.action, doc)
			if got != tc.allowed {
				t.Errorf("EvaluatePolicy(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Allow+NotAction style PB
// ---------------------------------------------------------------------------

func TestEvaluatePolicy_AllowNotAction_TableDriven(t *testing.T) {
	// PB allows everything EXCEPT specific sensitive actions.
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", NotAction: []interface{}{
				"iam:*",
				"organizations:*",
				"sts:AssumeRole",
				"sts:AssumeRoleWithSAML",
			}, Resource: "*"},
		},
	}

	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		// Actions clearly outside NotAction → allowed
		{"s3:GetObject", true, "s3 not in NotAction"},
		{"ec2:DescribeInstances", true, "ec2 not in NotAction"},
		{"glue:GetDatabase", true, "glue not in NotAction"},
		{"logs:PutLogEvents", true, "logs not in NotAction"},
		{"sts:GetCallerIdentity", true, "not excluded, only AssumeRole variants"},

		// Actions fully inside NotAction → not allowed
		{"iam:CreateRole", false, "iam:CreateRole matches iam:*"},
		{"iam:GetUser", false, "iam:GetUser matches iam:*"},
		{"organizations:ListAccounts", false, "matches organizations:*"},
		{"sts:AssumeRole", false, "exact match in NotAction"},
		{"sts:AssumeRoleWithSAML", false, "exact match in NotAction"},

		// Wildcard — entire service is in NotAction → not allowed
		{"iam:*", false, "iam:* matches iam:* pattern itself"},
		{"organizations:*", false, "organizations:* matches organizations:*"},

		// Wildcard — service not in NotAction at all → allowed
		{"s3:*", true, "s3 has no entries in NotAction"},
		{"ec2:*", true, "ec2 has no entries in NotAction"},

		// Wildcard — service partially in NotAction (sts:AssumeRole listed but not sts:*)
		// → conservative: overlap detected (both start with "sts:") → skip → not allowed
		{"sts:*", false, "sts:* overlaps with sts:AssumeRole entry → ambiguous → not allowed"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := EvaluatePolicy(tc.action, doc)
			if got != tc.allowed {
				t.Errorf("EvaluatePolicy(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// File-based integration tests
// ---------------------------------------------------------------------------

func TestLoadFromFile_ExistingPB_WildcardActions(t *testing.T) {
	// test-pb.json: Allow:* + Deny+NotAction [ec2:Describe*, ec2:CreateTags, s3:Get*, s3:List*, iam:Get*, iam:List*]
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb.json"))
	if err != nil {
		t.Fatalf("LoadFromFile test-pb.json: %v", err)
	}

	tests := []struct {
		action  string
		allowed bool
	}{
		// Specific allowed
		{"ec2:DescribeInstances", true},
		{"ec2:CreateTags", true},
		{"s3:GetObject", true},
		{"s3:ListBuckets", true},
		{"iam:GetRole", true},
		{"iam:ListUsers", true},
		// Specific blocked
		{"ec2:DeleteTags", false},
		{"ec2:RunInstances", false},
		{"s3:DeleteBucket", false},
		{"s3:PutObject", false},
		{"iam:CreateRole", false},
		{"iam:DeleteRole", false},
		// No entries for these services → always blocked
		{"athena:GetQueryResults", false},
		{"athena:StartQueryExecution", false},
		{"cloudtrail:DescribeTrails", false},
		// Wildcard with service overlap → not blocked (false-positive prevention)
		{"ec2:*", true},
		{"s3:*", true},
		{"iam:*", true},
		// Wildcard with no service overlap → correctly blocked
		{"athena:*", false},
		{"athena:Get*", false},
		{"athena:BatchGet*", false},
		{"cloudtrail:*", false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := IsActionAllowed(tc.action, pb)
			if got != tc.allowed {
				t.Errorf("IsActionAllowed(%q) = %v, want %v", tc.action, got, tc.allowed)
			}
		})
	}
}

func TestLoadFromFile_MultiServicePB_WildcardActions(t *testing.T) {
	// test-pb-multi-service.json: realistic minified PB with glue, elasticache, etc.
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb-multi-service.json"))
	if err != nil {
		t.Fatalf("LoadFromFile test-pb-multi-service.json: %v", err)
	}

	tests := []struct {
		action  string
		allowed bool
	}{
		// Specific allowed
		{"ec2:DescribeInstances", true},
		{"ec2:CreateTags", true},
		{"glue:GetDatabase", true},
		{"glue:ListCrawlers", true},
		{"elasticache:DescribeCacheClusters", true},
		{"s3:GetObject", true},
		{"s3:ListBuckets", true},
		{"iam:GetRole", true},
		{"logs:PutLogEvents", true},
		{"logs:CreateLogGroup", true},
		{"logs:CreateLogStream", true},
		// Specific blocked
		{"ec2:DeleteTags", false},
		{"glue:DeleteJob", false},
		{"elasticache:CreateCacheCluster", false},
		{"s3:DeleteBucket", false},
		{"s3:PutObject", true}, // PutObject contains 'j' in 'Object' → matches s3:*J*
		{"iam:CreateRole", false},
		{"logs:DescribeLogGroups", false}, // only three specific logs actions are in NotAction
		{"athena:GetQueryResults", false},
		{"cloudtrail:LookupEvents", false},
		// Wildcard with service overlap → not blocked
		{"ec2:*", true},
		{"glue:*", true},
		{"elasticache:Describe*", true},
		{"s3:*", true},
		{"iam:*", true},
		// Wildcard with no service overlap → correctly blocked
		{"athena:*", false},
		{"athena:Get*", false},
		{"athena:BatchGet*", false},
		{"cloudtrail:*", false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := IsActionAllowed(tc.action, pb)
			if got != tc.allowed {
				t.Errorf("IsActionAllowed(%q) = %v, want %v", tc.action, got, tc.allowed)
			}
		})
	}
}

func TestLoadFromFile_AllowNotAction_PB(t *testing.T) {
	// test-pb-allow-notaction.json: Allow+NotAction [iam:*, organizations:*, sts:AssumeRole, sts:AssumeRoleWithSAML]
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb-allow-notaction.json"))
	if err != nil {
		t.Fatalf("LoadFromFile test-pb-allow-notaction.json: %v", err)
	}

	tests := []struct {
		action  string
		allowed bool
	}{
		{"s3:GetObject", true},
		{"ec2:DescribeInstances", true},
		{"sts:GetCallerIdentity", true},
		{"iam:CreateRole", false},
		{"iam:GetUser", false},
		{"organizations:ListAccounts", false},
		{"sts:AssumeRole", false},
		{"iam:*", false},
		{"s3:*", true},
		{"ec2:*", true},
		{"sts:*", false}, // ambiguous: overlaps with sts:AssumeRole → conservative
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := IsActionAllowed(tc.action, pb)
			if got != tc.allowed {
				t.Errorf("IsActionAllowed(%q) = %v, want %v", tc.action, got, tc.allowed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fundamental AWS IAM evaluation rules
// ---------------------------------------------------------------------------

// TestEvaluatePolicy_MultipleAllowStatements verifies OR semantics: an action
// allowed by ANY Allow statement is permitted, regardless of which statement it matches.
func TestEvaluatePolicy_MultipleAllowStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:GetObject"},
			{Effect: "Allow", Action: "ec2:RunInstances"},
		},
	}
	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		{"s3:GetObject", true, "covered by first Allow statement"},
		{"ec2:RunInstances", true, "covered by second Allow statement"},
		{"iam:CreateRole", false, "not covered by any Allow → implicit deny"},
		{"s3:PutObject", false, "not covered by any Allow → implicit deny"},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := EvaluatePolicy(tc.action, doc)
			if got != tc.allowed {
				t.Errorf("EvaluatePolicy(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// TestEvaluatePolicy_ExplicitDenyWins_SpecificAction verifies the core AWS IAM rule:
// an explicit Deny always overrides an explicit Allow, even for the exact same action.
func TestEvaluatePolicy_ExplicitDenyWins_SpecificAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:GetObject"},
			{Effect: "Deny", Action: "s3:GetObject"},
		},
	}
	if EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("explicit Deny must override explicit Allow for the same specific action")
	}
	// Unrelated actions are not affected by the Deny
	if EvaluatePolicy("ec2:RunInstances", doc) {
		t.Fatal("ec2:RunInstances has no Allow → implicit deny")
	}
}

// TestEvaluatePolicy_EvalOrderIndependent_DenyAlwaysWins verifies that the order
// of Allow and Deny statements does not affect the outcome — Deny always wins.
func TestEvaluatePolicy_EvalOrderIndependent_DenyAlwaysWins(t *testing.T) {
	// Deny first, Allow second
	docDenyFirst := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Deny", Action: "s3:GetObject"},
			{Effect: "Allow", Action: "s3:GetObject"},
		},
	}
	// Allow first, Deny second
	docAllowFirst := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:GetObject"},
			{Effect: "Deny", Action: "s3:GetObject"},
		},
	}
	for _, doc := range []policy.PolicyDocument{docDenyFirst, docAllowFirst} {
		if EvaluatePolicy("s3:GetObject", doc) {
			t.Fatal("explicit Deny must win regardless of statement order")
		}
	}
	// Confirm the same with Allow:* + Deny:specific
	docAllowStar := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", Action: "s3:DeleteBucket"},
		},
	}
	if EvaluatePolicy("s3:DeleteBucket", docAllowStar) {
		t.Fatal("Deny:s3:DeleteBucket must override Allow:*")
	}
	if !EvaluatePolicy("s3:GetObject", docAllowStar) {
		t.Fatal("s3:GetObject not denied → must remain allowed by Allow:*")
	}
}

// TestEvaluatePolicy_DenyOnlyNoAllow verifies that without any Allow statement,
// actions are denied regardless of whether a Deny statement also applies.
// AWS rule: an action requires an explicit Allow; absence of Allow = implicit deny.
func TestEvaluatePolicy_DenyOnlyNoAllow(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Deny", Action: "s3:GetObject"},
		},
	}
	// Explicitly denied AND no Allow → denied
	if EvaluatePolicy("s3:GetObject", doc) {
		t.Fatal("s3:GetObject is explicitly denied and has no Allow → denied")
	}
	// Not explicitly denied but still no Allow → implicit deny
	if EvaluatePolicy("ec2:RunInstances", doc) {
		t.Fatal("ec2:RunInstances: not in Deny but no Allow exists → implicit deny")
	}
}

// TestEvaluatePolicy_AllowNotAction_Plus_DenyAction verifies correct interaction
// between an Allow+NotAction statement and an explicit Deny+Action statement.
func TestEvaluatePolicy_AllowNotAction_Plus_DenyAction(t *testing.T) {
	// PB: allow everything except iam:*, but also explicitly deny s3:DeleteBucket.
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", NotAction: []interface{}{"iam:*"}},
			{Effect: "Deny", Action: "s3:DeleteBucket"},
		},
	}
	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		{"s3:GetObject", true, "allowed by Allow+NotAction, not denied"},
		{"ec2:RunInstances", true, "allowed by Allow+NotAction, not denied"},
		// Explicit Deny overrides the Allow+NotAction coverage
		{"s3:DeleteBucket", false, "allowed by Allow+NotAction but overridden by explicit Deny"},
		// Excluded from Allow+NotAction (iam:* is in the NotAction list)
		{"iam:CreateRole", false, "iam:CreateRole matches iam:* → excluded from Allow+NotAction"},
		{"iam:GetUser", false, "iam:GetUser matches iam:* → excluded from Allow+NotAction"},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := EvaluatePolicy(tc.action, doc)
			if got != tc.allowed {
				t.Errorf("EvaluatePolicy(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// TestEvaluatePolicy_DenyNotAction_WildcardGrantLiterallyInNotAction verifies a
// subtle but important correctness property: a wildcard GRANT TOKEN (e.g. "iam:*")
// whose literal string satisfies the regex built from a NotAction entry (e.g. pattern
// "iam:*" → regex ^iam:.*$) is correctly treated as "covered by NotAction" and
// therefore NOT denied by the Deny+NotAction statement.
//
// This is the correct AWS-equivalent outcome: Deny+NotAction:[iam:*] means
// "deny everything EXCEPT iam actions". The grant iam:* (all iam) is entirely
// within that exception, so it is not denied.
func TestEvaluatePolicy_DenyNotAction_WildcardGrantLiterallyInNotAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "*"},
			{Effect: "Deny", NotAction: []interface{}{"iam:*"}},
		},
	}
	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		// Specific actions inside iam:* → not denied
		{"iam:CreateRole", true, "iam:CreateRole is in iam:* → not denied → allowed"},
		{"iam:GetUser", true, "iam:GetUser is in iam:* → not denied → allowed"},
		// Specific actions outside iam:* → denied by Deny+NotAction
		{"s3:GetObject", false, "s3:GetObject not in iam:* → denied"},
		{"ec2:RunInstances", false, "ec2:RunInstances not in iam:* → denied"},
		// Wildcard token "iam:*" as a literal string satisfies the regex ^iam:.*$
		// (the "*" char is matched by .*) → not denied → allowed
		{"iam:*", true, "literal \"iam:*\" satisfies ^iam:.*$ → in the NotAction exception → not denied"},
		// "iam:Get*" also satisfies ^iam:.*$ for the same reason
		{"iam:Get*", true, "literal \"iam:Get*\" satisfies ^iam:.*$ → not denied"},
		// "s3:*" does NOT satisfy ^iam:.*$ → denied
		{"s3:*", false, "s3:* does not match iam:* pattern → denied"},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := EvaluatePolicy(tc.action, doc)
			if got != tc.allowed {
				t.Errorf("EvaluatePolicy(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// File-based integration test: simple allow-list style PB
// ---------------------------------------------------------------------------

func TestLoadFromFile_SimpleAllowPB(t *testing.T) {
	// test-pb-simple-allow.json: pure Allow+Action list, no Deny, no NotAction.
	// Tests the straightforward "allowlist" PB style.
	pb, err := LoadFromFile(filepath.Join("..", "..", "testdata", "test-pb-simple-allow.json"))
	if err != nil {
		t.Fatalf("LoadFromFile test-pb-simple-allow.json: %v", err)
	}

	tests := []struct {
		action  string
		allowed bool
		note    string
	}{
		// Exact matches in the Allow list
		{"s3:GetObject", true, "exact match"},
		{"s3:PutObject", true, "exact match"},
		{"s3:ListBuckets", true, "exact match"},
		// Wildcard patterns in the Allow list match specific actions
		{"ec2:DescribeInstances", true, "matches ec2:Describe*"},
		{"ec2:DescribeSecurityGroups", true, "matches ec2:Describe*"},
		{"ec2:DescribeVpcs", true, "matches ec2:Describe*"},
		{"iam:GetRole", true, "matches iam:Get*"},
		{"iam:GetUser", true, "matches iam:Get*"},
		{"iam:ListUsers", true, "matches iam:List*"},
		{"iam:ListRoles", true, "matches iam:List*"},
		// Actions not in the Allow list → implicit deny
		{"ec2:RunInstances", false, "not in Allow list"},
		{"ec2:TerminateInstances", false, "not in Allow list"},
		{"iam:CreateRole", false, "not in Allow list"},
		{"iam:DeleteRole", false, "not in Allow list"},
		{"s3:DeleteBucket", false, "not in Allow list"},
		{"s3:DeleteObject", false, "not in Allow list"},
		{"athena:GetQueryResults", false, "athena not in Allow list at all"},
		{"cloudtrail:LookupEvents", false, "cloudtrail not in Allow list at all"},
		// Wildcard grant tokens: literal string must match an Allow entry
		// "ec2:Describe*" literal satisfies regex ^ec2:describe.*$ → allowed
		{"ec2:Describe*", true, "literal \"ec2:Describe*\" matches ec2:Describe* pattern"},
		// "iam:Get*" literal satisfies regex ^iam:get.*$ → allowed
		{"iam:Get*", true, "literal \"iam:Get*\" matches iam:Get* pattern"},
		// "ec2:*" does NOT match specific entries like ec2:Describe* because
		// the pattern ^ec2:describe.*$ requires 'describe' prefix → not allowed
		{"ec2:*", false, "ec2:* not covered by the specific ec2:Describe* Allow entry"},
		{"s3:*", false, "s3:* not covered: only specific s3 actions are allowed"},
		{"iam:*", false, "iam:* not covered: only Get/List operations are allowed"},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := IsActionAllowed(tc.action, pb)
			if got != tc.allowed {
				t.Errorf("IsActionAllowed(%q) = %v, want %v — %s", tc.action, got, tc.allowed, tc.note)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FindAllowingPatterns
// ---------------------------------------------------------------------------

func TestFindAllowingPatterns_PolicyDirect(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:Get*", "s3:List*", "ec2:Describe*"}},
			},
		},
	}
	patterns := FindAllowingPatterns("s3:GetObject", pb)
	if len(patterns) != 1 || patterns[0] != "s3:Get*" {
		t.Errorf("expected [s3:Get*], got %v", patterns)
	}
}

func TestFindAllowingPatterns_PolicyMultipleMatches(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:*", "s3:Get*"}},
			},
		},
	}
	patterns := FindAllowingPatterns("s3:GetObject", pb)
	if len(patterns) != 2 {
		t.Errorf("expected 2 matching patterns, got %v", patterns)
	}
}

func TestFindAllowingPatterns_PolicyNotAction(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", NotAction: []interface{}{"iam:*", "organizations:*"}},
			},
		},
	}
	patterns := FindAllowingPatterns("s3:GetObject", pb)
	if len(patterns) != 1 {
		t.Errorf("expected 1 NotAction pattern, got %v", patterns)
	}
	if len(patterns) > 0 && patterns[0] == "" {
		t.Error("pattern should describe the NotAction rule")
	}
}

func TestFindAllowingPatterns_PolicyNotAllowed(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:Get*"}},
			},
		},
	}
	patterns := FindAllowingPatterns("ec2:RunInstances", pb)
	if len(patterns) != 0 {
		t.Errorf("expected no patterns for denied action, got %v", patterns)
	}
}

func TestFindAllowingPatterns_PatternBased(t *testing.T) {
	pb := &PermissionBoundary{
		Patterns: []string{"s3:Get*", "ec2:Describe*"},
	}
	patterns := FindAllowingPatterns("s3:GetObject", pb)
	if len(patterns) != 1 || patterns[0] != "s3:Get*" {
		t.Errorf("expected [s3:Get*], got %v", patterns)
	}
}

func TestFindAllowingPatterns_DenyDoesNotSurface(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "*"},
				{Effect: "Deny", Action: []interface{}{"iam:CreateRole"}},
			},
		},
	}
	// iam:CreateRole is denied overall, but FindAllowingPatterns only returns allow-side matches
	patterns := FindAllowingPatterns("iam:CreateRole", pb)
	// It should return the Allow * pattern (the deny via Action is not surfaced here)
	if len(patterns) != 1 || patterns[0] != "*" {
		t.Errorf("expected [*] from Allow side, got %v", patterns)
	}
}

func TestFindAllowingPatterns_DenyNotAction_ShowsSavingPatterns(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "*"},
				{Effect: "Deny", NotAction: []interface{}{
					"ecr:*G*",
					"ecr:*be*",
					"ecr:*er*",
					"ecr:*g",
					"ecr:*ge",
					"ecr:*rt*",
					"ecr:L*",
					"ecr:V*",
					"s3:G*",
				}},
			},
		},
	}
	// ecr:CreatePullThroughCacheRule matches ecr:*er* (cach-er-ule) and ecr:*G* (throu-g-h)
	// via case-insensitive matching — these are the patterns that save it from the deny
	patterns := FindAllowingPatterns("ecr:CreatePullThroughCacheRule", pb)
	if len(patterns) == 0 {
		t.Fatal("expected matching NotAction patterns, got none")
	}
	// Should return the specific NotAction patterns, not just "*"
	for _, p := range patterns {
		if p == "*" {
			t.Error("expected specific NotAction patterns, not '*'")
		}
	}
}

func TestFindAllowingPatterns_DenyNotAction_NoMatch_FallsBackToAllow(t *testing.T) {
	pb := &PermissionBoundary{
		Policy: &policy.PolicyDocument{
			Statement: []policy.Statement{
				{Effect: "Allow", Action: []interface{}{"s3:Get*"}},
				{Effect: "Deny", NotAction: []interface{}{"ec2:Describe*"}},
			},
		},
	}
	// ec2:DescribeInstances matches the Deny+NotAction → not denied
	// but there's no Allow for ec2 — it's not allowed overall
	// s3:GetObject doesn't match the NotAction (no ec2) → it IS denied
	// This case is unusual; test that we get allow patterns when NotAction doesn't match
	patterns := FindAllowingPatterns("s3:GetObject", pb)
	// s3:GetObject is denied by the Deny+NotAction (not in ec2:Describe*),
	// but FindAllowingPatterns still returns the allow-side match
	if len(patterns) != 1 || patterns[0] != "s3:Get*" {
		t.Errorf("expected [s3:Get*], got %v", patterns)
	}
}
