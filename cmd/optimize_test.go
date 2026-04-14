package cmd

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/policy"
)

func TestBuildStatementsFromAccessedMap(t *testing.T) {
	accessed := map[string]string{
		"ec2:createnetworkinterface":    "ec2:CreateNetworkInterface",
		"ec2:describenetworkinterfaces": "ec2:DescribeNetworkInterfaces",
		"kms:decrypt":                   "kms:Decrypt",
	}

	stmts := buildStatementsFromAccessedMap(accessed)

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements (one per service), got %d", len(stmts))
	}

	// Statements should be sorted by service name
	if stmts[0].Effect != "Allow" {
		t.Errorf("expected Allow, got %s", stmts[0].Effect)
	}
	if stmts[0].Resource != "*" {
		t.Errorf("expected *, got %v", stmts[0].Resource)
	}

	ec2Actions, ok := stmts[0].Action.([]string)
	if !ok {
		t.Fatalf("expected []string action, got %T", stmts[0].Action)
	}
	if len(ec2Actions) != 2 {
		t.Fatalf("expected 2 ec2 actions, got %d", len(ec2Actions))
	}
	if ec2Actions[0] != "ec2:CreateNetworkInterface" {
		t.Errorf("expected ec2:CreateNetworkInterface, got %s", ec2Actions[0])
	}

	kmsActions, ok := stmts[1].Action.([]string)
	if !ok {
		t.Fatalf("expected []string action, got %T", stmts[1].Action)
	}
	if len(kmsActions) != 1 || kmsActions[0] != "kms:Decrypt" {
		t.Errorf("expected [kms:Decrypt], got %v", kmsActions)
	}
}

func TestBuildStatementsFromAccessedMap_Empty(t *testing.T) {
	stmts := buildStatementsFromAccessedMap(map[string]string{})
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(stmts))
	}
}

func TestShrinkDocument_RemovesUnusedActions(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Allow",
			Action:   []interface{}{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
			Resource: "*",
		}},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
		"s3:putobject": "s3:PutObject",
	}

	shrunk, removed := shrinkDocument(doc, accessed, shrinkOptions{})

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed action, got %d: %v", len(removed), removed)
	}
	if removed[0] != "s3:DeleteObject" {
		t.Errorf("expected s3:DeleteObject removed, got %s", removed[0])
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_PreservesDenyStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Deny",
			Action:   []interface{}{"iam:*"},
			Resource: "*",
		}},
	}

	shrunk, removed := shrinkDocument(doc, map[string]string{}, shrinkOptions{})

	if len(removed) != 0 {
		t.Fatalf("Deny statements should not be pruned, got %d removed", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved, got %d", len(shrunk.Statement))
	}
	if shrunk.Statement[0].Effect != "Deny" {
		t.Errorf("expected Deny, got %s", shrunk.Statement[0].Effect)
	}
}

func TestShrinkDocument_IgnoresDenyStatementsWhenFlagSet(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Deny",
			Action:   []interface{}{"iam:*"},
			Resource: "*",
		}},
	}

	shrunk, removed := shrinkDocument(doc, map[string]string{}, shrinkOptions{ignoreDeny: true})

	if len(removed) != 0 {
		t.Fatalf("Deny statements should be ignored without adding removed actions, got %d removed", len(removed))
	}
	if len(shrunk.Statement) != 0 {
		t.Fatalf("expected Deny statement to be omitted, got %d statements", len(shrunk.Statement))
	}
}

func TestShrinkDocument_PreservesNotActionStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:    "Allow",
			NotAction: []interface{}{"iam:*"},
			Resource:  "*",
		}},
	}

	shrunk, removed := shrinkDocument(doc, map[string]string{}, shrinkOptions{})

	if len(removed) != 0 {
		t.Fatalf("NotAction statements should not be pruned, got %d removed", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_RemovesEntireStatementIfAllUnused(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Allow",
			Action:   []interface{}{"s3:GetObject"},
			Resource: "*",
		}},
	}

	shrunk, removed := shrinkDocument(doc, map[string]string{}, shrinkOptions{})

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed action, got %d", len(removed))
	}
	if len(shrunk.Statement) != 0 {
		t.Fatalf("expected 0 statements (entire statement pruned), got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_SingleSurvivingActionBecomesString(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Allow",
			Action:   []interface{}{"s3:GetObject", "s3:PutObject"},
			Resource: "*",
		}},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
	}

	shrunk, removed := shrinkDocument(doc, accessed, shrinkOptions{})

	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(removed))
	}
	action, ok := shrunk.Statement[0].Action.(string)
	if !ok {
		t.Fatalf("expected string action for single surviving, got %T", shrunk.Statement[0].Action)
	}
	if action != "s3:GetObject" {
		t.Errorf("expected s3:GetObject, got %s", action)
	}
}

func TestShrinkDocument_PreservesStatementsWithNilAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Effect:   "Allow",
			Resource: "*",
		}},
	}

	shrunk, _ := shrinkDocument(doc, map[string]string{}, shrinkOptions{})

	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement preserved (nil Action), got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_PreservesSidAndCondition(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{{
			Sid:       "AllowS3",
			Effect:    "Allow",
			Action:    []interface{}{"s3:GetObject", "s3:PutObject"},
			Resource:  "arn:aws:s3:::my-bucket/*",
			Condition: map[string]interface{}{"StringEquals": map[string]interface{}{"s3:prefix": "home/"}},
		}},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
	}

	shrunk, _ := shrinkDocument(doc, accessed, shrinkOptions{})

	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
	if shrunk.Statement[0].Sid != "AllowS3" {
		t.Errorf("Sid not preserved: got %q", shrunk.Statement[0].Sid)
	}
	if shrunk.Statement[0].Condition == nil {
		t.Error("Condition not preserved")
	}
	if shrunk.Statement[0].Resource != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("Resource not preserved: got %v", shrunk.Statement[0].Resource)
	}
}

func TestShrinkDocument_MixedStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "*"},
			{Effect: "Deny", Action: []interface{}{"iam:*"}, Resource: "*"},
			{Effect: "Allow", Action: []interface{}{"ec2:RunInstances"}, Resource: "*"},
			{Effect: "Allow", NotAction: []interface{}{"sts:*"}, Resource: "*"},
		},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
	}

	shrunk, removed := shrinkDocument(doc, accessed, shrinkOptions{})

	if len(removed) != 2 {
		t.Fatalf("expected 2 removed, got %d: %v", len(removed), removed)
	}
	if len(shrunk.Statement) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_StringAction(t *testing.T) {
	doc := policy.PolicyDocument{
		Version:   "2012-10-17",
		Statement: []policy.Statement{{Effect: "Allow", Action: "s3:GetObject", Resource: "*"}},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
	}

	shrunk, removed := shrinkDocument(doc, accessed, shrinkOptions{})

	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
}

func TestShrinkDocument_StrictExpandsWildcardActions(t *testing.T) {
	doc := policy.PolicyDocument{
		Version:   "2012-10-17",
		Statement: []policy.Statement{{Effect: "Allow", Action: "s3:*", Resource: "*"}},
	}
	accessed := map[string]string{
		"s3:getbucketlocation": "s3:GetBucketLocation",
		"s3:getobject":         "s3:GetObject",
		"s3:putobject":         "s3:PutObject",
	}

	shrunk, removed := shrinkDocument(doc, accessed, shrinkOptions{strict: true})

	if len(removed) != 0 {
		t.Fatalf("expected wildcard action to expand instead of being removed, got %v", removed)
	}
	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(shrunk.Statement))
	}
	actions, ok := shrunk.Statement[0].Action.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} action list, got %T", shrunk.Statement[0].Action)
	}
	if len(actions) != 3 {
		t.Fatalf("expected 3 expanded actions, got %d", len(actions))
	}
}

func TestShrinkDocument_StrictDedupesEquivalentStatements(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:*", Resource: "*"},
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "*"},
		},
	}
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
		"s3:putobject": "s3:PutObject",
	}

	shrunk, _ := shrinkDocument(doc, accessed, shrinkOptions{strict: true})

	if len(shrunk.Statement) != 1 {
		t.Fatalf("expected equivalent statements to be deduplicated, got %d", len(shrunk.Statement))
	}
	actions, ok := shrunk.Statement[0].Action.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} action list, got %T", shrunk.Statement[0].Action)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions after dedupe, got %d", len(actions))
	}
}

func TestShrinkDocument_StrictPreservesTargetedResources(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Sid: "One", Effect: "Allow", Action: "logs:CreateLogStream", Resource: "*"},
			{Sid: "Two", Effect: "Allow", Action: "logs:CreateLogStream", Resource: []interface{}{"arn:aws:logs:*:*:log-group:/aws/lambda-insights:*"}},
			{Effect: "Allow", Action: "logs:CreateLogStream", Resource: []interface{}{"*"}},
		},
	}
	accessed := map[string]string{
		"logs:createlogstream": "logs:CreateLogStream",
	}

	shrunk, _ := shrinkDocument(doc, accessed, shrinkOptions{strict: true})

	if len(shrunk.Statement) != 2 {
		t.Fatalf("expected wildcard duplicate to collapse but targeted resource to remain, got %d statements", len(shrunk.Statement))
	}

	var hasWildcard bool
	var hasTargeted bool
	for _, stmt := range shrunk.Statement {
		resource, ok := stmt.Resource.(string)
		if !ok {
			t.Fatalf("expected normalized resource strings, got %T", stmt.Resource)
		}
		if resource == "*" {
			hasWildcard = true
		}
		if resource == "arn:aws:logs:*:*:log-group:/aws/lambda-insights:*" {
			hasTargeted = true
		}
	}
	if !hasWildcard || !hasTargeted {
		t.Fatalf("expected both wildcard and targeted resources, got %+v", shrunk.Statement)
	}
}

func TestShrinkDocument_DedupesRemovedActions(t *testing.T) {
	doc := policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{Effect: "Allow", Action: "s3:GetObject", Resource: "*"},
			{Effect: "Allow", Action: []interface{}{"s3:GetObject", "s3:PutObject"}, Resource: "*"},
		},
	}

	_, removed := shrinkDocument(doc, map[string]string{}, shrinkOptions{})

	if len(removed) != 2 {
		t.Fatalf("expected unique removed actions, got %d: %v", len(removed), removed)
	}
	if removed[0] != "s3:GetObject" || removed[1] != "s3:PutObject" {
		t.Fatalf("expected sorted unique removed actions, got %v", removed)
	}
}

func TestIsActionAccessed_DirectMatch(t *testing.T) {
	accessed := map[string]string{"s3:getobject": "s3:GetObject"}
	if !isActionAccessed("s3:GetObject", accessed) {
		t.Error("expected case-insensitive match for s3:GetObject")
	}
}

func TestIsActionAccessed_NoMatch(t *testing.T) {
	accessed := map[string]string{"s3:getobject": "s3:GetObject"}
	if isActionAccessed("s3:PutObject", accessed) {
		t.Error("s3:PutObject should not match")
	}
}

func TestIsActionAccessed_WildcardMatch(t *testing.T) {
	accessed := map[string]string{
		"s3:getobject": "s3:GetObject",
		"s3:putobject": "s3:PutObject",
	}
	if !isActionAccessed("s3:*", accessed) {
		t.Error("s3:* should match accessed s3 actions")
	}
}

func TestIsActionAccessed_WildcardNoMatch(t *testing.T) {
	accessed := map[string]string{"ec2:describeinstances": "ec2:DescribeInstances"}
	if isActionAccessed("s3:*", accessed) {
		t.Error("s3:* should not match ec2 actions")
	}
}

func TestIsActionAccessed_PartialWildcard(t *testing.T) {
	accessed := map[string]string{
		"s3:getobject":       "s3:GetObject",
		"s3:getbucketpolicy": "s3:GetBucketPolicy",
	}
	if !isActionAccessed("s3:Get*", accessed) {
		t.Error("s3:Get* should match s3:getobject")
	}
}

func TestIsActionAccessed_EmptyAccessed(t *testing.T) {
	accessed := map[string]string{}
	if isActionAccessed("s3:GetObject", accessed) {
		t.Error("nothing accessed, should return false")
	}
	if isActionAccessed("s3:*", accessed) {
		t.Error("wildcard with nothing accessed should return false")
	}
}

func TestMergePolicyDocs(t *testing.T) {
	policies := map[string]policy.PolicyDocument{
		"PolicyA": {
			Version: "2012-10-17",
			Statement: []policy.Statement{{
				Effect:   "Allow",
				Action:   "s3:GetObject",
				Resource: "*",
			}},
		},
		"PolicyB": {
			Version: "2012-10-17",
			Statement: []policy.Statement{
				{Effect: "Allow", Action: "ec2:RunInstances", Resource: "*"},
				{Effect: "Deny", Action: "iam:*", Resource: "*"},
			},
		},
	}

	merged := mergePolicyDocs(policies)

	if merged.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", merged.Version)
	}
	if len(merged.Statement) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(merged.Statement))
	}
}

func TestMergePolicyDocs_Empty(t *testing.T) {
	policies := map[string]policy.PolicyDocument{}

	merged := mergePolicyDocs(policies)

	if len(merged.Statement) != 0 {
		t.Fatalf("expected 0 statements for empty input, got %d", len(merged.Statement))
	}
}

func TestValueOrEmpty_Nil(t *testing.T) {
	if got := valueOrEmpty(nil); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestValueOrEmpty_WithMessage(t *testing.T) {
	err := &iamtypes.ErrorDetails{
		Message: aws.String("something went wrong"),
	}
	if got := valueOrEmpty(err); got != "something went wrong" {
		t.Errorf("expected 'something went wrong', got %q", got)
	}
}

func TestValueOrEmpty_NilMessage(t *testing.T) {
	err := &iamtypes.ErrorDetails{}
	if got := valueOrEmpty(err); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
