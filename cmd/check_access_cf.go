package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/cfn"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// cfResourceAnalysis holds the fully-evaluated results for one CloudFormation IAM resource.
type cfResourceAnalysis struct {
	LogicalID            string
	ResourceType         string
	Line                 int
	EvaluationMethod     string
	AllowedActions       []string
	BlockedActions       []string
	ActionSources        map[string]string // action -> source policy name (for all Allow actions)
	DenyActions          []string
	DenySources          map[string]string
	NotActionSummaries   []string
	AllPolicyNames       []string
	InlinePoliciesCount  int
	ManagedPoliciesCount int
	extracted            policy.ExtractedActions
}

// runCheckCf checks CloudFormation IAM resources against a permission boundary.
func runCheckCf(cmd *cobra.Command, templateFile string) error {
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")
	resource, _ := cmd.Flags().GetString("resource")

	tmpl, err := cfn.ParseTemplate(templateFile)
	if err != nil {
		return err
	}

	roles, err := cfn.ExtractIAMRoles(tmpl)
	if err != nil {
		return err
	}

	policies, err := cfn.ExtractIAMPolicies(tmpl)
	if err != nil {
		return err
	}

	// Filter to a specific resource if requested
	if resource != "" {
		var filteredRoles []cfn.IAMRole
		for _, r := range roles {
			if r.LogicalID == resource {
				filteredRoles = append(filteredRoles, r)
			}
		}
		var filteredPolicies []cfn.IAMPolicyResource
		for _, p := range policies {
			if p.LogicalID == resource {
				filteredPolicies = append(filteredPolicies, p)
			}
		}
		if len(filteredRoles) == 0 && len(filteredPolicies) == 0 {
			var available []string
			for _, r := range roles {
				available = append(available, r.LogicalID)
			}
			for _, p := range policies {
				available = append(available, p.LogicalID)
			}
			return fmt.Errorf("resource %q not found; available IAM resources: %s", resource, strings.Join(available, ", "))
		}
		roles = filteredRoles
		policies = filteredPolicies
	}

	if len(roles) == 0 && len(policies) == 0 {
		fmt.Println("No IAM role or policy resources found in template")
		return nil
	}

	// Collect analyses for all resources
	var analyses []*cfResourceAnalysis

	for _, role := range roles {
		a, err := analyzeCfRole(cmd, role, profile)
		if err != nil {
			return fmt.Errorf("checking role %q: %w", role.LogicalID, err)
		}
		if a != nil {
			analyses = append(analyses, a)
		}
	}

	for _, pol := range policies {
		a, err := analyzeCfPolicy(cmd, pol)
		if err != nil {
			return fmt.Errorf("checking policy %q: %w", pol.LogicalID, err)
		}
		if a != nil {
			analyses = append(analyses, a)
		}
	}

	hasBlocked := false
	for _, a := range analyses {
		if len(a.BlockedActions) > 0 {
			hasBlocked = true
			break
		}
	}

	switch format {
	case "sarif":
		printCfSARIF(analyses, templateFile, cmd.Root().Version)
	default:
		for i, a := range analyses {
			if i > 0 {
				fmt.Println()
				fmt.Println(strings.Repeat("=", 80))
				fmt.Println()
			}
			renderCfAnalysis(cmd, a, format)
		}
	}

	if hasBlocked {
		os.Exit(1)
	}
	return nil
}

// analyzeCfRole resolves the permission boundary, fetches managed policies, and evaluates
// all actions for a CloudFormation IAM role. It does not produce any output.
func analyzeCfRole(cmd *cobra.Command, role cfn.IAMRole, profile string) (*cfResourceAnalysis, error) {
	ctx := cmd.Context()

	needsAWS := len(role.Properties.ManagedPolicyArns) > 0 || len(role.Properties.ManagedPolicyArnsRaw) > 0
	if !cmd.Flags().Changed("pb") && (role.Properties.PermissionBoundary != "" || role.Properties.PermissionBoundaryRaw != nil) {
		needsAWS = true
	}

	var iamClient awsiam.IAMClient
	if needsAWS {
		var err error
		iamClient, err = awsiam.NewIAMClient(ctx, profile)
		if err != nil {
			return nil, err
		}
	}

	var pb *boundary.PermissionBoundary
	if cmd.Flags().Changed("pb") {
		pbFile, _ := cmd.Flags().GetString("pb")
		var err error
		pb, err = boundary.LoadFromFile(pbFile)
		if err != nil {
			return nil, fmt.Errorf("loading permission boundary: %w", err)
		}
	} else if role.Properties.PermissionBoundary != "" {
		pbArn := role.Properties.PermissionBoundary
		fmt.Fprintf(os.Stderr, "Fetching permission boundary from template ARN: %s\n", pbArn)
		var err error
		pb, err = awsiam.FetchManagedPolicyAsBoundary(ctx, iamClient, pbArn)
		if err != nil {
			return nil, fmt.Errorf("fetching permission boundary %q: %w", pbArn, err)
		}
	} else if role.Properties.PermissionBoundaryRaw != nil {
		fmt.Fprintf(os.Stderr, "Resolving PermissionsBoundary intrinsic function...\n")
		pseudoParams, err := awsiam.GetAWSPseudoParams(ctx, profile)
		if err != nil {
			return nil, fmt.Errorf("fetching AWS context for intrinsic resolution: %w (use --pb to provide it manually)", err)
		}
		pbArn, err := cfn.ResolveIntrinsic(role.Properties.PermissionBoundaryRaw, pseudoParams)
		if err != nil {
			return nil, fmt.Errorf("resolving PermissionsBoundary intrinsic for role %q: %w (use --pb to provide it manually)", role.LogicalID, err)
		}
		fmt.Fprintf(os.Stderr, "Resolved permission boundary ARN: %s\n", pbArn)
		if iamClient == nil {
			iamClient, err = awsiam.NewIAMClient(ctx, profile)
			if err != nil {
				return nil, err
			}
		}
		pb, err = awsiam.FetchManagedPolicyAsBoundary(ctx, iamClient, pbArn)
		if err != nil {
			return nil, fmt.Errorf("fetching permission boundary %q: %w", pbArn, err)
		}
	} else {
		return nil, fmt.Errorf("role %q has no PermissionsBoundary in template and --pb was not provided", role.LogicalID)
	}

	mergedAllow := make(map[string]string) // action -> source policy name
	mergedDeny := make(map[string]string)
	var allNotActionStmts []policy.NotActionStatement
	hasWildcards, hasConditions, hasNotResources := false, false, false

	for policyName, doc := range role.Properties.InlinePolicies {
		extracted := policy.ExtractActions(doc)
		hasWildcards = hasWildcards || extracted.HasWildcards
		hasConditions = hasConditions || extracted.HasConditions
		hasNotResources = hasNotResources || extracted.HasNotResources
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = policyName + " (inline)"
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = policyName + " (inline)"
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
	}

	var managedPolicyNames []string

	if len(role.Properties.ManagedPolicyArnsRaw) > 0 {
		pseudoParams, err := awsiam.GetAWSPseudoParams(ctx, profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not resolve intrinsic ManagedPolicyArns: %v\n", err)
		} else {
			for _, raw := range role.Properties.ManagedPolicyArnsRaw {
				resolved, err := cfn.ResolveIntrinsic(raw, pseudoParams)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: skipping unresolvable ManagedPolicyArn: %v\n", err)
					continue
				}
				fmt.Fprintf(os.Stderr, "Resolved ManagedPolicyArn: %s\n", resolved)
				role.Properties.ManagedPolicyArns = append(role.Properties.ManagedPolicyArns, resolved)
			}
		}
	}

	for _, arn := range role.Properties.ManagedPolicyArns {
		fmt.Fprintf(os.Stderr, "Fetching managed policy: %s\n", arn)
		doc, err := awsiam.FetchManagedPolicy(ctx, iamClient, arn)
		if err != nil {
			return nil, fmt.Errorf("fetching managed policy %q: %w", arn, err)
		}
		policyName := arn
		if parts := strings.Split(arn, "/"); len(parts) > 0 {
			policyName = parts[len(parts)-1]
		}
		managedPolicyNames = append(managedPolicyNames, policyName)

		extracted := policy.ExtractActions(*doc)
		hasWildcards = hasWildcards || extracted.HasWildcards
		hasConditions = hasConditions || extracted.HasConditions
		hasNotResources = hasNotResources || extracted.HasNotResources
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = policyName
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = policyName
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
	}

	totalPolicies := len(role.Properties.InlinePolicies) + len(role.Properties.ManagedPolicyArns)
	if totalPolicies == 0 {
		fmt.Fprintf(os.Stderr, "Role %s: no policies found\n", role.LogicalID)
		return nil, nil
	}

	var allowActions []string
	for a := range mergedAllow {
		allowActions = append(allowActions, a)
	}
	sort.Strings(allowActions)

	var denyActions []string
	for a := range mergedDeny {
		denyActions = append(denyActions, a)
	}
	sort.Strings(denyActions)

	mergedExtracted := policy.ExtractedActions{
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
		NotActionStmts:  allNotActionStmts,
		AllowActions:    allowActions,
		DenyActions:     denyActions,
	}

	var allowedActions, blockedActions []string
	for _, action := range allowActions {
		if boundary.IsActionAllowed(action, pb) {
			allowedActions = append(allowedActions, action)
		} else {
			blockedActions = append(blockedActions, action)
		}
	}
	sort.Strings(allowedActions)
	sort.Strings(blockedActions)

	var notActionSummaries []string
	for _, nas := range allNotActionStmts {
		summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
		if nas.Condition != nil {
			summary += " (has Condition)"
		}
		notActionSummaries = append(notActionSummaries, summary)
	}

	var allPolicyNames []string
	for name := range role.Properties.InlinePolicies {
		allPolicyNames = append(allPolicyNames, name+" (inline)")
	}
	allPolicyNames = append(allPolicyNames, managedPolicyNames...)
	sort.Strings(allPolicyNames)

	return &cfResourceAnalysis{
		LogicalID:            role.LogicalID,
		ResourceType:         "AWS::IAM::Role",
		Line:                 role.Line,
		EvaluationMethod:     pb.EvaluationMethod,
		AllowedActions:       allowedActions,
		BlockedActions:       blockedActions,
		ActionSources:        mergedAllow,
		DenyActions:          denyActions,
		DenySources:          mergedDeny,
		NotActionSummaries:   notActionSummaries,
		AllPolicyNames:       allPolicyNames,
		InlinePoliciesCount:  len(role.Properties.InlinePolicies),
		ManagedPoliciesCount: len(role.Properties.ManagedPolicyArns),
		extracted:            mergedExtracted,
	}, nil
}

// analyzeCfPolicy evaluates a standalone CloudFormation IAM policy resource.
// It does not produce any output.
func analyzeCfPolicy(cmd *cobra.Command, pol cfn.IAMPolicyResource) (*cfResourceAnalysis, error) {
	if !cmd.Flags().Changed("pb") {
		return nil, fmt.Errorf("policy %q (%s) requires --pb to specify a permission boundary", pol.LogicalID, pol.Type)
	}

	pbFile, _ := cmd.Flags().GetString("pb")
	pb, err := boundary.LoadFromFile(pbFile)
	if err != nil {
		return nil, fmt.Errorf("loading permission boundary: %w", err)
	}

	extracted := policy.ExtractActions(pol.PolicyDocument)

	if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 && len(extracted.NotActionStmts) == 0 {
		fmt.Fprintf(os.Stderr, "Resource %s (%s): no actions found\n", pol.LogicalID, pol.Type)
		return nil, nil
	}

	var allowedActions, blockedActions []string
	for _, action := range extracted.AllowActions {
		if boundary.IsActionAllowed(action, pb) {
			allowedActions = append(allowedActions, action)
		} else {
			blockedActions = append(blockedActions, action)
		}
	}
	sort.Strings(allowedActions)
	sort.Strings(blockedActions)

	var notActionSummaries []string
	for _, nas := range extracted.NotActionStmts {
		summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
		if nas.Condition != nil {
			summary += " (has Condition)"
		}
		notActionSummaries = append(notActionSummaries, summary)
	}

	return &cfResourceAnalysis{
		LogicalID:          pol.LogicalID,
		ResourceType:       pol.Type,
		Line:               pol.Line,
		EvaluationMethod:   pb.EvaluationMethod,
		AllowedActions:     allowedActions,
		BlockedActions:     blockedActions,
		ActionSources:      nil, // standalone policies have no source breakdown
		DenyActions:        extracted.DenyActions,
		NotActionSummaries: notActionSummaries,
		extracted:          extracted,
	}, nil
}

// renderCfAnalysis prints the analysis for a single resource in list or json format.
func renderCfAnalysis(cmd *cobra.Command, a *cfResourceAnalysis, format string) {
	switch format {
	case "json":
		warnings := policy.Warnings(a.extracted, true)
		blockedDetail := make([]map[string]string, 0, len(a.BlockedActions))
		for _, action := range a.BlockedActions {
			entry := map[string]string{"action": action}
			if a.ActionSources != nil {
				entry["source"] = a.ActionSources[action]
			}
			blockedDetail = append(blockedDetail, entry)
		}
		result := map[string]interface{}{
			"resource":              a.LogicalID,
			"resource_type":         a.ResourceType,
			"evaluation_method":     a.EvaluationMethod,
			"allowed":               policy.NullableStringSlice(a.AllowedActions),
			"blocked":               blockedDetail,
			"skipped_deny":          policy.NullableStringSlice(a.DenyActions),
			"not_action_statements": policy.NullableStringSlice(a.NotActionSummaries),
			"warnings":              warnings,
			"summary": map[string]int{
				"allowed":               len(a.AllowedActions),
				"blocked":               len(a.BlockedActions),
				"skipped_deny":          len(a.DenyActions),
				"not_action_statements": len(a.extracted.NotActionStmts),
			},
		}
		if a.ResourceType == "AWS::IAM::Role" {
			result["policies"] = a.AllPolicyNames
			result["summary"].(map[string]int)["inline_policies"] = a.InlinePoliciesCount
			result["summary"].(map[string]int)["managed_policies"] = a.ManagedPoliciesCount
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default: // list
		warnings := policy.Warnings(a.extracted, false)
		fmt.Fprintf(os.Stderr, "Resource: %s (%s)\n", a.LogicalID, a.ResourceType)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n", a.EvaluationMethod)
		if a.ResourceType == "AWS::IAM::Role" {
			fmt.Fprintf(os.Stderr, "Policies: %d inline, %d managed\n", a.InlinePoliciesCount, a.ManagedPoliciesCount)
			for _, name := range a.AllPolicyNames {
				fmt.Fprintf(os.Stderr, "  - %s\n", name)
			}
		}
		fmt.Fprintln(os.Stderr)
		printWarnings(warnings, os.Stderr)
		if len(a.AllowedActions) > 0 {
			fmt.Println("🟢  Allowed actions:")
			for _, action := range a.AllowedActions {
				if a.ActionSources != nil {
					fmt.Printf("    %-58s  — %s\n", action, a.ActionSources[action])
				} else {
					fmt.Printf("    %s\n", action)
				}
			}
		}
		if len(a.BlockedActions) > 0 {
			fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
			for _, action := range a.BlockedActions {
				if a.ActionSources != nil {
					fmt.Printf("    %-58s  — %s\n", action, a.ActionSources[action])
				} else {
					fmt.Printf("    %s\n", action)
				}
			}
		}
		if len(a.DenyActions) > 0 {
			fmt.Println("\n🟡  Skipped actions (explicitly denied by policy):")
			for _, action := range a.DenyActions {
				if a.DenySources != nil {
					fmt.Printf("    %-58s  — %s\n", action, a.DenySources[action])
				} else {
					fmt.Printf("    %s\n", action)
				}
			}
		}
		if len(a.NotActionSummaries) > 0 {
			fmt.Println("\n🟠  NotAction statements (requires manual review):")
			for _, s := range a.NotActionSummaries {
				fmt.Printf("    %s\n", s)
			}
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
			len(a.AllowedActions), len(a.BlockedActions), len(a.DenyActions), len(a.extracted.NotActionStmts))
	}
}

// printCfSARIF emits a single SARIF 2.1.0 document covering all resources to stdout.
func printCfSARIF(analyses []*cfResourceAnalysis, templateFile, version string) {
	uri := filepath.ToSlash(templateFile)

	rules := []interface{}{
		map[string]interface{}{
			"id":   "PB001",
			"name": "ActionBlockedByPermissionBoundary",
			"shortDescription": map[string]string{
				"text": "IAM action blocked by permission boundary",
			},
			"helpUri":              "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
			"defaultConfiguration": map[string]string{"level": "error"},
		},
		map[string]interface{}{
			"id":   "PB002",
			"name": "WildcardActionNeedsReview",
			"shortDescription": map[string]string{
				"text": "Wildcard IAM action cannot be fully evaluated against the permission boundary",
			},
			"helpUri":              "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html",
			"defaultConfiguration": map[string]string{"level": "warning"},
		},
		map[string]interface{}{
			"id":   "PB003",
			"name": "NotActionStatementNeedsReview",
			"shortDescription": map[string]string{
				"text": "NotAction statement cannot be fully evaluated against the permission boundary",
			},
			"helpUri":              "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
			"defaultConfiguration": map[string]string{"level": "warning"},
		},
	}

	var results []interface{}
	for _, a := range analyses {
		loc := sarifLocation(uri, a.Line, a.LogicalID, a.ResourceType)

		// PB001 — one result per blocked action
		for _, action := range a.BlockedActions {
			msg := fmt.Sprintf("Action '%s' is blocked by the permission boundary", action)
			if a.ActionSources != nil {
				if src := a.ActionSources[action]; src != "" {
					msg += fmt.Sprintf(" (source: %s)", src)
				}
			}
			results = append(results, map[string]interface{}{
				"ruleId":    "PB001",
				"level":     "error",
				"message":   map[string]string{"text": msg},
				"locations": []interface{}{loc},
			})
		}

		// PB002 — one result per resource that has wildcard actions
		if a.extracted.HasWildcards {
			results = append(results, map[string]interface{}{
				"ruleId": "PB002",
				"level":  "warning",
				"message": map[string]string{
					"text": fmt.Sprintf("Resource '%s' (%s) contains wildcard actions that require manual review against the permission boundary", a.LogicalID, a.ResourceType),
				},
				"locations": []interface{}{loc},
			})
		}

		// PB003 — one result per NotAction statement
		for _, summary := range a.NotActionSummaries {
			results = append(results, map[string]interface{}{
				"ruleId": "PB003",
				"level":  "warning",
				"message": map[string]string{
					"text": fmt.Sprintf("Resource '%s' (%s) has a NotAction statement that requires manual review: %s", a.LogicalID, a.ResourceType, summary),
				},
				"locations": []interface{}{loc},
			})
		}
	}

	if results == nil {
		results = []interface{}{}
	}

	sarif := map[string]interface{}{
		"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "iamctl",
						"version":        version,
						"informationUri": "https://github.com/jordiprats/iamctl",
						"rules":          rules,
					},
				},
				"artifacts": []interface{}{
					map[string]interface{}{
						"location": map[string]interface{}{
							"uri":       uri,
							"uriBaseId": "%SRCROOT%",
						},
					},
				},
				"results": results,
			},
		},
	}

	out, _ := json.MarshalIndent(sarif, "", "  ")
	fmt.Println(string(out))
}

func sarifLocation(templateURI string, line int, logicalID, resourceType string) map[string]interface{} {
	physLoc := map[string]interface{}{
		"artifactLocation": map[string]interface{}{
			"uri":       templateURI,
			"uriBaseId": "%SRCROOT%",
		},
	}
	if line > 0 {
		physLoc["region"] = map[string]interface{}{
			"startLine":   line,
			"startColumn": 1,
		}
	}
	return map[string]interface{}{
		"physicalLocation": physLoc,
		"logicalLocations": []interface{}{
			map[string]interface{}{
				"name":          logicalID,
				"decoratedName": fmt.Sprintf("%s (%s)", logicalID, resourceType),
				"kind":          "resource",
			},
		},
	}
}
