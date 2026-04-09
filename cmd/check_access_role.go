package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// runCheckRole checks an IAM role's actions against a permission boundary.
func runCheckRole(cmd *cobra.Command, roleName string) error {
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	// If --pb was explicitly provided, load from file; otherwise fetch the role's own PB
	var pb *boundary.PermissionBoundary
	if cmd.Flags().Changed("pb") {
		pbFile, _ := cmd.Flags().GetString("pb")
		pb, err = boundary.LoadFromFile(pbFile)
		if err != nil {
			return fmt.Errorf("loading permission boundary: %w", err)
		}
	} else {
		pb, err = awsiam.FetchRoleBoundary(cmd.Context(), iamClient, roleName)
		if err != nil {
			return err
		}
	}

	managedPolicies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
	if err != nil {
		return fmt.Errorf("fetching managed policies: %w", err)
	}

	inlinePolicies, err := awsiam.FetchRoleInlinePolicies(cmd.Context(), iamClient, roleName)
	if err != nil {
		return fmt.Errorf("fetching inline policies: %w", err)
	}

	if len(managedPolicies) == 0 && len(inlinePolicies) == 0 {
		fmt.Println("No policies attached to role")
		return nil
	}

	// Merge all actions from managed and inline policies
	mergedAllow := make(map[string]string) // action -> policy name (with "(inline)" suffix for inline)
	mergedDeny := make(map[string]string)
	var allNotActionStmts []policy.NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	for policyName, policyDoc := range managedPolicies {
		extracted := policy.ExtractActions(policyDoc)
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

	for policyName, policyDoc := range inlinePolicies {
		extracted := policy.ExtractActions(policyDoc)
		hasWildcards = hasWildcards || extracted.HasWildcards
		hasConditions = hasConditions || extracted.HasConditions
		hasNotResources = hasNotResources || extracted.HasNotResources
		label := policyName + " (inline)"
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = label
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = label
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
	}

	mergedExtracted := policy.ExtractedActions{
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
		NotActionStmts:  allNotActionStmts,
	}

	// Sort actions
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
	mergedExtracted.AllowActions = allowActions
	mergedExtracted.DenyActions = denyActions

	// Evaluate against boundary
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

	switch format {
	case "json":
		warnings := policy.Warnings(mergedExtracted, true)
		managedNames := make([]string, 0, len(managedPolicies))
		for name := range managedPolicies {
			managedNames = append(managedNames, name)
		}
		sort.Strings(managedNames)

		inlineNames := make([]string, 0, len(inlinePolicies))
		for name := range inlinePolicies {
			inlineNames = append(inlineNames, name)
		}
		sort.Strings(inlineNames)

		blockedDetail := make([]map[string]string, 0, len(blockedActions))
		for _, a := range blockedActions {
			blockedDetail = append(blockedDetail, map[string]string{
				"action": a,
				"policy": mergedAllow[a],
			})
		}
		result := map[string]interface{}{
			"role":                  roleName,
			"evaluation_method":     pb.EvaluationMethod,
			"managed_policies":      managedNames,
			"inline_policies":       inlineNames,
			"allowed":               policy.NullableStringSlice(allowedActions),
			"blocked":               blockedDetail,
			"skipped_deny":          policy.NullableStringSlice(denyActions),
			"not_action_statements": policy.NullableStringSlice(notActionSummaries),
			"warnings":              warnings,
			"summary": map[string]int{
				"managed_policies":      len(managedPolicies),
				"inline_policies":       len(inlinePolicies),
				"allowed":               len(allowedActions),
				"blocked":               len(blockedActions),
				"skipped_deny":          len(denyActions),
				"not_action_statements": len(allNotActionStmts),
			},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default: // list
		warnings := policy.Warnings(mergedExtracted, false)
		fmt.Fprintf(os.Stderr, "Role: %s\n", roleName)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n", pb.EvaluationMethod)
		fmt.Fprintf(os.Stderr, "Managed policies: %d\n", len(managedPolicies))
		for name := range managedPolicies {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		fmt.Fprintf(os.Stderr, "Inline policies: %d\n", len(inlinePolicies))
		for name := range inlinePolicies {
			fmt.Fprintf(os.Stderr, "  - %s (inline)\n", name)
		}
		fmt.Fprintln(os.Stderr)
		printWarnings(warnings, os.Stderr)
		if len(allowedActions) > 0 {
			fmt.Println("🟢  Allowed actions:")
			for _, a := range allowedActions {
				fmt.Printf("    %-58s  — %s\n", a, mergedAllow[a])
			}
		}
		if len(blockedActions) > 0 {
			fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
			for _, a := range blockedActions {
				fmt.Printf("    %-58s  — %s\n", a, mergedAllow[a])
			}
		}
		if len(denyActions) > 0 {
			fmt.Println("\n🟡  Skipped actions (explicitly denied by policy):")
			for _, a := range denyActions {
				fmt.Printf("    %-58s  — %s\n", a, mergedDeny[a])
			}
		}
		if len(notActionSummaries) > 0 {
			fmt.Println("\n🟠  NotAction statements (requires manual review):")
			for _, s := range notActionSummaries {
				fmt.Printf("    %s\n", s)
			}
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
			len(allowedActions), len(blockedActions), len(denyActions), len(allNotActionStmts))
	}

	if len(blockedActions) > 0 {
		os.Exit(1)
	}
	return nil
}
