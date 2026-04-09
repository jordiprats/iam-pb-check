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

// runCheckPolicy checks policy actions against a permission boundary.
func runCheckPolicy(cmd *cobra.Command, policyFile string) error {
	pbFile, _ := cmd.Flags().GetString("pb")
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")
	managedPolicies, _ := cmd.Flags().GetStringSlice("managed-policy")
	policyFiles, _ := cmd.Flags().GetStringSlice("policy-file")

	if policyFile == "" && len(managedPolicies) == 0 && len(policyFiles) == 0 {
		return fmt.Errorf("at least one of a policy file, --policy-file, or --managed-policy must be specified")
	}

	if pbFile == "" {
		return fmt.Errorf("--pb is required when checking policies")
	}

	// Merge actions from all policy sources
	mergedAllow := make(map[string]bool)
	mergedDeny := make(map[string]bool)
	var allNotActionStmts []policy.NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	// Load local policy file if provided
	if policyFile != "" {
		data, err := policy.ReadFromPathOrStdin(policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parsing policy JSON: %w", err)
		}
		extracted := policy.ExtractActions(doc)
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = true
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = true
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
		hasWildcards = hasWildcards || extracted.HasWildcards
		hasConditions = hasConditions || extracted.HasConditions
		hasNotResources = hasNotResources || extracted.HasNotResources
	}

	// Load additional local policy files if provided
	for _, pf := range policyFiles {
		data, err := policy.ReadFromPathOrStdin(pf)
		if err != nil {
			return fmt.Errorf("reading policy file %q: %w", pf, err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parsing policy JSON %q: %w", pf, err)
		}
		extracted := policy.ExtractActions(doc)
		for _, a := range extracted.AllowActions {
			mergedAllow[a] = true
		}
		for _, a := range extracted.DenyActions {
			mergedDeny[a] = true
		}
		allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
		hasWildcards = hasWildcards || extracted.HasWildcards
		hasConditions = hasConditions || extracted.HasConditions
		hasNotResources = hasNotResources || extracted.HasNotResources
	}

	// Fetch managed policies from AWS if provided
	if len(managedPolicies) > 0 {
		ctx := cmd.Context()
		iamClient, err := awsiam.NewIAMClient(ctx, profile)
		if err != nil {
			return fmt.Errorf("creating AWS IAM client: %w", err)
		}
		for _, arn := range managedPolicies {
			doc, err := awsiam.FetchManagedPolicy(ctx, iamClient, arn)
			if err != nil {
				return err
			}
			extracted := policy.ExtractActions(*doc)
			for _, a := range extracted.AllowActions {
				mergedAllow[a] = true
			}
			for _, a := range extracted.DenyActions {
				mergedDeny[a] = true
			}
			allNotActionStmts = append(allNotActionStmts, extracted.NotActionStmts...)
			hasWildcards = hasWildcards || extracted.HasWildcards
			hasConditions = hasConditions || extracted.HasConditions
			hasNotResources = hasNotResources || extracted.HasNotResources
		}
	}

	// Build sorted action lists
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

	extracted := policy.ExtractedActions{
		AllowActions:    allowActions,
		DenyActions:     denyActions,
		NotActionStmts:  allNotActionStmts,
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
	}

	if len(allowActions) == 0 && len(denyActions) == 0 && len(allNotActionStmts) == 0 {
		fmt.Println("No actions found in policy")
		return nil
	}

	pb, err := boundary.LoadFromFile(pbFile)
	if err != nil {
		return fmt.Errorf("loading permission boundary: %w", err)
	}

	// Evaluate Allow actions against the permission boundary
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

	// Summarise NotAction statements for display
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
		warnings := policy.Warnings(extracted, true)
		result := map[string]interface{}{
			"evaluation_method":     pb.EvaluationMethod,
			"allowed":               policy.NullableStringSlice(allowedActions),
			"blocked":               policy.NullableStringSlice(blockedActions),
			"skipped_deny":          policy.NullableStringSlice(denyActions),
			"not_action_statements": policy.NullableStringSlice(notActionSummaries),
			"warnings":              warnings,
			"summary": map[string]int{
				"allowed":               len(allowedActions),
				"blocked":               len(blockedActions),
				"skipped_deny":          len(denyActions),
				"not_action_statements": len(allNotActionStmts),
			},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "table":
		warnings := policy.Warnings(extracted, false)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
		printWarnings(warnings, os.Stderr)
		fmt.Printf("%-4s %-58s %s\n", "", "ACTION", "STATUS")
		fmt.Printf("%s\n", strings.Repeat("-", 75))
		for _, a := range allowedActions {
			fmt.Printf("🟢  %-58s ALLOWED\n", a)
		}
		for _, a := range blockedActions {
			fmt.Printf("🔴  %-58s BLOCKED\n", a)
		}
		for _, a := range denyActions {
			fmt.Printf("🟡  %-58s SKIPPED (explicitly denied by policy)\n", a)
		}
		for _, s := range notActionSummaries {
			fmt.Printf("🟠  %-58s NOTACTION (manual review needed)\n", s)
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
			len(allowedActions), len(blockedActions), len(denyActions), len(allNotActionStmts))

	default: // list
		warnings := policy.Warnings(extracted, false)
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
		printWarnings(warnings, os.Stderr)
		if len(allowedActions) > 0 {
			fmt.Println("🟢  Allowed actions:")
			for _, a := range allowedActions {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(blockedActions) > 0 {
			fmt.Println("\n🔴  Blocked actions (not allowed by permission boundary):")
			for _, a := range blockedActions {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(denyActions) > 0 {
			fmt.Println("\n🟡  Skipped actions (explicitly denied by policy, irrelevant to boundary check):")
			for _, a := range denyActions {
				fmt.Printf("    %s\n", a)
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
