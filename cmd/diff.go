package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/cfn"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// diffSide holds resolved actions for one side of a diff comparison.
type diffSide struct {
	label     string
	extracted policy.ExtractedActions
}

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "diff [policy-file]",
		Aliases: []string{"pb-diff", "compare", "cmp", "role-diff", "rd"},
		Short:   "Compare IAM permissions between two sources or permission boundaries",
		Long: `Compare IAM permissions using a unified diff format (like diff -u).

Mode 1 — Source diff: Compare actions between two IAM sources.
Each side (--from-* / --to-*) can be an AWS role, a CloudFormation template,
or a policy file.

Mode 2 — Boundary diff (legacy pb-diff): Compare a policy source's actions
against two permission boundaries to see what access would be gained or lost.

Source types for --from-* and --to-*:
  --from-role / --to-role       Live AWS IAM role
  --from-cf / --to-cf           CloudFormation template
  --from-policy / --to-policy   Local policy JSON file (or '-' for stdin)

Output uses unified diff format:
  Lines prefixed with '-' exist only in the 'from' side (removed).
  Lines prefixed with '+' exist only in the 'to' side (added).
  Lines prefixed with ' ' exist in both sides (unchanged).`,
		Args: cobra.MaximumNArgs(1),
		Example: `  # Compare two live AWS roles
  iamctl diff --from-role my-role-dev --to-role my-role-prod
  iamctl diff --from-role my-role-dev --to-role my-role-prod --profile staging

  # Compare a role to a policy file
  iamctl diff --from-role my-role --to-policy desired-policy.json

  # Compare a CloudFormation template to a live role
  iamctl diff --from-cf template.yaml --to-role my-role
  iamctl diff --from-cf template.yaml --from-resource LambdaRole --to-role my-role

  # Compare two policy files
  iamctl diff --from-policy old.json --to-policy new.json

  # Compare two CloudFormation templates
  iamctl diff --from-cf old-template.yaml --to-cf new-template.yaml

  # Boundary diff (legacy pb-diff mode)
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json --role my-role

  # JSON output
  iamctl diff --from-role roleA --to-role roleB --output json`,
		RunE: runDiff,
	}

	// Source diff flags
	cmd.Flags().String("from-role", "", "AWS IAM role name for the 'from' side")
	cmd.Flags().String("from-cf", "", "CloudFormation template file for the 'from' side")
	cmd.Flags().String("from-policy", "", "Policy JSON file for the 'from' side (or '-' for stdin)")
	cmd.Flags().String("from-resource", "", "Logical ID of a specific IAM resource (only with --from-cf)")

	cmd.Flags().String("to-role", "", "AWS IAM role name for the 'to' side")
	cmd.Flags().String("to-cf", "", "CloudFormation template file for the 'to' side")
	cmd.Flags().String("to-policy", "", "Policy JSON file for the 'to' side (or '-' for stdin)")
	cmd.Flags().String("to-resource", "", "Logical ID of a specific IAM resource (only with --to-cf)")

	// Boundary diff flags (legacy pb-diff mode)
	cmd.Flags().String("pb", "", "Path to the old permission boundary file (boundary diff mode)")
	cmd.Flags().String("pb-new", "", "Path to the new permission boundary (boundary diff mode)")
	cmd.Flags().String("role", "", "IAM role name (boundary diff mode; mutually exclusive with policy file argument)")

	// Common flags
	cmd.Flags().String("profile", "", "AWS profile to use")
	cmd.Flags().String("output", "unified", "Output format: unified, json, or list (list only for boundary diff mode)")

	return cmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	fromRole, _ := cmd.Flags().GetString("from-role")
	fromCf, _ := cmd.Flags().GetString("from-cf")
	fromPolicy, _ := cmd.Flags().GetString("from-policy")
	toRole, _ := cmd.Flags().GetString("to-role")
	toCf, _ := cmd.Flags().GetString("to-cf")
	toPolicy, _ := cmd.Flags().GetString("to-policy")
	pbFile, _ := cmd.Flags().GetString("pb")
	pbNewFile, _ := cmd.Flags().GetString("pb-new")
	roleName, _ := cmd.Flags().GetString("role")
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")

	hasSourceDiff := fromRole != "" || fromCf != "" || fromPolicy != "" ||
		toRole != "" || toCf != "" || toPolicy != ""
	hasBoundaryDiff := pbFile != "" || pbNewFile != ""

	// Positional arg or --role without source diff flags implies boundary diff
	if !hasSourceDiff && (roleName != "" || len(args) > 0) {
		hasBoundaryDiff = true
	}

	if hasSourceDiff && hasBoundaryDiff {
		return fmt.Errorf("cannot mix source diff flags (--from-*/--to-*) with boundary diff flags (--pb/--pb-new/--role)")
	}

	if hasSourceDiff && roleName != "" {
		return fmt.Errorf("--role is for boundary diff mode; use --from-role/--to-role for source diff mode")
	}

	if hasSourceDiff && len(args) > 0 {
		return fmt.Errorf("positional policy file argument is for boundary diff mode; use --from-policy/--to-policy for source diff mode")
	}

	if hasSourceDiff {
		return runSourceDiff(cmd, format, profile,
			fromRole, fromCf, fromPolicy,
			toRole, toCf, toPolicy)
	}

	if hasBoundaryDiff {
		return runBoundaryDiff(cmd, args, format, profile, pbFile, pbNewFile, roleName)
	}

	return fmt.Errorf("specify source diff flags (--from-*/--to-*) or boundary diff flags (--pb/--pb-new)")
}

// runSourceDiff compares actions between two IAM sources.
func runSourceDiff(cmd *cobra.Command, format, profile,
	fromRole, fromCf, fromPolicy,
	toRole, toCf, toPolicy string) error {

	fromResource, _ := cmd.Flags().GetString("from-resource")
	toResource, _ := cmd.Flags().GetString("to-resource")

	if fromResource != "" && fromCf == "" {
		return fmt.Errorf("--from-resource can only be used with --from-cf")
	}
	if toResource != "" && toCf == "" {
		return fmt.Errorf("--to-resource can only be used with --to-cf")
	}

	fromCount := countTrue(fromRole != "", fromCf != "", fromPolicy != "")
	if fromCount == 0 {
		return fmt.Errorf("specify a 'from' source: --from-role, --from-cf, or --from-policy")
	}
	if fromCount > 1 {
		return fmt.Errorf("specify only one 'from' source: --from-role, --from-cf, or --from-policy")
	}

	toCount := countTrue(toRole != "", toCf != "", toPolicy != "")
	if toCount == 0 {
		return fmt.Errorf("specify a 'to' source: --to-role, --to-cf, or --to-policy")
	}
	if toCount > 1 {
		return fmt.Errorf("specify only one 'to' source: --to-role, --to-cf, or --to-policy")
	}

	from, err := resolveDiffSource(cmd, fromRole, fromCf, fromPolicy, fromResource, profile)
	if err != nil {
		return fmt.Errorf("resolving 'from' source: %w", err)
	}

	to, err := resolveDiffSource(cmd, toRole, toCf, toPolicy, toResource, profile)
	if err != nil {
		return fmt.Errorf("resolving 'to' source: %w", err)
	}

	addedAllow, removedAllow, commonAllow := computeActionDiff(from.extracted.AllowActions, to.extracted.AllowActions)
	addedDeny, removedDeny, commonDeny := computeActionDiff(from.extracted.DenyActions, to.extracted.DenyActions)

	allWarnings := dedupeWarnings(
		policy.Warnings(from.extracted, format == "json"),
		policy.Warnings(to.extracted, format == "json"),
	)

	hasAllowDiff := len(addedAllow) > 0 || len(removedAllow) > 0
	hasDenyDiff := len(addedDeny) > 0 || len(removedDeny) > 0
	hasDiff := hasAllowDiff || hasDenyDiff

	switch format {
	case "json":
		result := map[string]interface{}{
			"from": from.label,
			"to":   to.label,
			"allow": map[string]interface{}{
				"added":   policy.NullableStringSlice(addedAllow),
				"removed": policy.NullableStringSlice(removedAllow),
				"common":  policy.NullableStringSlice(commonAllow),
			},
			"deny": map[string]interface{}{
				"added":   policy.NullableStringSlice(addedDeny),
				"removed": policy.NullableStringSlice(removedDeny),
				"common":  policy.NullableStringSlice(commonDeny),
			},
			"summary": map[string]interface{}{
				"allow": map[string]int{
					"added":   len(addedAllow),
					"removed": len(removedAllow),
					"common":  len(commonAllow),
				},
				"deny": map[string]int{
					"added":   len(addedDeny),
					"removed": len(removedDeny),
					"common":  len(commonDeny),
				},
			},
			"warnings": allWarnings,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	default: // unified
		printWarnings(allWarnings, os.Stderr)

		if !hasDiff {
			fmt.Println("No differences found.")
			return nil
		}

		fmt.Printf("--- %s\n", from.label)
		fmt.Printf("+++ %s\n", to.label)

		if hasAllowDiff {
			printUnifiedSection("Allow Actions",
				len(addedAllow), len(removedAllow), len(commonAllow),
				addedAllow, removedAllow, commonAllow)
		} else if len(commonAllow) > 0 {
			fmt.Printf("\n  Allow Actions: %d action(s), no changes\n", len(commonAllow))
		}

		if hasDenyDiff {
			printUnifiedSection("Deny Actions",
				len(addedDeny), len(removedDeny), len(commonDeny),
				addedDeny, removedDeny, commonDeny)
		} else if len(commonDeny) > 0 {
			fmt.Printf("\n  Deny Actions: %d action(s), no changes\n", len(commonDeny))
		}

		totalAdded := len(addedAllow) + len(addedDeny)
		totalRemoved := len(removedAllow) + len(removedDeny)
		totalCommon := len(commonAllow) + len(commonDeny)
		fmt.Fprintf(os.Stderr, "\nSummary: %d added, %d removed, %d unchanged\n", totalAdded, totalRemoved, totalCommon)
	}

	if hasDiff {
		os.Exit(1)
	}
	return nil
}

// runBoundaryDiff is the legacy pb-diff mode: compare a policy source's actions
// against two permission boundaries.
func runBoundaryDiff(cmd *cobra.Command, args []string, format, profile, pbFile, pbNewFile, roleName string) error {
	if pbFile == "" {
		return fmt.Errorf("--pb is required for boundary diff mode")
	}
	if pbNewFile == "" {
		return fmt.Errorf("--pb-new is required for boundary diff mode")
	}

	if roleName == "" && len(args) == 0 {
		return fmt.Errorf("either a policy file argument or --role must be specified")
	}
	if roleName != "" && len(args) > 0 {
		return fmt.Errorf("--role and a policy file argument are mutually exclusive")
	}

	pbOld, err := boundary.LoadFromFile(pbFile)
	if err != nil {
		return fmt.Errorf("loading old permission boundary: %w", err)
	}
	pbNew, err := boundary.LoadFromFile(pbNewFile)
	if err != nil {
		return fmt.Errorf("loading new permission boundary: %w", err)
	}

	var extracted policy.ExtractedActions
	var sourceLabel string

	if roleName != "" {
		iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
		if err != nil {
			return err
		}
		policies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
		if err != nil {
			return fmt.Errorf("fetching role policies: %w", err)
		}
		if len(policies) == 0 {
			fmt.Fprintln(os.Stderr, "No managed policies attached to role")
			return nil
		}
		extracted = extractActionsFromPolicies(policies)
		sourceLabel = "role: " + roleName
	} else {
		data, err := policy.ReadFromPathOrStdin(args[0])
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parsing policy JSON: %w", err)
		}
		extracted = policy.ExtractActions(doc)
		sourceLabel = "policy: " + args[0]
	}

	// Classify every Allow action by old vs new boundary
	var oldAllowed, newAllowed []string
	for _, action := range extracted.AllowActions {
		if boundary.IsActionAllowed(action, pbOld) {
			oldAllowed = append(oldAllowed, action)
		}
		if boundary.IsActionAllowed(action, pbNew) {
			newAllowed = append(newAllowed, action)
		}
	}

	gained, lost, unchanged := computeActionDiff(oldAllowed, newAllowed)

	switch format {
	case "json":
		warnings := policy.Warnings(extracted, true)
		result := map[string]interface{}{
			"source":    sourceLabel,
			"gained":    policy.NullableStringSlice(gained),
			"lost":      policy.NullableStringSlice(lost),
			"unchanged": policy.NullableStringSlice(unchanged),
			"warnings":  warnings,
			"summary": map[string]int{
				"gained":    len(gained),
				"lost":      len(lost),
				"unchanged": len(unchanged),
			},
		}
		if roleName != "" {
			result["role"] = roleName
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "list":
		warnings := policy.Warnings(extracted, false)
		if roleName != "" {
			fmt.Fprintf(os.Stderr, "Role: %s\n\n", roleName)
		}
		printWarnings(warnings, os.Stderr)
		if len(gained) > 0 {
			fmt.Println("🟢  Newly allowed by new boundary (gained access):")
			for _, a := range gained {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(lost) > 0 {
			fmt.Println("\n🔴  No longer allowed by new boundary (lost access):")
			for _, a := range lost {
				fmt.Printf("    %s\n", a)
			}
		}
		if len(unchanged) > 0 {
			fmt.Printf("\n--  Unchanged: %d action(s)\n", len(unchanged))
		}
		fmt.Printf("\nSummary: %d gained, %d lost, %d unchanged\n", len(gained), len(lost), len(unchanged))

	default: // unified
		warnings := policy.Warnings(extracted, false)
		printWarnings(warnings, os.Stderr)

		if len(gained) == 0 && len(lost) == 0 {
			fmt.Println("No differences found.")
			return nil
		}

		fmt.Printf("--- allowed by: %s\n", pbFile)
		fmt.Printf("+++ allowed by: %s\n", pbNewFile)
		printUnifiedSection("Actions ("+sourceLabel+")",
			len(gained), len(lost), len(unchanged),
			gained, lost, unchanged)
		fmt.Fprintf(os.Stderr, "\nSummary: %d gained, %d lost, %d unchanged\n", len(gained), len(lost), len(unchanged))
	}

	if len(lost) > 0 {
		os.Exit(1)
	}
	return nil
}

// resolveDiffSource resolves a single diff side to its extracted actions.
func resolveDiffSource(cmd *cobra.Command, roleName, cfTemplate, policyFile, resource, profile string) (*diffSide, error) {
	ctx := cmd.Context()

	if roleName != "" {
		iamClient, err := awsiam.NewIAMClient(ctx, profile)
		if err != nil {
			return nil, err
		}

		managedPolicies, err := awsiam.FetchRolePolicies(ctx, iamClient, roleName)
		if err != nil {
			return nil, fmt.Errorf("fetching managed policies: %w", err)
		}

		inlinePolicies, err := awsiam.FetchRoleInlinePolicies(ctx, iamClient, roleName)
		if err != nil {
			return nil, fmt.Errorf("fetching inline policies: %w", err)
		}

		allPolicies := make(map[string]policy.PolicyDocument)
		for name, doc := range managedPolicies {
			allPolicies[name] = doc
		}
		for name, doc := range inlinePolicies {
			allPolicies[name+" (inline)"] = doc
		}

		return &diffSide{
			label:     "role: " + roleName,
			extracted: extractActionsFromPolicies(allPolicies),
		}, nil
	}

	if cfTemplate != "" {
		tmpl, err := cfn.ParseTemplate(cfTemplate)
		if err != nil {
			return nil, err
		}

		roles, err := cfn.ExtractIAMRoles(tmpl)
		if err != nil {
			return nil, err
		}

		policies, err := cfn.ExtractIAMPolicies(tmpl)
		if err != nil {
			return nil, err
		}

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
				return nil, fmt.Errorf("resource %q not found; available IAM resources: %s", resource, strings.Join(available, ", "))
			}
			roles = filteredRoles
			policies = filteredPolicies
		}

		allPolicies := make(map[string]policy.PolicyDocument)

		for _, role := range roles {
			rolePolicies, err := collectRolePolicies(cmd, role, profile, true)
			if err != nil {
				return nil, fmt.Errorf("collecting policies for role %q: %w", role.LogicalID, err)
			}
			for name, doc := range rolePolicies {
				allPolicies[role.LogicalID+"/"+name] = doc
			}
		}

		for _, pol := range policies {
			allPolicies[pol.LogicalID] = pol.PolicyDocument
		}

		label := "cf: " + cfTemplate
		if resource != "" {
			label += " (" + resource + ")"
		}

		return &diffSide{
			label:     label,
			extracted: extractActionsFromPolicies(allPolicies),
		}, nil
	}

	if policyFile != "" {
		data, err := policy.ReadFromPathOrStdin(policyFile)
		if err != nil {
			return nil, fmt.Errorf("reading policy file: %w", err)
		}
		var doc policy.PolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing policy JSON: %w", err)
		}

		return &diffSide{
			label:     "policy: " + policyFile,
			extracted: policy.ExtractActions(doc),
		}, nil
	}

	return nil, fmt.Errorf("no source specified")
}

// extractActionsFromPolicies merges actions from multiple policy documents into
// a single ExtractedActions.
func extractActionsFromPolicies(policies map[string]policy.PolicyDocument) policy.ExtractedActions {
	mergedAllow := make(map[string]bool)
	mergedDeny := make(map[string]bool)
	var allNotActionStmts []policy.NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	for _, policyDoc := range policies {
		ext := policy.ExtractActions(policyDoc)
		hasWildcards = hasWildcards || ext.HasWildcards
		hasConditions = hasConditions || ext.HasConditions
		hasNotResources = hasNotResources || ext.HasNotResources
		allNotActionStmts = append(allNotActionStmts, ext.NotActionStmts...)
		for _, a := range ext.AllowActions {
			mergedAllow[a] = true
		}
		for _, a := range ext.DenyActions {
			mergedDeny[a] = true
		}
	}

	var allowList, denyList []string
	for a := range mergedAllow {
		allowList = append(allowList, a)
	}
	for a := range mergedDeny {
		denyList = append(denyList, a)
	}
	sort.Strings(allowList)
	sort.Strings(denyList)

	return policy.ExtractedActions{
		AllowActions:    allowList,
		DenyActions:     denyList,
		NotActionStmts:  allNotActionStmts,
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
	}
}

// computeActionDiff computes the added, removed, and common actions between two sorted lists.
func computeActionDiff(fromActions, toActions []string) (added, removed, common []string) {
	fromSet := make(map[string]bool, len(fromActions))
	toSet := make(map[string]bool, len(toActions))

	for _, a := range fromActions {
		fromSet[a] = true
	}
	for _, a := range toActions {
		toSet[a] = true
	}

	for _, a := range fromActions {
		if toSet[a] {
			common = append(common, a)
		} else {
			removed = append(removed, a)
		}
	}
	for _, a := range toActions {
		if !fromSet[a] {
			added = append(added, a)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(common)
	return
}

const diffContextLines = 3

// printUnifiedSection prints a section of a unified diff with context lines
// around changes, similar to diff -u. Unchanged lines far from changes are
// collapsed into a "..." marker.
func printUnifiedSection(header string, nAdded, nRemoved, nCommon int, added, removed, common []string) {
	fmt.Printf("\n📋 %s | 🟢 %d added, 🔴 %d removed, %d unchanged\n", header, nAdded, nRemoved, nCommon)

	type diffLine struct {
		action  string
		prefix  string
		changed bool
	}

	var lines []diffLine
	for _, a := range common {
		lines = append(lines, diffLine{action: a, prefix: "   ", changed: false})
	}
	for _, a := range removed {
		lines = append(lines, diffLine{action: a, prefix: "🔴 ", changed: true})
	}
	for _, a := range added {
		lines = append(lines, diffLine{action: a, prefix: "🟢 ", changed: true})
	}

	sort.Slice(lines, func(i, j int) bool {
		if lines[i].action == lines[j].action {
			return lines[i].prefix < lines[j].prefix
		}
		return lines[i].action < lines[j].action
	})

	// Compute which lines are visible: changed lines + context around them
	visible := make([]bool, len(lines))
	for i, l := range lines {
		if l.changed {
			for j := max(0, i-diffContextLines); j <= min(len(lines)-1, i+diffContextLines); j++ {
				visible[j] = true
			}
		}
	}

	skipped := false
	for i, l := range lines {
		if !visible[i] {
			if !skipped {
				fmt.Println("   ...")
				skipped = true
			}
			continue
		}
		skipped = false
		fmt.Printf("%s%s\n", l.prefix, l.action)
	}
}

// dedupeWarnings merges two warning slices, removing duplicates.
func dedupeWarnings(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	var result []string
	for _, w := range a {
		if !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}
	for _, w := range b {
		if !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}
	return result
}

// countTrue returns the number of true values.
func countTrue(vals ...bool) int {
	n := 0
	for _, v := range vals {
		if v {
			n++
		}
	}
	return n
}
