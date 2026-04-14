package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "list <query>",
		Aliases: []string{
			"ls",
			// Legacy role-list aliases
			"role-list", "rl", "lr", "search-roles", "sr",
			// Legacy policy-list aliases
			"policy-list", "pl", "lp", "search-policies", "sp",
		},
		Short: "List IAM roles or policies whose names contain a string",
		Long: `Search IAM roles or managed policies by name substring.

By default, lists roles. Use --policies to list managed policies instead.

When invoked as role-list/rl/lr/sr/search-roles, lists roles.
When invoked as policy-list/pl/lp/sp/search-policies, lists policies.`,
		Args: cobra.ExactArgs(1),
		Example: `  # List roles (default)
  iamctl list app
  iamctl list -1 app
  iamctl list --active-within-days 90 app

  # List policies
  iamctl list --policies read
  iamctl list --policies --scope local app
  iamctl list --policies --description-contains readonly read

  # Legacy aliases still work
  iamctl role-list app
  iamctl policy-list --scope local app`,
		RunE: func(cmd *cobra.Command, args []string) error {
			calledAs := cmd.CalledAs()
			wantPolicies, _ := cmd.Flags().GetBool("policies")

			switch calledAs {
			case "policy-list", "pl", "lp", "search-policies", "sp":
				wantPolicies = true
			case "role-list", "rl", "lr", "search-roles", "sr":
				wantPolicies = false
			}

			if wantPolicies {
				return runListPolicies(cmd, args)
			}
			return runListRoles(cmd, args)
		},
	}

	// Common flags
	cmd.Flags().String("output", "list", "Output format: list or json")
	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")

	// Mode flag
	cmd.Flags().Bool("policies", false, "List managed policies instead of roles")

	// Role-specific flags
	cmd.Flags().Int("active-within-days", 0, "Filter to roles active within the last N days (0 disables)")
	cmd.Flags().BoolP("one-per-line", "1", false, "Print only matching names, one per line")

	// Policy-specific flags
	cmd.Flags().String("scope", "all", "Policy scope: all, aws, or local (only with --policies)")
	cmd.Flags().String("description-contains", "", "Filter policies whose description contains this string")
	cmd.Flags().String("description-not-contains", "", "Filter policies whose description does not contain this string")

	return cmd
}

func runListRoles(cmd *cobra.Command, args []string) error {
	query := strings.TrimSpace(args[0])
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")
	activeWithinDays, _ := cmd.Flags().GetInt("active-within-days")
	onePerLine, _ := cmd.Flags().GetBool("one-per-line")

	if activeWithinDays < 0 {
		return fmt.Errorf("--active-within-days must be >= 0")
	}

	filters := awsiam.RoleSearchFilters{}
	if activeWithinDays > 0 {
		cutoff := time.Now().Add(-time.Duration(activeWithinDays) * 24 * time.Hour)
		filters.LastActiveAfter = &cutoff
	}

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	roles, err := awsiam.SearchRolesBySubstring(cmd.Context(), iamClient, query, filters)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		if onePerLine {
			return fmt.Errorf("-1/--one-per-line cannot be used with --output json")
		}
		result := map[string]interface{}{
			"query":              query,
			"active_within_days": activeWithinDays,
			"matches":            roles,
			"summary":            map[string]int{"matches": len(roles)},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		if onePerLine {
			for _, role := range roles {
				fmt.Println(role.Name)
			}
			return nil
		}
		if len(roles) == 0 {
			fmt.Printf("No IAM roles found matching the requested filters\n")
			return nil
		}
		for _, role := range roles {
			lastUsed := "(never/unknown)"
			if role.LastUsedAt != nil {
				lastUsed = role.LastUsedAt.UTC().Format(time.RFC3339)
			}
			fmt.Printf("- %s (%s) last-used: %s\n", role.Name, role.ARN, lastUsed)
		}
	}

	return nil
}

func runListPolicies(cmd *cobra.Command, args []string) error {
	query := strings.TrimSpace(args[0])
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")
	scopeRaw, _ := cmd.Flags().GetString("scope")
	descriptionContains, _ := cmd.Flags().GetString("description-contains")
	descriptionNotContains, _ := cmd.Flags().GetString("description-not-contains")

	scope, err := parsePolicyScope(scopeRaw)
	if err != nil {
		return err
	}

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	filters := awsiam.PolicySearchFilters{
		DescriptionContains:    descriptionContains,
		DescriptionNotContains: descriptionNotContains,
	}

	policies, err := awsiam.SearchManagedPoliciesBySubstring(cmd.Context(), iamClient, query, scope, filters)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		result := map[string]interface{}{
			"query":                    query,
			"scope":                    strings.ToLower(scopeRaw),
			"description_contains":     descriptionContains,
			"description_not_contains": descriptionNotContains,
			"matches":                  policies,
			"summary":                  map[string]int{"matches": len(policies)},
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		if len(policies) == 0 {
			fmt.Printf("No IAM managed policies found matching the requested filters\n")
			return nil
		}
		fmt.Printf("Found %d IAM managed policies containing %q:\n", len(policies), query)
		for _, p := range policies {
			desc := p.Description
			if desc == "" {
				desc = "(no description)"
			}
			fmt.Printf("- %s (%s)\n  description: %s\n", p.Name, p.ARN, desc)
		}
	}

	return nil
}

func parsePolicyScope(value string) (types.PolicyScopeType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "all":
		return types.PolicyScopeTypeAll, nil
	case "aws":
		return types.PolicyScopeTypeAws, nil
	case "local":
		return types.PolicyScopeTypeLocal, nil
	default:
		return "", fmt.Errorf("invalid --scope %q (expected all, aws, or local)", value)
	}
}
