package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/spf13/cobra"
)

func newDescribeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "describe <role-name | policy-arn>",
		Aliases: []string{"desc", "describe-role", "dr", "describe-policy", "dp"},
		Short:   "Describe an IAM role or managed policy",
		Long: `Describe an IAM role or managed policy.

The argument type is auto-detected:
  - If it starts with "arn:", it is treated as a managed policy ARN
  - Otherwise, it is treated as a role name

When invoked as describe-role/dr, the argument is always a role name.
When invoked as describe-policy/dp, the argument is always a policy ARN.`,
		Args: cobra.ExactArgs(1),
		Example: `  # Describe a role
  iamctl describe my-role
  iamctl describe --output json my-role

  # Describe a managed policy
  iamctl describe arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl describe --json-policy arn:aws:iam::123456789012:policy/MyPolicy

  # Legacy aliases
  iamctl describe-role my-role
  iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			calledAs := cmd.CalledAs()

			isPolicy := false
			switch calledAs {
			case "describe-policy", "dp":
				isPolicy = true
			case "describe-role", "dr":
				isPolicy = false
			default:
				isPolicy = strings.HasPrefix(target, "arn:")
			}

			if isPolicy {
				return runDescribePolicy(cmd, target)
			}
			return runDescribeRole(cmd, target)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use (defaults to current AWS_PROFILE / default)")
	cmd.Flags().String("output", "wide", "Output format: wide or json")
	cmd.Flags().Bool("json-policy", false, "Print only the policy JSON document (only with policy ARN)")

	return cmd
}

func runDescribeRole(cmd *cobra.Command, roleName string) error {
	profile, _ := cmd.Flags().GetString("profile")
	output, _ := cmd.Flags().GetString("output")

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	desc, err := awsiam.DescribeRole(cmd.Context(), iamClient, roleName)
	if err != nil {
		return err
	}

	switch output {
	case "json":
		out, _ := json.MarshalIndent(desc, "", "  ")
		fmt.Println(string(out))
		return nil
	case "wide":
		// Continue with human-readable describe-style output below.
	default:
		return fmt.Errorf("invalid --output %q (expected wide or json)", output)
	}

	printDescribeField("Name", desc.RoleName)
	printDescribeField("ARN", desc.ARN)
	printDescribeField("Creation Timestamp", formatDateTimeForConsole(desc.CreateDate))
	printDescribeField("Last Activity", formatLastActivity(desc.LastUsedAt))
	printDescribeField("Max Session Duration", formatSessionDuration(desc.MaxSessionDuration))
	if desc.SwitchRoleURL != "" {
		printDescribeField("Switch Role URL", desc.SwitchRoleURL)
	} else {
		printDescribeField("Switch Role URL", "(not available)")
	}

	fmt.Println("Managed Policies:")
	if len(desc.AttachedPolicies) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, p := range desc.AttachedPolicies {
			fmt.Printf("  - %s\n", p.ARN)
		}
	}

	fmt.Println("Inline Policies:")
	if len(desc.InlinePolicies) == 0 {
		fmt.Println("  (none)")
		return nil
	}

	names := make([]string, 0, len(desc.InlinePolicies))
	for name := range desc.InlinePolicies {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("  %s:\n", name)
		out, _ := json.MarshalIndent(desc.InlinePolicies[name], "", "  ")
		fmt.Println(indentBlock(string(out), "    "))
	}

	return nil
}

func runDescribePolicy(cmd *cobra.Command, policyARN string) error {
	profile, _ := cmd.Flags().GetString("profile")
	jsonPolicyOnly, _ := cmd.Flags().GetBool("json-policy")

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	desc, err := awsiam.DescribeManagedPolicy(cmd.Context(), iamClient, policyARN)
	if err != nil {
		return err
	}

	if jsonPolicyOnly {
		out, _ := json.MarshalIndent(desc.Document, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	printDescribeField("Name", desc.Name)
	printDescribeField("ARN", desc.ARN)
	if desc.IsAWSManaged {
		printDescribeField("Type", "AWS managed")
	} else {
		printDescribeField("Type", "Customer managed")
	}
	if desc.Description == "" {
		printDescribeField("Description", "(none)")
	} else {
		printDescribeField("Description", desc.Description)
	}
	if desc.Path == "" {
		printDescribeField("Path", "/")
	} else {
		printDescribeField("Path", desc.Path)
	}
	if desc.CreateDate != nil {
		printDescribeField("Creation Timestamp", formatDateTimeForConsole(*desc.CreateDate))
	} else {
		printDescribeField("Creation Timestamp", "(unknown)")
	}
	if desc.UpdateDate != nil {
		printDescribeField("Updated Timestamp", formatDateTimeForConsole(*desc.UpdateDate))
	} else {
		printDescribeField("Updated Timestamp", "(unknown)")
	}
	printDescribeField("Default Version", desc.DefaultVersionID)

	fmt.Println("Policy Document:")
	out, _ := json.MarshalIndent(desc.Document, "", "  ")
	fmt.Println(indentBlock(string(out), "  "))

	return nil
}
