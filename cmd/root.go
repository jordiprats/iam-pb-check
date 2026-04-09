package cmd

import "github.com/spf13/cobra"

// NewRootCmd creates the root cobra command.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "iamctl",
		Short: "Inspect IAM and analyze permission boundaries",
		Long:  "Inspect AWS IAM roles and policies, validate access against permission boundaries, generate least-privilege policies, and more.",
	}

	root.Version = version
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(newCheckAccessCmd())
	root.AddCommand(newDescribeRoleCmd())
	root.AddCommand(newDescribePolicyCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newRoleListCmd())
	root.AddCommand(newPolicyListCmd())
	root.AddCommand(newPolicyFromRoleUsageCmd())
	root.AddCommand(newShrinkRolePoliciesCmd())
	root.AddCommand(newMergePoliciesCmd())
	root.AddCommand(GenDocsCmd(root))

	return root
}
