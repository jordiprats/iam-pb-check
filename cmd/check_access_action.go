package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/matcher"
	"github.com/spf13/cobra"
)

// runCheckAction evaluates specific actions against a permission boundary.
func runCheckAction(cmd *cobra.Command, actions []string) error {
	pbFile, _ := cmd.Flags().GetString("pb")
	if pbFile == "" {
		return fmt.Errorf("--pb is required when checking actions")
	}

	pb, err := boundary.LoadFromFile(pbFile)
	if err != nil {
		return fmt.Errorf("loading permission boundary: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)

	anyDenied := false
	for _, action := range actions {
		if matcher.IsWildcardAction(action) {
			fmt.Fprintf(os.Stderr, "🟡  '%s' contains a wildcard — result reflects pattern matching only, not full action enumeration.\n", action)
		}
		if boundary.IsActionAllowed(action, pb) {
			matchingPatterns := boundary.FindAllowingPatterns(action, pb)
			if len(matchingPatterns) > 0 {
				fmt.Printf("🟢  %-58s matches: %s\n", action, strings.Join(matchingPatterns, ", "))
			} else {
				fmt.Printf("🟢  %-58s ALLOWED\n", action)
			}
		} else {
			anyDenied = true
			fmt.Printf("🔴  %-58s DENIED\n", action)
		}
	}

	if anyDenied {
		os.Exit(1)
	}
	return nil
}
