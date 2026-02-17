package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// Policy document structures
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid       string      `json:"Sid,omitempty"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action,omitempty"`
	NotAction interface{} `json:"NotAction,omitempty"`
	Resource  interface{} `json:"Resource,omitempty"`
}

// AWS IAM GetPolicyVersion response structure
type PolicyVersionWrapper struct {
	PolicyVersion PolicyVersion `json:"PolicyVersion"`
}

type PolicyVersion struct {
	Document         PolicyDocument `json:"Document"`
	VersionId        string         `json:"VersionId,omitempty"`
	IsDefaultVersion bool           `json:"IsDefaultVersion,omitempty"`
	CreateDate       string         `json:"CreateDate,omitempty"`
}

// PermissionBoundary holds the loaded permission boundary in whatever format was available
type PermissionBoundary struct {
	Policy           *PolicyDocument
	Patterns         []string
	EvaluationMethod string
}

// ExtractedActions holds actions separated by their effect in the source policy
type ExtractedActions struct {
	AllowActions []string
	DenyActions  []string
}

// loadPermissionBoundaryUnified tries to load the permission boundary in all supported formats
func loadPermissionBoundaryUnified(filename string) (*PermissionBoundary, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PolicyVersionWrapper (aws iam get-policy-version format)
	var wrapper PolicyVersionWrapper
	if err := json.Unmarshal(data, &wrapper); err == nil {
		return &PermissionBoundary{
			Policy:           &wrapper.PolicyVersion.Document,
			EvaluationMethod: "Full IAM policy evaluation",
		}, nil
	}

	// Try to parse as direct PolicyDocument
	var policy PolicyDocument
	if err := json.Unmarshal(data, &policy); err == nil {
		if len(policy.Statement) > 0 {
			return &PermissionBoundary{
				Policy:           &policy,
				EvaluationMethod: "Full IAM policy evaluation",
			}, nil
		}
	}

	// Try to parse as simple JSON array
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err == nil && len(patterns) > 0 {
		return &PermissionBoundary{
			Patterns:         patterns,
			EvaluationMethod: "Simple pattern matching",
		}, nil
	}

	// If JSON parsing fails, try line-by-line text format
	patterns = []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	if len(patterns) > 0 {
		return &PermissionBoundary{
			Patterns:         patterns,
			EvaluationMethod: "Simple pattern matching",
		}, nil
	}

	return nil, fmt.Errorf("no valid permission boundary found in file")
}

// isActionAllowed checks if an action is allowed using the appropriate evaluation method
func isActionAllowed(action string, pb *PermissionBoundary) bool {
	if pb.Policy != nil {
		return evaluatePermissionBoundary(action, *pb.Policy)
	}
	matched, _ := matchesAnyPattern(action, pb.Patterns)
	return matched
}

// evaluatePermissionBoundary checks if an action is allowed by the permission boundary
// IAM evaluation logic:
// 1. By default, everything is denied
// 2. Check Allow statements - if any Allow matches, it's potentially allowed
// 3. Check Deny statements - if any Deny matches, it's explicitly denied (overrides Allow)
// 4. Special case: NotAction in Deny means "deny everything EXCEPT these actions"
func evaluatePermissionBoundary(action string, policy PolicyDocument) bool {
	allowed := false
	denied := false

	for _, stmt := range policy.Statement {
		if stmt.Effect == "Allow" {
			if stmt.Action != nil {
				patterns := extractStrings(stmt.Action)
				if matches, _ := matchesAnyPattern(action, patterns); matches {
					allowed = true
				}
			}
		} else if stmt.Effect == "Deny" {
			if stmt.NotAction != nil {
				patterns := extractStrings(stmt.NotAction)
				if matches, _ := matchesAnyPattern(action, patterns); !matches {
					denied = true
				}
			} else if stmt.Action != nil {
				patterns := extractStrings(stmt.Action)
				if matches, _ := matchesAnyPattern(action, patterns); matches {
					denied = true
				}
			}
		}
	}

	if denied {
		return false
	}
	return allowed
}

func extractStrings(value interface{}) []string {
	var result []string
	switch v := value.(type) {
	case string:
		result = append(result, v)
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

func iamWildcardMatch(pattern, str string) bool {
	pattern = strings.ToLower(pattern)
	str = strings.ToLower(str)

	p, s := 0, 0
	pStar, sStar := -1, -1

	for s < len(str) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == str[s]) {
			p++
			s++
		} else if p < len(pattern) && pattern[p] == '*' {
			pStar = p
			sStar = s
			p++
		} else if pStar >= 0 {
			p = pStar + 1
			sStar++
			s = sStar
		} else {
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

func matchesAnyPattern(action string, patterns []string) (bool, []string) {
	var matches []string
	for _, pattern := range patterns {
		if iamWildcardMatch(pattern, action) {
			matches = append(matches, pattern)
		}
	}
	return len(matches) > 0, matches
}

// extractActions separates actions by their Effect (Allow vs Deny) in the source policy
func extractActions(policy PolicyDocument) ExtractedActions {
	allowMap := make(map[string]bool)
	denyMap := make(map[string]bool)

	for _, stmt := range policy.Statement {
		if stmt.Action == nil {
			continue
		}

		target := allowMap
		if stmt.Effect == "Deny" {
			target = denyMap
		}

		switch actions := stmt.Action.(type) {
		case string:
			target[actions] = true
		case []interface{}:
			for _, action := range actions {
				if s, ok := action.(string); ok {
					target[s] = true
				}
			}
		}
	}

	var allowList, denyList []string
	for a := range allowMap {
		allowList = append(allowList, a)
	}
	for a := range denyMap {
		denyList = append(denyList, a)
	}
	sort.Strings(allowList)
	sort.Strings(denyList)

	return ExtractedActions{AllowActions: allowList, DenyActions: denyList}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pb-checker",
		Short: "AWS IAM Permission Boundary Checker",
		Long:  "Validate AWS IAM actions and policies against a permission boundary definition.",
	}

	// Persistent flag shared by all subcommands
	root.PersistentFlags().String("pb", "pb.json", "Path to the permission boundary file (JSON or text format)")

	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(newCheckActionCmd())
	root.AddCommand(newCheckPolicyCmd())

	return root
}

func newCheckActionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-action <action>",
		Short: "Check if a single action is allowed by the permission boundary",
		Args:  cobra.ExactArgs(1),
		Example: `  pb-checker check-action ec2:RunInstances
  pb-checker check-action --pb boundary.json s3:PutObject`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			action := args[0]

			pb, err := loadPermissionBoundaryUnified(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)

			if isActionAllowed(action, pb) {
				if pb.Policy != nil {
					fmt.Printf("✅ '%s' is ALLOWED by the permission boundary\n", action)
				} else {
					_, matchingPatterns := matchesAnyPattern(action, pb.Patterns)
					fmt.Printf("✅ '%s' matches the following pattern(s):\n", action)
					for _, p := range matchingPatterns {
						fmt.Printf("  - %s\n", p)
					}
				}
				return nil
			}

			if pb.Policy != nil {
				fmt.Printf("❌ '%s' is DENIED by the permission boundary\n", action)
			} else {
				fmt.Printf("❌ '%s' does not match any pattern\n", action)
			}
			os.Exit(1)
			return nil
		},
	}
}

func newCheckPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check-policy <policy-file>",
		Short: "Check which actions in a policy are allowed or blocked by the permission boundary",
		Args:  cobra.ExactArgs(1),
		Example: `  pb-checker check-policy policy.json
  pb-checker check-policy --output json policy.json
  pb-checker check-policy --pb boundary.json --output table policy.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			format, _ := cmd.Flags().GetString("output")
			policyFile := args[0]

			// Read and parse policy file
			data, err := os.ReadFile(policyFile)
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var policy PolicyDocument
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			extracted := extractActions(policy)
			if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 {
				fmt.Println("No actions found in policy")
				return nil
			}

			// Load permission boundary
			pb, err := loadPermissionBoundaryUnified(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			// Evaluate only Allow actions against the permission boundary
			var allowedActions, blockedActions []string
			for _, action := range extracted.AllowActions {
				if isActionAllowed(action, pb) {
					allowedActions = append(allowedActions, action)
				} else {
					blockedActions = append(blockedActions, action)
				}
			}
			sort.Strings(allowedActions)
			sort.Strings(blockedActions)

			// Output results
			switch format {
			case "json":
				result := map[string]interface{}{
					"evaluation_method": pb.EvaluationMethod,
					"allowed":           allowedActions,
					"blocked":           blockedActions,
					"skipped_deny":      extracted.DenyActions,
					"summary": map[string]int{
						"allowed":      len(allowedActions),
						"blocked":      len(blockedActions),
						"skipped_deny": len(extracted.DenyActions),
					},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			case "table":
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				fmt.Printf("%-60s %s\n", "ACTION", "STATUS")
				fmt.Printf("%s\n", strings.Repeat("-", 75))
				for _, a := range allowedActions {
					fmt.Printf("%-60s %s\n", a, "✅ ALLOWED")
				}
				for _, a := range blockedActions {
					fmt.Printf("%-60s %s\n", a, "❌ BLOCKED")
				}
				for _, a := range extracted.DenyActions {
					fmt.Printf("%-60s %s\n", a, "⏭️  SKIPPED (denied by policy)")
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (already denied by policy)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions))

			default: // list
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				if len(allowedActions) > 0 {
					fmt.Println("✅ Allowed actions:")
					for _, a := range allowedActions {
						fmt.Printf("  %s\n", a)
					}
				}
				if len(blockedActions) > 0 {
					fmt.Println("\n❌ Blocked actions (not allowed by permission boundary):")
					for _, a := range blockedActions {
						fmt.Printf("  %s\n", a)
					}
				}
				if len(extracted.DenyActions) > 0 {
					fmt.Println("\n⏭️  Skipped actions (already denied by policy):")
					for _, a := range extracted.DenyActions {
						fmt.Printf("  %s\n", a)
					}
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (already denied by policy)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions))
			}

			if len(blockedActions) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("output", "list", "Output format: list, json, or table")

	return cmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
