package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var version = "dev"

// Policy document structures
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid          string      `json:"Sid,omitempty"`
	Effect       string      `json:"Effect"`
	Action       interface{} `json:"Action,omitempty"`
	NotAction    interface{} `json:"NotAction,omitempty"`
	Resource     interface{} `json:"Resource,omitempty"`
	NotResource  interface{} `json:"NotResource,omitempty"`
	Principal    interface{} `json:"Principal,omitempty"`
	NotPrincipal interface{} `json:"NotPrincipal,omitempty"`
	Condition    interface{} `json:"Condition,omitempty"`
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

// ActionResult describes how an action was evaluated
type ActionResult struct {
	Action   string
	Allowed  bool
	Source   string // "Allow", "Deny", "NotAction-Deny", "NoMatch", "pattern"
	Warnings []string
}

// ExtractedActions holds actions separated by their effect in the source policy
type ExtractedActions struct {
	AllowActions    []string
	DenyActions     []string
	NotActionStmts  []NotActionStatement // NotAction statements that need special handling
	HasWildcards    bool
	HasConditions   bool
	HasNotResources bool
}

// NotActionStatement captures a statement using NotAction (grants everything EXCEPT listed actions)
type NotActionStatement struct {
	Effect     string
	NotActions []string
	Resource   interface{}
	Condition  interface{}
}

// loadPermissionBoundaryUnified tries to load the permission boundary in all supported formats
func loadPermissionBoundaryUnified(filename string) (*PermissionBoundary, error) {
	var data []byte
	var err error

	if filename == "-" {
		data, err = readStdin()
	} else {
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PolicyVersionWrapper (aws iam get-policy-version format)
	var wrapper PolicyVersionWrapper
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.PolicyVersion.Document.Statement) > 0 {
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

func readStdin() ([]byte, error) {
	var sb strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func readPolicyFromPathOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return readStdin()
	}
	return os.ReadFile(path)
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
			} else if stmt.NotAction != nil {
				// NotAction + Allow: allows everything EXCEPT listed actions
				patterns := extractStrings(stmt.NotAction)
				if matches, _ := matchesAnyPattern(action, patterns); !matches {
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

func iamPatternToRegex(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

func matchesAnyPattern(action string, patterns []string) (bool, []string) {
	var matches []string
	for _, pattern := range patterns {
		re, err := iamPatternToRegex(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(action) {
			matches = append(matches, pattern)
		}
	}
	return len(matches) > 0, matches
}

// isWildcardAction returns true if the action string contains * or ?
func isWildcardAction(action string) bool {
	return strings.ContainsAny(action, "*?")
}

// extractActions separates actions by their Effect (Allow vs Deny) in the source policy,
// and captures NotAction statements and metadata about wildcards/conditions.
func extractActions(policy PolicyDocument) ExtractedActions {
	allowMap := make(map[string]bool)
	denyMap := make(map[string]bool)
	var notActionStmts []NotActionStatement
	hasWildcards := false
	hasConditions := false
	hasNotResources := false

	for _, stmt := range policy.Statement {
		if stmt.Condition != nil {
			hasConditions = true
		}
		if stmt.NotResource != nil {
			hasNotResources = true
		}

		// Handle NotAction statements separately
		if stmt.NotAction != nil {
			notActionStmts = append(notActionStmts, NotActionStatement{
				Effect:     stmt.Effect,
				NotActions: extractStrings(stmt.NotAction),
				Resource:   stmt.Resource,
				Condition:  stmt.Condition,
			})
			continue
		}

		if stmt.Action == nil {
			continue
		}

		target := allowMap
		if stmt.Effect == "Deny" {
			target = denyMap
		}

		switch actions := stmt.Action.(type) {
		case string:
			if isWildcardAction(actions) {
				hasWildcards = true
			}
			target[actions] = true
		case []interface{}:
			for _, action := range actions {
				if s, ok := action.(string); ok {
					if isWildcardAction(s) {
						hasWildcards = true
					}
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

	return ExtractedActions{
		AllowActions:    allowList,
		DenyActions:     denyList,
		NotActionStmts:  notActionStmts,
		HasWildcards:    hasWildcards,
		HasConditions:   hasConditions,
		HasNotResources: hasNotResources,
	}
}

// policyWarnings builds a list of human-readable caveats for the user
func policyWarnings(extracted ExtractedActions) []string {
	var warnings []string
	if extracted.HasWildcards {
		warnings = append(warnings, "⚠️  Policy contains wildcard actions (e.g. s3:* or ec2:Describe*). "+
			"This tool checks the wildcard pattern against the boundary as-is and cannot enumerate "+
			"every concrete action it covers. A wildcard may match boundary-allowed AND boundary-denied "+
			"actions simultaneously — review manually.")
	}
	if len(extracted.NotActionStmts) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"⚠️  Policy contains %d statement(s) using NotAction. These grant (or deny) a broad "+
				"set of actions and cannot be fully evaluated without a complete AWS action catalog. "+
				"Review these statements manually (details shown below).",
			len(extracted.NotActionStmts)))
	}
	if extracted.HasConditions {
		warnings = append(warnings, "⚠️  Policy contains Condition keys. This tool does not evaluate "+
			"conditions — an action may appear allowed/blocked here but behave differently at runtime "+
			"depending on request context.")
	}
	if extracted.HasNotResources {
		warnings = append(warnings, "⚠️  Policy contains NotResource. Resource scope is not evaluated "+
			"by this tool.")
	}
	return warnings
}

// diffPolicies computes actions in A that are allowed but not in B
func diffPolicies(pbA, pbB *PermissionBoundary, actionsA []string) (onlyInA, onlyInB []string) {
	for _, a := range actionsA {
		inA := isActionAllowed(a, pbA)
		inB := isActionAllowed(a, pbB)
		if inA && !inB {
			onlyInA = append(onlyInA, a)
		} else if !inA && inB {
			onlyInB = append(onlyInB, a)
		}
	}
	return
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pb-checker",
		Short: "AWS IAM Permission Boundary Checker",
		Long:  "Validate AWS IAM actions and policies against a permission boundary definition.",
	}

	root.Version = version
	root.PersistentFlags().String("pb", "pb.json", "Path to the permission boundary file (JSON or text format), or '-' for stdin")
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(newCheckActionCmd())
	root.AddCommand(newCheckPolicyCmd())
	root.AddCommand(newDiffCmd())

	return root
}

func newCheckActionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-action <action> [action...]",
		Short: "Check if one or more actions are allowed by the permission boundary",
		Args:  cobra.MinimumNArgs(1),
		Example: `  pb-checker check-action ec2:RunInstances
  pb-checker check-action s3:PutObject s3:GetObject ec2:DescribeInstances
  pb-checker check-action --pb boundary.json s3:PutObject
  aws iam get-policy-version ... | pb-checker --pb - check-action ec2:RunInstances`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")

			pb, err := loadPermissionBoundaryUnified(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)

			anyDenied := false
			for _, action := range args {
				if isWildcardAction(action) {
					fmt.Fprintf(os.Stderr, "⚠️  '%s' contains a wildcard — result reflects pattern matching only, not full action enumeration.\n", action)
				}
				if isActionAllowed(action, pb) {
					if pb.Policy != nil {
						fmt.Printf("✅ '%s' is ALLOWED by the permission boundary\n", action)
					} else {
						_, matchingPatterns := matchesAnyPattern(action, pb.Patterns)
						fmt.Printf("✅ '%s' matches pattern(s): %s\n", action, strings.Join(matchingPatterns, ", "))
					}
				} else {
					anyDenied = true
					if pb.Policy != nil {
						fmt.Printf("❌ '%s' is DENIED by the permission boundary\n", action)
					} else {
						fmt.Printf("❌ '%s' does not match any pattern\n", action)
					}
				}
			}

			if anyDenied {
				os.Exit(1)
			}
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
  pb-checker check-policy --pb boundary.json --output table policy.json
  cat policy.json | pb-checker check-policy -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			format, _ := cmd.Flags().GetString("output")
			policyFile := args[0]

			data, err := readPolicyFromPathOrStdin(policyFile)
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var policy PolicyDocument
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			extracted := extractActions(policy)
			if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 && len(extracted.NotActionStmts) == 0 {
				fmt.Println("No actions found in policy")
				return nil
			}

			pb, err := loadPermissionBoundaryUnified(pbFile)
			if err != nil {
				return fmt.Errorf("loading permission boundary: %w", err)
			}

			warnings := policyWarnings(extracted)

			// Evaluate Allow actions against the permission boundary
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

			// Summarise NotAction statements for display
			var notActionSummaries []string
			for _, nas := range extracted.NotActionStmts {
				summary := fmt.Sprintf("Effect=%s NotAction=[%s]", nas.Effect, strings.Join(nas.NotActions, ", "))
				if nas.Condition != nil {
					summary += " (has Condition)"
				}
				notActionSummaries = append(notActionSummaries, summary)
			}

			switch format {
			case "json":
				result := map[string]interface{}{
					"evaluation_method":     pb.EvaluationMethod,
					"allowed":               nullableStringSlice(allowedActions),
					"blocked":               nullableStringSlice(blockedActions),
					"skipped_deny":          nullableStringSlice(extracted.DenyActions),
					"not_action_statements": notActionSummaries,
					"warnings":              warnings,
					"summary": map[string]int{
						"allowed":               len(allowedActions),
						"blocked":               len(blockedActions),
						"skipped_deny":          len(extracted.DenyActions),
						"not_action_statements": len(extracted.NotActionStmts),
					},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			case "table":
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				printWarnings(warnings, os.Stderr)
				fmt.Printf("%-60s %s\n", "ACTION", "STATUS")
				fmt.Printf("%s\n", strings.Repeat("-", 75))
				for _, a := range allowedActions {
					fmt.Printf("%-60s %s\n", a, "✅ ALLOWED")
				}
				for _, a := range blockedActions {
					fmt.Printf("%-60s %s\n", a, "❌ BLOCKED")
				}
				for _, a := range extracted.DenyActions {
					fmt.Printf("%-60s %s\n", a, "⏭️  SKIPPED (explicitly denied by policy)")
				}
				for _, s := range notActionSummaries {
					fmt.Printf("%-60s %s\n", s, "⚠️  NOTACTION (manual review needed)")
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions), len(extracted.NotActionStmts))

			default: // list
				fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
				printWarnings(warnings, os.Stderr)
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
					fmt.Println("\n⏭️  Skipped actions (explicitly denied by policy, irrelevant to boundary check):")
					for _, a := range extracted.DenyActions {
						fmt.Printf("  %s\n", a)
					}
				}
				if len(notActionSummaries) > 0 {
					fmt.Println("\n⚠️  NotAction statements (requires manual review):")
					for _, s := range notActionSummaries {
						fmt.Printf("  %s\n", s)
					}
				}
				fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (denied by policy), %d NotAction statement(s)\n",
					len(allowedActions), len(blockedActions), len(extracted.DenyActions), len(extracted.NotActionStmts))
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

func newDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <policy-file>",
		Short: "Compare policy actions against two permission boundaries to show what changes",
		Long: `Loads two permission boundaries (--pb and --pb-new) and reports which Allow actions
in the given policy would gain or lose access when switching from the old to the new boundary.`,
		Args: cobra.ExactArgs(1),
		Example: `  pb-checker diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  pb-checker diff --pb old-boundary.json --pb-new new-boundary.json --output json policy.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pbFile, _ := cmd.Flags().GetString("pb")
			pbNewFile, _ := cmd.Flags().GetString("pb-new")
			format, _ := cmd.Flags().GetString("output")
			policyFile := args[0]

			if pbNewFile == "" {
				return fmt.Errorf("--pb-new is required for the diff subcommand")
			}

			data, err := readPolicyFromPathOrStdin(policyFile)
			if err != nil {
				return fmt.Errorf("reading policy file: %w", err)
			}

			var policy PolicyDocument
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("parsing policy JSON: %w", err)
			}

			extracted := extractActions(policy)

			pbOld, err := loadPermissionBoundaryUnified(pbFile)
			if err != nil {
				return fmt.Errorf("loading old permission boundary: %w", err)
			}

			pbNew, err := loadPermissionBoundaryUnified(pbNewFile)
			if err != nil {
				return fmt.Errorf("loading new permission boundary: %w", err)
			}

			// Classify every Allow action
			type diffEntry struct {
				Action     string
				OldAllowed bool
				NewAllowed bool
			}

			var entries []diffEntry
			for _, action := range extracted.AllowActions {
				entries = append(entries, diffEntry{
					Action:     action,
					OldAllowed: isActionAllowed(action, pbOld),
					NewAllowed: isActionAllowed(action, pbNew),
				})
			}

			var gained, lost, unchanged []string
			for _, e := range entries {
				switch {
				case !e.OldAllowed && e.NewAllowed:
					gained = append(gained, e.Action)
				case e.OldAllowed && !e.NewAllowed:
					lost = append(lost, e.Action)
				default:
					unchanged = append(unchanged, e.Action)
				}
			}

			warnings := policyWarnings(extracted)

			switch format {
			case "json":
				result := map[string]interface{}{
					"gained":    nullableStringSlice(gained),
					"lost":      nullableStringSlice(lost),
					"unchanged": nullableStringSlice(unchanged),
					"warnings":  warnings,
					"summary": map[string]int{
						"gained":    len(gained),
						"lost":      len(lost),
						"unchanged": len(unchanged),
					},
				}
				out, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(out))

			default: // list
				printWarnings(warnings, os.Stderr)
				if len(gained) > 0 {
					fmt.Println("🟢 Newly allowed by new boundary (gained access):")
					for _, a := range gained {
						fmt.Printf("  %s\n", a)
					}
				}
				if len(lost) > 0 {
					fmt.Println("\n🔴 No longer allowed by new boundary (lost access):")
					for _, a := range lost {
						fmt.Printf("  %s\n", a)
					}
				}
				if len(unchanged) > 0 {
					fmt.Printf("\n⬜ Unchanged: %d action(s)\n", len(unchanged))
				}
				fmt.Printf("\nSummary: %d gained, %d lost, %d unchanged\n", len(gained), len(lost), len(unchanged))
			}

			// Exit non-zero if any access is lost
			if len(lost) > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().String("pb-new", "", "Path to the new permission boundary to compare against (required)")
	cmd.Flags().String("output", "list", "Output format: list or json")
	return cmd
}

func printWarnings(warnings []string, w *os.File) {
	for _, warn := range warnings {
		fmt.Fprintln(w, warn)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w)
	}
}

// nullableStringSlice returns an empty slice (not nil) so JSON output is [] not null
func nullableStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
