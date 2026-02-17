package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		// Skip empty lines and comments
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

	for _, statement := range policy.Statement {
		if statement.Effect == "Allow" {
			// Check if this Allow statement applies to the action
			if statement.Action != nil {
				patterns := extractStrings(statement.Action)
				if matches, _ := matchesAnyPattern(action, patterns); matches {
					allowed = true
				}
			}
		} else if statement.Effect == "Deny" {
			// Check Deny with NotAction (means deny everything EXCEPT these)
			if statement.NotAction != nil {
				patterns := extractStrings(statement.NotAction)
				// If action does NOT match NotAction patterns, it's denied
				if matches, _ := matchesAnyPattern(action, patterns); !matches {
					denied = true
				}
			} else if statement.Action != nil {
				// Regular Deny with Action
				patterns := extractStrings(statement.Action)
				if matches, _ := matchesAnyPattern(action, patterns); matches {
					denied = true
				}
			}
		}
	}

	// Explicit deny always wins
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

func matchesAnyPattern(action string, patterns []string) (bool, []string) {
	var matches []string
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, action)
		if err != nil {
			continue
		}
		if matched {
			matches = append(matches, pattern)
		}
	}
	return len(matches) > 0, matches
}

// extractActions separates actions by their Effect (Allow vs Deny) in the source policy
func extractActions(policy PolicyDocument) ExtractedActions {
	allowMap := make(map[string]bool)
	denyMap := make(map[string]bool)

	for _, statement := range policy.Statement {
		if statement.Action == nil {
			continue
		}

		target := allowMap
		if statement.Effect == "Deny" {
			target = denyMap
		}

		switch actions := statement.Action.(type) {
		case string:
			target[actions] = true
		case []interface{}:
			for _, action := range actions {
				if actionStr, ok := action.(string); ok {
					target[actionStr] = true
				}
			}
		}
	}

	// Convert maps to sorted slices
	var allowList, denyList []string
	for action := range allowMap {
		allowList = append(allowList, action)
	}
	for action := range denyMap {
		denyList = append(denyList, action)
	}
	sort.Strings(allowList)
	sort.Strings(denyList)

	return ExtractedActions{
		AllowActions: allowList,
		DenyActions:  denyList,
	}
}

func checkActionCommand(args []string) {
	fs := flag.NewFlagSet("check-action", flag.ExitOnError)
	configFile := fs.String("pb", "pb.json", "Path to the permission boundary file (JSON or text format)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s check-action [options] <action>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Check if an AWS action is allowed by the permission boundary\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s check-action -pb pb.json ec2:RunInstances\n", os.Args[0])
	}

	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	action := fs.Arg(0)

	// Load permission boundary
	pb, err := loadPermissionBoundaryUnified(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading permission boundary: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)

	if isActionAllowed(action, pb) {
		if pb.Policy != nil {
			fmt.Printf("✅ '%s' is ALLOWED by the permission boundary\n", action)
		} else {
			matched, matchingPatterns := matchesAnyPattern(action, pb.Patterns)
			if matched {
				fmt.Printf("✅ '%s' matches the following pattern(s):\n", action)
				for _, pattern := range matchingPatterns {
					fmt.Printf("  - %s\n", pattern)
				}
			}
		}
		os.Exit(0)
	} else {
		if pb.Policy != nil {
			fmt.Printf("❌ '%s' is DENIED by the permission boundary\n", action)
		} else {
			fmt.Printf("❌ '%s' does not match any pattern\n", action)
		}
		os.Exit(1)
	}
}

func checkPolicyCommand(args []string) {
	fs := flag.NewFlagSet("check-policy", flag.ExitOnError)
	configFile := fs.String("pb", "pb.json", "Path to the permission boundary file (JSON or text format)")
	outputFormat := fs.String("format", "list", "Output format: list, json, or table")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s check-policy [options] <policy-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Check which actions in an IAM policy are allowed or blocked by the permission boundary\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s check-policy policy.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s check-policy -format json policy.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s check-policy -pb pb.json policy.json\n", os.Args[0])
	}

	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	policyFile := fs.Arg(0)

	// Read and parse policy file
	data, err := os.ReadFile(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading policy file: %v\n", err)
		os.Exit(1)
	}

	var policy PolicyDocument
	if err := json.Unmarshal(data, &policy); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing policy JSON: %v\n", err)
		os.Exit(1)
	}

	extracted := extractActions(policy)

	if len(extracted.AllowActions) == 0 && len(extracted.DenyActions) == 0 {
		fmt.Println("No actions found in policy")
		return
	}

	// Load permission boundary
	pb, err := loadPermissionBoundaryUnified(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading permission boundary: %v\n", err)
		os.Exit(1)
	}

	// Evaluate only Allow actions against the permission boundary
	var allowedActions []string
	var blockedActions []string

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
	switch *outputFormat {
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
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))

	case "table":
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
		fmt.Printf("%-60s %s\n", "ACTION", "STATUS")
		fmt.Printf("%s\n", strings.Repeat("-", 75))
		for _, action := range allowedActions {
			fmt.Printf("%-60s %s\n", action, "✅ ALLOWED")
		}
		for _, action := range blockedActions {
			fmt.Printf("%-60s %s\n", action, "❌ BLOCKED")
		}
		for _, action := range extracted.DenyActions {
			fmt.Printf("%-60s %s\n", action, "⏭️  SKIPPED (denied by policy)")
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (already denied by policy)\n",
			len(allowedActions), len(blockedActions), len(extracted.DenyActions))

	default: // list
		fmt.Fprintf(os.Stderr, "Evaluation method: %s\n\n", pb.EvaluationMethod)
		if len(allowedActions) > 0 {
			fmt.Println("✅ Allowed actions:")
			for _, action := range allowedActions {
				fmt.Printf("  %s\n", action)
			}
		}

		if len(blockedActions) > 0 {
			fmt.Println("\n❌ Blocked actions (not allowed by permission boundary):")
			for _, action := range blockedActions {
				fmt.Printf("  %s\n", action)
			}
		}

		if len(extracted.DenyActions) > 0 {
			fmt.Println("\n⏩  Skipped actions (already denied by policy):")
			for _, action := range extracted.DenyActions {
				fmt.Printf("  %s\n", action)
			}
		}

		fmt.Printf("\nSummary: %d allowed, %d blocked, %d skipped (already denied by policy)\n",
			len(allowedActions), len(blockedActions), len(extracted.DenyActions))
	}

	// Exit with error code if there are blocked actions
	if len(blockedActions) > 0 {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "AWS IAM Permission Boundary Checker\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  check-action    Check if a single action is allowed by the permission boundary\n")
	fmt.Fprintf(os.Stderr, "  check-policy    Check which actions in a policy are allowed or blocked\n")
	fmt.Fprintf(os.Stderr, "\nRun '%s <command> -h' for more information on a command.\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "check-action":
		checkActionCommand(os.Args[2:])
	case "check-policy":
		checkPolicyCommand(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}
