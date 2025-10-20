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

func loadPatternsFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PolicyVersionWrapper (aws iam get-policy-version format)
	var wrapper PolicyVersionWrapper
	if err := json.Unmarshal(data, &wrapper); err == nil {
		patterns := extractPatternsFromPolicy(wrapper.PolicyVersion.Document)
		if len(patterns) > 0 {
			return patterns, nil
		}
	}

	// Try to parse as direct PolicyDocument
	var policy PolicyDocument
	if err := json.Unmarshal(data, &policy); err == nil {
		patterns := extractPatternsFromPolicy(policy)
		if len(patterns) > 0 {
			return patterns, nil
		}
	}

	// Try to parse as simple JSON array
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err == nil {
		return patterns, nil
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

	if len(patterns) == 0 {
		return nil, fmt.Errorf("no patterns found in file")
	}

	return patterns, nil
}

func loadPermissionBoundary(filename string) (PolicyDocument, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PolicyVersionWrapper (aws iam get-policy-version format)
	var wrapper PolicyVersionWrapper
	if err := json.Unmarshal(data, &wrapper); err == nil {
		return wrapper.PolicyVersion.Document, nil
	}

	// Try to parse as direct PolicyDocument
	var policy PolicyDocument
	if err := json.Unmarshal(data, &policy); err == nil {
		return policy, nil
	}

	return PolicyDocument{}, fmt.Errorf("unable to parse permission boundary policy")
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

func extractPatternsFromPolicy(policy PolicyDocument) []string {
	var patterns []string

	for _, statement := range policy.Statement {
		// For permission boundaries, we want patterns from Deny statements with NotAction
		// These represent the actions that are NOT denied (i.e., allowed)
		if statement.Effect == "Deny" && statement.NotAction != nil {
			patterns = append(patterns, extractStrings(statement.NotAction)...)
		}
	}

	return patterns
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

func extractActions(policy PolicyDocument) []string {
	actionsMap := make(map[string]bool)

	for _, statement := range policy.Statement {
		if statement.Action == nil {
			continue
		}

		// Action can be a string or array of strings
		switch actions := statement.Action.(type) {
		case string:
			actionsMap[actions] = true
		case []interface{}:
			for _, action := range actions {
				if actionStr, ok := action.(string); ok {
					actionsMap[actionStr] = true
				}
			}
		}
	}

	// Convert map to sorted slice
	var actionsList []string
	for action := range actionsMap {
		actionsList = append(actionsList, action)
	}
	sort.Strings(actionsList)

	return actionsList
}

func pbCheckCommand(args []string) {
	fs := flag.NewFlagSet("pb-check", flag.ExitOnError)
	configFile := fs.String("pb", "pb.json", "Path to the permission boundary file (JSON or text format)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s pb-check [options] <action>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Check if an AWS action matches allowed patterns (permission boundary check)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s pb-check -pb pb.json ec2:RunInstances\n", os.Args[0])
	}

	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	action := fs.Arg(0)

	// Try to load as full policy document first
	pbPolicy, err := loadPermissionBoundary(*configFile)
	if err == nil {
		// Evaluate using full policy logic
		if evaluatePermissionBoundary(action, pbPolicy) {
			fmt.Printf("✅ '%s' is ALLOWED by the permission boundary\n", action)
			os.Exit(0)
		} else {
			fmt.Printf("❌ '%s' is DENIED by the permission boundary\n", action)
			os.Exit(1)
		}
	}

	// Fallback to pattern matching for simple pattern files
	patterns, err := loadPatternsFromFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading permission boundary: %v\n", err)
		os.Exit(1)
	}

	matched, matchingPatterns := matchesAnyPattern(action, patterns)

	if matched {
		fmt.Printf("✅ '%s' matches the following pattern(s):\n", action)
		for _, pattern := range matchingPatterns {
			fmt.Printf("  - %s\n", pattern)
		}
		os.Exit(0)
	} else {
		fmt.Printf("❌ '%s' does not match any pattern\n", action)
		os.Exit(1)
	}
}

func getBlockedActionsCommand(args []string) {
	fs := flag.NewFlagSet("get-blocked-actions", flag.ExitOnError)
	configFile := fs.String("pb", "pb.json", "Path to the permission boundary file (JSON or text format)")
	outputFormat := fs.String("format", "list", "Output format: list, json, or table")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s get-blocked-actions [options] <policy-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Extract actions from an IAM policy that are blocked by permission boundary\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s get-blocked-actions policy.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s get-blocked-actions -format json policy.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s get-blocked-actions -pb pb.json policy.json\n", os.Args[0])
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

	actions := extractActions(policy)

	if len(actions) == 0 {
		fmt.Println("No actions found in policy")
		return
	}

	// Try to load permission boundary as full policy document first
	pbPolicy, err := loadPermissionBoundary(*configFile)
	var allowedActions []string
	var blockedActions []string

	if err == nil {
		// Use full policy evaluation logic
		for _, action := range actions {
			if evaluatePermissionBoundary(action, pbPolicy) {
				allowedActions = append(allowedActions, action)
			} else {
				blockedActions = append(blockedActions, action)
			}
		}
	} else {
		// Fallback to simple pattern matching
		patterns, err := loadPatternsFromFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading permission boundary: %v\n", err)
			os.Exit(1)
		}

		for _, action := range actions {
			matched, _ := matchesAnyPattern(action, patterns)
			if matched {
				allowedActions = append(allowedActions, action)
			} else {
				blockedActions = append(blockedActions, action)
			}
		}
	}

	// Sort both lists alphabetically
	sort.Strings(allowedActions)
	sort.Strings(blockedActions)

	// Output results
	switch *outputFormat {
	case "json":
		result := map[string]interface{}{
			"allowed": allowedActions,
			"blocked": blockedActions,
			"summary": map[string]int{
				"allowed": len(allowedActions),
				"blocked": len(blockedActions),
			},
		}
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))

	case "table":
		fmt.Printf("%-60s %s\n", "ACTION", "STATUS")
		fmt.Printf("%s\n", strings.Repeat("-", 75))
		for _, action := range allowedActions {
			fmt.Printf("%-60s %s\n", action, "✅ ALLOWED")
		}
		for _, action := range blockedActions {
			fmt.Printf("%-60s %s\n", action, "❌ BLOCKED")
		}
		fmt.Printf("\nSummary: %d allowed, %d blocked\n", len(allowedActions), len(blockedActions))

	default: // list
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

		fmt.Printf("\nSummary: %d allowed, %d blocked\n", len(allowedActions), len(blockedActions))
	}

	// Exit with error code if there are blocked actions
	if len(blockedActions) > 0 {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "AWS IAM Action Matcher\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  pb-check              Check if an action matches permission boundary patterns\n")
	fmt.Fprintf(os.Stderr, "  get-blocked-actions   Extract actions from a policy that are blocked by permission boundary\n")
	fmt.Fprintf(os.Stderr, "\nRun '%s <command> -h' for more information on a command.\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "pb-check":
		pbCheckCommand(os.Args[2:])
	case "get-blocked-actions":
		getBlockedActionsCommand(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}
