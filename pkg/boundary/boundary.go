package boundary

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jordiprats/iamctl/pkg/matcher"
	"github.com/jordiprats/iamctl/pkg/policy"
)

// PermissionBoundary holds the loaded permission boundary.
type PermissionBoundary struct {
	Policy           *policy.PolicyDocument
	Patterns         []string
	EvaluationMethod string
}

// LoadFromFile loads a permission boundary from a file (or stdin if filename is "-").
func LoadFromFile(filename string) (*PermissionBoundary, error) {
	var data []byte
	var err error

	if filename == "-" {
		data, err = policy.ReadStdin()
	} else {
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PolicyVersionWrapper (aws iam get-policy-version format)
	var wrapper policy.PolicyVersionWrapper
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.PolicyVersion.Document.Statement) > 0 {
		doc := wrapper.PolicyVersion.Document
		return &PermissionBoundary{
			Policy:           &doc,
			EvaluationMethod: "Full IAM policy evaluation",
		}, nil
	}

	// Try to parse as direct PolicyDocument
	var doc policy.PolicyDocument
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Statement) > 0 {
		return &PermissionBoundary{
			Policy:           &doc,
			EvaluationMethod: "Full IAM policy evaluation",
		}, nil
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

// IsActionAllowed checks if an action is allowed by the permission boundary.
func IsActionAllowed(action string, pb *PermissionBoundary) bool {
	if pb.Policy != nil {
		return EvaluatePolicy(action, *pb.Policy)
	}
	matched, _ := matcher.MatchesAnyPattern(action, pb.Patterns)
	return matched
}

// EvaluatePolicy checks if an action is allowed by the permission boundary policy document.
func EvaluatePolicy(action string, doc policy.PolicyDocument) bool {
	allowed := false
	denied := false

	for _, stmt := range doc.Statement {
		switch stmt.Effect {
		case "Allow":
			if stmt.Action != nil {
				patterns := matcher.ExtractStrings(stmt.Action)
				if matches, _ := matcher.MatchesAnyPattern(action, patterns); matches {
					allowed = true
				}
			} else if stmt.NotAction != nil {
				patterns := matcher.ExtractStrings(stmt.NotAction)
				if matches, _ := matcher.MatchesAnyPattern(action, patterns); !matches {
					// For wildcard actions: if the wildcard overlaps with a NotAction entry,
					// we can't confirm the wildcard is fully outside NotAction — skip.
					if matcher.IsWildcardAction(action) && matcher.WildcardOverlapsAnyPattern(action, patterns) {
						break
					}
					allowed = true
				}
			}
		case "Deny":
			if stmt.NotAction != nil {
				patterns := matcher.ExtractStrings(stmt.NotAction)
				if matches, _ := matcher.MatchesAnyPattern(action, patterns); !matches {
					// For wildcard actions: if the wildcard overlaps with a NotAction entry,
					// at least some expansions are NOT denied — skip to avoid false positives.
					if matcher.IsWildcardAction(action) && matcher.WildcardOverlapsAnyPattern(action, patterns) {
						break
					}
					denied = true
				}
			} else if stmt.Action != nil {
				patterns := matcher.ExtractStrings(stmt.Action)
				if matches, _ := matcher.MatchesAnyPattern(action, patterns); matches {
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

// FindAllowingPatterns returns the patterns from the permission boundary that cause
// the action to be allowed (or denied). For policy-based boundaries it inspects each
// statement; for simple pattern lists it delegates to matcher.MatchesAnyPattern.
func FindAllowingPatterns(action string, pb *PermissionBoundary) []string {
	if pb.Policy != nil {
		return findPolicyMatchingPatterns(action, *pb.Policy)
	}
	_, patterns := matcher.MatchesAnyPattern(action, pb.Patterns)
	return patterns
}

// findPolicyMatchingPatterns collects the most informative patterns explaining
// why an action is allowed. When a Deny+NotAction statement is present, the
// specific NotAction patterns that saved the action from denial are returned
// instead of the less useful Allow:* pattern.
func findPolicyMatchingPatterns(action string, doc policy.PolicyDocument) []string {
	var allowPatterns []string
	var denyNotActionMatches []string
	hasDenyNotAction := false

	for _, stmt := range doc.Statement {
		switch stmt.Effect {
		case "Allow":
			if stmt.Action != nil {
				patterns := matcher.ExtractStrings(stmt.Action)
				if _, matched := matcher.MatchesAnyPattern(action, patterns); len(matched) > 0 {
					allowPatterns = append(allowPatterns, matched...)
				}
			} else if stmt.NotAction != nil {
				patterns := matcher.ExtractStrings(stmt.NotAction)
				if matches, _ := matcher.MatchesAnyPattern(action, patterns); !matches {
					if matcher.IsWildcardAction(action) && matcher.WildcardOverlapsAnyPattern(action, patterns) {
						continue
					}
					allowPatterns = append(allowPatterns, "NotAction (everything except "+strings.Join(patterns, ", ")+")")
				}
			}
		case "Deny":
			if stmt.NotAction != nil {
				hasDenyNotAction = true
				patterns := matcher.ExtractStrings(stmt.NotAction)
				if _, matched := matcher.MatchesAnyPattern(action, patterns); len(matched) > 0 {
					// These are the NotAction patterns that saved the action from the deny
					denyNotActionMatches = append(denyNotActionMatches, matched...)
				}
			}
		}
	}

	// When a Deny+NotAction is present and matched, those are more informative
	// than a broad Allow:* — show which patterns prevented the deny.
	if hasDenyNotAction && len(denyNotActionMatches) > 0 {
		return denyNotActionMatches
	}
	return allowPatterns
}

// DiffPolicies computes actions in A that are allowed but not in B.
func DiffPolicies(pbA, pbB *PermissionBoundary, actionsA []string) (onlyInA, onlyInB []string) {
	for _, a := range actionsA {
		inA := IsActionAllowed(a, pbA)
		inB := IsActionAllowed(a, pbB)
		if inA && !inB {
			onlyInA = append(onlyInA, a)
		} else if !inA && inB {
			onlyInB = append(onlyInB, a)
		}
	}
	return
}
