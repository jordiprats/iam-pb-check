package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/boundary"
	"github.com/jordiprats/iamctl/pkg/matcher"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

// statementMatch describes a single policy statement that matched an action.
type statementMatch struct {
	PolicyName  string      `json:"policy_name"`
	PolicyType  string      `json:"policy_type"` // "managed" or "inline"
	Effect      string      `json:"effect"`      // "Allow" or "Deny"
	Sid         string      `json:"sid,omitempty"`
	Pattern     string      `json:"matched_pattern"`
	Resources   []string    `json:"resources,omitempty"`
	Conditions  interface{} `json:"conditions,omitempty"`
	Conditional bool        `json:"conditional"` // true when Resource != "*" or Condition is present
}

// isConditionalMatch returns true when the statement has resource restrictions
// (not just "*") or condition constraints.
func isConditionalMatch(resources []string, conditions interface{}) bool {
	if conditions != nil {
		return true
	}
	if len(resources) == 0 {
		return false
	}
	for _, r := range resources {
		if r != "*" {
			return true
		}
	}
	return false
}

// actionCheckResult holds the evaluation result for a single action.
type actionCheckResult struct {
	Action          string           `json:"action"`
	Allowed         bool             `json:"allowed"`
	Conditional     bool             `json:"conditional"`
	Reason          string           `json:"reason"`
	BoundaryAllowed *bool            `json:"boundary_allowed,omitempty"`
	AllowMatches    []statementMatch `json:"allow_matches,omitempty"`
	DenyMatches     []statementMatch `json:"deny_matches,omitempty"`
}

// policyStatementIndex stores pre-indexed statement data per policy.
type policyStatementIndex struct {
	policyName string
	policyType string // "managed" or "inline"
	statements []policy.Statement
}

// runCheckRoleAction checks whether specific actions are granted by a role's policies,
// optionally also checking against a permission boundary.
func runCheckRoleAction(cmd *cobra.Command, roleName string, actions []string) error {
	format, _ := cmd.Flags().GetString("output")
	profile, _ := cmd.Flags().GetString("profile")

	iamClient, err := awsiam.NewIAMClient(cmd.Context(), profile)
	if err != nil {
		return err
	}

	// Load permission boundary if provided or available on the role
	var pb *boundary.PermissionBoundary
	if cmd.Flags().Changed("pb") {
		pbFile, _ := cmd.Flags().GetString("pb")
		pb, err = boundary.LoadFromFile(pbFile)
		if err != nil {
			return fmt.Errorf("loading permission boundary: %w", err)
		}
	} else {
		pb, _ = awsiam.FetchRoleBoundary(cmd.Context(), iamClient, roleName)
		// pb may be nil if the role has no boundary — that's fine
	}

	managedPolicies, err := awsiam.FetchRolePolicies(cmd.Context(), iamClient, roleName)
	if err != nil {
		return fmt.Errorf("fetching managed policies: %w", err)
	}

	inlinePolicies, err := awsiam.FetchRoleInlinePolicies(cmd.Context(), iamClient, roleName)
	if err != nil {
		return fmt.Errorf("fetching inline policies: %w", err)
	}

	if len(managedPolicies) == 0 && len(inlinePolicies) == 0 {
		fmt.Println("No policies attached to role")
		return nil
	}

	// Index all statements per policy
	var policyIndex []policyStatementIndex
	for name, doc := range managedPolicies {
		policyIndex = append(policyIndex, policyStatementIndex{
			policyName: name,
			policyType: "managed",
			statements: doc.Statement,
		})
	}
	for name, doc := range inlinePolicies {
		policyIndex = append(policyIndex, policyStatementIndex{
			policyName: name,
			policyType: "inline",
			statements: doc.Statement,
		})
	}

	// Evaluate each requested action
	var results []actionCheckResult
	anyDenied := false

	for _, action := range actions {
		r := actionCheckResult{Action: action}

		for _, pi := range policyIndex {
			for _, stmt := range pi.statements {
				actionPatterns := matcher.ExtractStrings(stmt.Action)
				if len(actionPatterns) == 0 {
					continue
				}

				if matched, matchingPatterns := matcher.MatchesAnyPattern(action, actionPatterns); matched {
					resources := matcher.ExtractStrings(stmt.Resource)
					m := statementMatch{
						PolicyName:  pi.policyName,
						PolicyType:  pi.policyType,
						Effect:      stmt.Effect,
						Sid:         stmt.Sid,
						Pattern:     strings.Join(matchingPatterns, ", "),
						Resources:   resources,
						Conditions:  stmt.Condition,
						Conditional: isConditionalMatch(resources, stmt.Condition),
					}
					if stmt.Effect == "Deny" {
						r.DenyMatches = append(r.DenyMatches, m)
					} else {
						r.AllowMatches = append(r.AllowMatches, m)
					}
				}
			}
		}

		// Check permission boundary if available
		if pb != nil {
			boundaryOk := boundary.IsActionAllowed(action, pb)
			r.BoundaryAllowed = &boundaryOk
		}

		// Final determination
		hasDeny := len(r.DenyMatches) > 0
		hasAllow := len(r.AllowMatches) > 0
		boundaryOk := r.BoundaryAllowed == nil || *r.BoundaryAllowed

		switch {
		case hasDeny:
			r.Allowed = false
			r.Reason = fmt.Sprintf("explicit deny in %s", r.DenyMatches[0].PolicyName)
		case !hasAllow:
			r.Allowed = false
			r.Reason = "no policy grants this action"
		case !boundaryOk:
			r.Allowed = false
			r.Reason = "blocked by permission boundary"
		default:
			r.Allowed = true
			r.Reason = fmt.Sprintf("granted by %s", r.AllowMatches[0].PolicyName)
			// Check if ALL allow matches are conditional (restricted by Resource or Condition)
			allConditional := true
			for _, m := range r.AllowMatches {
				if !m.Conditional {
					allConditional = false
					break
				}
			}
			r.Conditional = allConditional
		}

		if !r.Allowed {
			anyDenied = true
		}

		results = append(results, r)
	}

	switch format {
	case "json":
		out, _ := json.MarshalIndent(map[string]interface{}{
			"role":    roleName,
			"results": results,
		}, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "Role: %s\n", roleName)
		if pb != nil {
			fmt.Fprintf(os.Stderr, "Permission boundary: %s\n", pb.EvaluationMethod)
		}
		fmt.Fprintln(os.Stderr)

		for _, r := range results {
			if matcher.IsWildcardAction(r.Action) {
				fmt.Fprintf(os.Stderr, "🟡  '%s' contains a wildcard — result reflects pattern matching only.\n", r.Action)
			}

			if r.Allowed {
				if r.Conditional {
					fmt.Printf("🟡  %-58s ALLOWED (conditional — resource/condition restrictions apply)\n", r.Action)
				} else {
					fmt.Printf("🟢  %-58s ALLOWED\n", r.Action)
				}
			} else {
				fmt.Printf("🔴  %-58s %s\n", r.Action, strings.ToUpper(r.Reason))
			}

			// Print detail for allow matches
			for _, m := range r.AllowMatches {
				label := m.PolicyName
				if m.PolicyType == "inline" {
					label += " (inline)"
				}
				fmt.Printf("      Allow via: %-40s pattern: %s\n", label, m.Pattern)
				if m.Sid != "" {
					fmt.Printf("        Sid: %s\n", m.Sid)
				}
				if len(m.Resources) > 0 {
					fmt.Printf("        Resources: %s\n", strings.Join(m.Resources, ", "))
				}
				if m.Conditions != nil {
					condJSON, _ := json.Marshal(m.Conditions)
					fmt.Printf("        Conditions: %s\n", string(condJSON))
				}
			}

			// Print detail for deny matches
			for _, m := range r.DenyMatches {
				label := m.PolicyName
				if m.PolicyType == "inline" {
					label += " (inline)"
				}
				fmt.Printf("      Deny via:  %-40s pattern: %s\n", label, m.Pattern)
				if m.Sid != "" {
					fmt.Printf("        Sid: %s\n", m.Sid)
				}
				if len(m.Resources) > 0 {
					fmt.Printf("        Resources: %s\n", strings.Join(m.Resources, ", "))
				}
				if m.Conditions != nil {
					condJSON, _ := json.Marshal(m.Conditions)
					fmt.Printf("        Conditions: %s\n", string(condJSON))
				}
			}
		}
	}

	if anyDenied {
		os.Exit(1)
	}
	return nil
}
