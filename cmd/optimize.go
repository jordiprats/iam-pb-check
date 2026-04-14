package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jordiprats/iamctl/pkg/awsiam"
	"github.com/jordiprats/iamctl/pkg/matcher"
	"github.com/jordiprats/iamctl/pkg/policy"
	"github.com/spf13/cobra"
)

func newOptimizeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "optimize <role-name>",
		Aliases: []string{
			"opt", "minimize",
			// legacy shrink-role-policies aliases
			"shrink-role-policies", "shrink", "srp",
			// legacy policy-from-role-usage aliases
			"policy-from-role-usage", "activity-policy", "policy-from-usage", "pfu",
		},
		Short: "Generate a minimal policy for a role based on actual usage",
		Long: `Analyze a role's service last accessed data (at ACTION_LEVEL granularity) and
generate a minimal policy containing only the actions the role has actually used.

By default (shrink mode), the command fetches attached managed policies and removes
unused Allow actions while preserving Deny statements, NotAction statements,
Conditions, Resources, and Sids.

Use --from-scratch to ignore existing policies and generate a clean-slate policy
from the raw usage data (all actions grouped by service, Resource: "*").

Use --ignore-deny to omit Deny statements from the output.
Use --strict to expand wildcard actions to exact observed actions and deduplicate
equivalent statements while preserving targeted resources.`,
		Args: cobra.ExactArgs(1),
		Example: `  # Shrink a role's policies to only used actions (default)
  iamctl optimize my-role

  # Generate a clean-slate policy from usage data
  iamctl optimize --from-scratch my-role

  # Legacy aliases still work
  iamctl shrink-role-policies my-role
  iamctl policy-from-role-usage my-role

  # Quiet mode for piping into a file
  iamctl optimize -q my-role > minimal-policy.json

  # Expand wildcards and deduplicate
  iamctl optimize --strict my-role`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			quiet, _ := cmd.Flags().GetBool("quiet")
			ignoreDeny, _ := cmd.Flags().GetBool("ignore-deny")
			strict, _ := cmd.Flags().GetBool("strict")
			fromScratch, _ := cmd.Flags().GetBool("from-scratch")
			roleName := args[0]

			// Auto-detect from-scratch mode when invoked via legacy aliases
			calledAs := cmd.CalledAs()
			switch calledAs {
			case "policy-from-role-usage", "activity-policy", "policy-from-usage", "pfu":
				fromScratch = true
			}

			ctx := cmd.Context()

			var opts []func(*config.LoadOptions) error
			opts = append(opts, config.WithRetryMode(aws.RetryModeAdaptive))
			opts = append(opts, config.WithRetryMaxAttempts(10))
			if profile != "" {
				opts = append(opts, config.WithSharedConfigProfile(profile))
			}
			cfg, err := config.LoadDefaultConfig(ctx, opts...)
			if err != nil {
				return fmt.Errorf("loading AWS config: %w", err)
			}

			client := iam.NewFromConfig(cfg)

			// Get the role ARN
			roleOut, err := client.GetRole(ctx, &iam.GetRoleInput{
				RoleName: &roleName,
			})
			if err != nil {
				return fmt.Errorf("getting role %q: %w", roleName, err)
			}
			roleArn := *roleOut.Role.Arn

			if fromScratch {
				return runOptimizeFromScratch(ctx, client, roleArn, quiet)
			}
			return runOptimizeShrink(ctx, cmd, client, roleName, roleArn, quiet, ignoreDeny, strict)
		},
	}

	cmd.Flags().String("profile", "", "AWS profile to use")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress informational output, print only the policy JSON")
	cmd.Flags().Bool("from-scratch", false, "Generate a clean-slate policy from usage data instead of shrinking existing policies")
	cmd.Flags().Bool("ignore-deny", false, "Omit Deny statements from the output policy (shrink mode only)")
	cmd.Flags().Bool("strict", false, "Expand wildcard actions to exact observed actions and deduplicate equivalent statements (shrink mode only)")

	return cmd
}

// runOptimizeFromScratch generates a brand-new policy from raw usage data.
func runOptimizeFromScratch(ctx context.Context, client *iam.Client, roleArn string, quiet bool) error {
	if !quiet {
		fmt.Fprintf(os.Stderr, "Analyzing activity for role: %s\n", roleArn)
	}

	accessedActions, accessedDetails, err := fetchAccessedActions(ctx, client, roleArn)
	if err != nil {
		return err
	}

	if !quiet {
		printTrackingPeriod(accessedDetails)
	}

	statements := buildStatementsFromAccessedMap(accessedActions)

	if len(statements) == 0 {
		return fmt.Errorf("no activity found for role: %s", roleArn)
	}

	doc := policy.PolicyDocument{
		Version:   "2012-10-17",
		Statement: statements,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// runOptimizeShrink fetches attached policies and removes unused actions.
func runOptimizeShrink(ctx context.Context, cmd *cobra.Command, client *iam.Client, roleName, roleArn string, quiet, ignoreDeny, strict bool) error {
	if !quiet {
		fmt.Fprintf(os.Stderr, "Fetching policies for role: %s\n", roleArn)
	}
	policies, err := awsiam.FetchRolePolicies(ctx, client, roleName)
	if err != nil {
		return fmt.Errorf("fetching role policies: %w", err)
	}
	if len(policies) == 0 {
		return fmt.Errorf("no managed policies attached to role %q", roleName)
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "Found %d attached policy/policies\n", len(policies))
	}
	doc := mergePolicyDocs(policies)

	// Fetch service last accessed data
	accessedActions, accessedDetails, err := fetchAccessedActions(ctx, client, roleArn)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "Actions observed in use: %d\n", len(accessedActions))
		printTrackingPeriod(accessedDetails)
	}

	// Shrink the policy
	shrunk, removed := shrinkDocument(doc, accessedActions, shrinkOptions{
		ignoreDeny: ignoreDeny,
		strict:     strict,
	})

	if !quiet {
		if len(removed) > 0 {
			fmt.Fprintf(os.Stderr, "\nRemoved %d unused action(s):\n", len(removed))
			for _, a := range removed {
				fmt.Fprintf(os.Stderr, "  - %s\n", a)
			}
			fmt.Fprintln(os.Stderr)
		} else {
			fmt.Fprintln(os.Stderr, "No unused actions found — policy is already minimal.")
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(shrunk)
}

// buildStatementsFromAccessedMap creates policy statements grouped by service
// from the accessed actions map (used in from-scratch mode).
func buildStatementsFromAccessedMap(accessed map[string]string) []policy.Statement {
	// Group actions by service namespace
	byService := make(map[string][]string)
	for _, canonical := range accessed {
		parts := strings.SplitN(canonical, ":", 2)
		if len(parts) == 2 {
			byService[parts[0]] = append(byService[parts[0]], canonical)
		}
	}

	// Sort service names for deterministic output
	serviceNames := make([]string, 0, len(byService))
	for svc := range byService {
		serviceNames = append(serviceNames, svc)
	}
	sort.Strings(serviceNames)

	var statements []policy.Statement
	for _, svc := range serviceNames {
		actions := byService[svc]
		sort.Strings(actions)
		stmt := policy.Statement{
			Effect:   "Allow",
			Action:   actions,
			Resource: "*",
		}
		statements = append(statements, stmt)
	}

	return statements
}

// fetchAccessedActions retrieves ACTION_LEVEL last accessed data for an ARN
// and returns a map of lowercase "service:action" to canonical "service:Action" strings.
func fetchAccessedActions(ctx context.Context, client *iam.Client, arn string) (map[string]string, *iam.GetServiceLastAccessedDetailsOutput, error) {
	genOut, err := client.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         &arn,
		Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("generating service last accessed details: %w", err)
	}

	jobID := *genOut.JobId

	var details *iam.GetServiceLastAccessedDetailsOutput
	for {
		details, err = client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId: &jobID,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("getting service last accessed details: %w", err)
		}
		if details.JobStatus == iamtypes.JobStatusTypeCompleted {
			break
		}
		if details.JobStatus == iamtypes.JobStatusTypeFailed {
			return nil, nil, fmt.Errorf("job failed: %s", valueOrEmpty(details.Error))
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	accessed := make(map[string]string)

	// Collect all pages
	services := details.ServicesLastAccessed
	marker := details.Marker
	for details.IsTruncated {
		page, err := client.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId:  &jobID,
			Marker: marker,
		})
		if err != nil {
			break
		}
		services = append(services, page.ServicesLastAccessed...)
		marker = page.Marker
		details.IsTruncated = page.IsTruncated
	}

	for _, svc := range services {
		if svc.TotalAuthenticatedEntities == nil || *svc.TotalAuthenticatedEntities == 0 {
			continue
		}
		if svc.TrackedActionsLastAccessed == nil {
			continue
		}
		for _, action := range svc.TrackedActionsLastAccessed {
			if action.LastAccessedEntity != nil {
				canonical := fmt.Sprintf("%s:%s", *svc.ServiceNamespace, *action.ActionName)
				key := strings.ToLower(canonical)
				accessed[key] = canonical
			}
		}
	}

	return accessed, details, nil
}

type shrinkOptions struct {
	ignoreDeny bool
	strict     bool
}

// shrinkDocument removes unused Allow actions from a policy document.
// Deny statements are kept unless ignoreDeny is true.
// NotAction statements and non-Action statements are kept as-is.
// Returns the shrunk document and a list of removed actions.
func shrinkDocument(doc policy.PolicyDocument, accessed map[string]string, opts shrinkOptions) (policy.PolicyDocument, []string) {
	var kept []policy.Statement
	var removed []string

	for _, stmt := range doc.Statement {
		// Keep Deny statements unless explicitly ignored
		if strings.EqualFold(stmt.Effect, "Deny") {
			if opts.ignoreDeny {
				continue
			}
			kept = append(kept, stmt)
			continue
		}

		// Keep NotAction statements untouched
		if stmt.NotAction != nil {
			kept = append(kept, stmt)
			continue
		}

		// Skip statements without Action
		if stmt.Action == nil {
			kept = append(kept, stmt)
			continue
		}

		actions := matcher.ExtractStrings(stmt.Action)
		var surviving []string
		for _, a := range actions {
			if opts.strict {
				matches := matchedAccessedActions(a, accessed)
				if len(matches) > 0 {
					surviving = append(surviving, matches...)
				} else {
					removed = append(removed, a)
				}
				continue
			}

			if isActionAccessed(a, accessed) {
				surviving = append(surviving, a)
			} else {
				removed = append(removed, a)
			}
		}

		surviving = dedupeStrings(surviving)

		if len(surviving) == 0 {
			continue
		}

		newStmt := stmt
		if len(surviving) == 1 {
			newStmt.Action = surviving[0]
		} else {
			iface := make([]interface{}, len(surviving))
			for i, s := range surviving {
				iface[i] = s
			}
			newStmt.Action = iface
		}
		kept = append(kept, newStmt)
	}

	if opts.strict {
		kept = compactStatements(kept)
	}
	removed = dedupeStrings(removed)
	sort.Strings(removed)

	return policy.PolicyDocument{
		Version:   doc.Version,
		Statement: kept,
	}, removed
}

// isActionAccessed checks if a policy action (which may contain wildcards)
// matches any of the actually-accessed actions.
func isActionAccessed(policyAction string, accessed map[string]string) bool {
	lower := strings.ToLower(policyAction)

	if _, ok := accessed[lower]; ok {
		return true
	}

	if matcher.IsWildcardAction(policyAction) {
		re, err := matcher.IamPatternToRegex(policyAction)
		if err != nil {
			return true // keep on error, be conservative
		}
		for a := range accessed {
			if re.MatchString(a) {
				return true
			}
		}
		return false
	}

	return false
}

func matchedAccessedActions(policyAction string, accessed map[string]string) []string {
	lower := strings.ToLower(policyAction)
	if canonical, ok := accessed[lower]; ok {
		return []string{canonical}
	}

	if !matcher.IsWildcardAction(policyAction) {
		return nil
	}

	re, err := matcher.IamPatternToRegex(policyAction)
	if err != nil {
		return []string{policyAction}
	}

	var matches []string
	for lowerAction, canonical := range accessed {
		if re.MatchString(lowerAction) {
			matches = append(matches, canonical)
		}
	}

	sort.Strings(matches)
	return dedupeStrings(matches)
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func dedupeStatements(statements []policy.Statement) []policy.Statement {
	if len(statements) < 2 {
		return statements
	}

	seen := make(map[string]struct{}, len(statements))
	result := make([]policy.Statement, 0, len(statements))
	for _, stmt := range statements {
		keyBytes, err := json.Marshal(stmt)
		if err != nil {
			result = append(result, stmt)
			continue
		}
		key := string(keyBytes)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, stmt)
	}
	return result
}

func compactStatements(statements []policy.Statement) []policy.Statement {
	if len(statements) < 2 {
		return normalizeStatements(statements)
	}

	type aggregate struct {
		statement policy.Statement
		count     int
	}

	aggregates := make(map[string]*aggregate, len(statements))
	order := make([]string, 0, len(statements))

	for _, stmt := range normalizeStatements(statements) {
		key, err := statementKeyWithoutSid(stmt)
		if err != nil {
			keyBytes, marshalErr := json.Marshal(stmt)
			if marshalErr != nil {
				key = fmt.Sprintf("fallback:%d", len(order))
			} else {
				key = string(keyBytes)
			}
		}

		agg, ok := aggregates[key]
		if !ok {
			agg = &aggregate{statement: stmt}
			aggregates[key] = agg
			order = append(order, key)
		}
		agg.count++
	}

	result := make([]policy.Statement, 0, len(order))
	for _, key := range order {
		agg := aggregates[key]
		stmt := agg.statement
		if agg.count > 1 {
			stmt.Sid = ""
		}

		result = append(result, stmt)
	}

	return result
}

func normalizeStatements(statements []policy.Statement) []policy.Statement {
	result := make([]policy.Statement, 0, len(statements))
	for _, stmt := range statements {
		normalized := stmt
		if values, ok := normalizeStringValue(stmt.Action); ok {
			normalized.Action = makeStringOrSlice(values)
		}
		if values, ok := normalizeStringValue(stmt.NotAction); ok {
			normalized.NotAction = makeStringOrSlice(values)
		}
		if values, ok := normalizeStringValue(stmt.Resource); ok {
			normalized.Resource = makeStringOrSlice(values)
		}
		if values, ok := normalizeStringValue(stmt.NotResource); ok {
			normalized.NotResource = makeStringOrSlice(values)
		}
		result = append(result, normalized)
	}
	return result
}

func statementKeyWithoutSid(stmt policy.Statement) (string, error) {
	keyStmt := stmt
	keyStmt.Sid = ""
	keyBytes, err := json.Marshal(keyStmt)
	if err != nil {
		return "", err
	}
	return string(keyBytes), nil
}

func normalizeStringValue(value interface{}) ([]string, bool) {
	if value == nil {
		return nil, false
	}

	values := matcher.ExtractStrings(value)
	if len(values) == 0 {
		return nil, false
	}

	values = dedupeStrings(values)
	sort.Strings(values)
	return values, true
}

func makeStringOrSlice(values []string) interface{} {
	if len(values) == 1 {
		return values[0]
	}
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

// mergePolicyDocs merges multiple policy documents into one.
func mergePolicyDocs(policies map[string]policy.PolicyDocument) policy.PolicyDocument {
	var allStatements []policy.Statement
	for _, doc := range policies {
		allStatements = append(allStatements, doc.Statement...)
	}
	return policy.PolicyDocument{
		Version:   "2012-10-17",
		Statement: allStatements,
	}
}

func valueOrEmpty(err *iamtypes.ErrorDetails) string {
	if err == nil {
		return ""
	}
	if err.Message != nil {
		return *err.Message
	}
	return ""
}

// printTrackingPeriod prints the time range covered by the service last accessed data.
func printTrackingPeriod(details *iam.GetServiceLastAccessedDetailsOutput) {
	var oldest, newest time.Time

	for _, svc := range details.ServicesLastAccessed {
		if svc.LastAuthenticated == nil {
			continue
		}
		t := *svc.LastAuthenticated
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
		if newest.IsZero() || t.After(newest) {
			newest = t
		}
	}

	if !oldest.IsZero() {
		days := int(time.Since(oldest).Hours() / 24)
		fmt.Fprintf(os.Stderr, "Tracking period: %s to %s (~%d days)\n",
			oldest.Format("2006-01-02"), newest.Format("2006-01-02"), days)
	}
	fmt.Fprintf(os.Stderr, "Note: AWS IAM tracks action-level usage for up to 400 days\n\n")
}
