## iamctl optimize

Generate a minimal policy for a role based on actual usage

### Synopsis

Analyze a role's service last accessed data (at ACTION_LEVEL granularity) and
generate a minimal policy containing only the actions the role has actually used.

By default (shrink mode), the command fetches attached managed policies and removes
unused Allow actions while preserving Deny statements, NotAction statements,
Conditions, Resources, and Sids.

Use --from-scratch to ignore existing policies and generate a clean-slate policy
from the raw usage data (all actions grouped by service, Resource: "*").

Use --ignore-deny to omit Deny statements from the output.
Use --strict to expand wildcard actions to exact observed actions and deduplicate
equivalent statements while preserving targeted resources.

```
iamctl optimize <role-name> [flags]
```

### Examples

```
  # Shrink a role's policies to only used actions (default)
  iamctl optimize my-role

  # Generate a clean-slate policy from usage data
  iamctl optimize --from-scratch my-role

  # Legacy aliases still work
  iamctl shrink-role-policies my-role
  iamctl policy-from-role-usage my-role

  # Quiet mode for piping into a file
  iamctl optimize -q my-role > minimal-policy.json

  # Expand wildcards and deduplicate
  iamctl optimize --strict my-role
```

### Options

```
      --from-scratch     Generate a clean-slate policy from usage data instead of shrinking existing policies
  -h, --help             help for optimize
      --ignore-deny      Omit Deny statements from the output policy (shrink mode only)
      --profile string   AWS profile to use
  -q, --quiet            Suppress informational output, print only the policy JSON
      --strict           Expand wildcard actions to exact observed actions and deduplicate equivalent statements (shrink mode only)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

