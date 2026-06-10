## iamctl diff

Compare IAM permissions between two sources or permission boundaries

### Synopsis

Compare IAM permissions using a unified diff format (like diff -u).

Mode 1 — Source diff: Compare actions between two IAM sources.
Each side (--from-* / --to-*) can be an AWS role, a CloudFormation template,
or a policy file.

Mode 2 — Boundary diff (legacy pb-diff): Compare a policy source's actions
against two permission boundaries to see what access would be gained or lost.

Source types for --from-* and --to-*:
  --from-role / --to-role       Live AWS IAM role
  --from-cf / --to-cf           CloudFormation template
  --from-policy / --to-policy   Local policy JSON file (or '-' for stdin)

Output uses unified diff format:
  Lines prefixed with '-' exist only in the 'from' side (removed).
  Lines prefixed with '+' exist only in the 'to' side (added).
  Lines prefixed with ' ' exist in both sides (unchanged).

```
iamctl diff [policy-file] [flags]
```

### Examples

```
  # Compare two live AWS roles
  iamctl diff --from-role my-role-dev --to-role my-role-prod
  iamctl diff --from-role my-role-dev --to-role my-role-prod --profile staging

  # Compare a role to a policy file
  iamctl diff --from-role my-role --to-policy desired-policy.json

  # Compare a CloudFormation template to a live role
  iamctl diff --from-cf template.yaml --to-role my-role
  iamctl diff --from-cf template.yaml --from-resource LambdaRole --to-role my-role

  # Compare two policy files
  iamctl diff --from-policy old.json --to-policy new.json

  # Compare two CloudFormation templates
  iamctl diff --from-cf old-template.yaml --to-cf new-template.yaml

  # Compare two permission boundaries directly
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json

  # Boundary diff (legacy pb-diff mode)
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json policy.json
  iamctl diff --pb old-boundary.json --pb-new new-boundary.json --role my-role

  # JSON output
  iamctl diff --from-role roleA --to-role roleB --output json
```

### Options

```
      --from-cf string         CloudFormation template file for the 'from' side
      --from-policy string     Policy JSON file for the 'from' side (or '-' for stdin)
      --from-resource string   Logical ID of a specific IAM resource (only with --from-cf)
      --from-role string       AWS IAM role name for the 'from' side
  -h, --help                   help for diff
      --output string          Output format: unified, json, or list (list only for boundary diff mode) (default "unified")
      --pb string              Path to the old permission boundary file (boundary diff mode)
      --pb-new string          Path to the new permission boundary (boundary diff mode)
      --profile string         AWS profile to use
      --role string            IAM role name (boundary diff mode; mutually exclusive with policy file argument)
      --to-cf string           CloudFormation template file for the 'to' side
      --to-policy string       Policy JSON file for the 'to' side (or '-' for stdin)
      --to-resource string     Logical ID of a specific IAM resource (only with --to-cf)
      --to-role string         AWS IAM role name for the 'to' side
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

