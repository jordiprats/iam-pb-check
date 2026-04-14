## iamctl describe

Describe an IAM role or managed policy

### Synopsis

Describe an IAM role or managed policy.

The argument type is auto-detected:
  - If it starts with "arn:", it is treated as a managed policy ARN
  - Otherwise, it is treated as a role name

When invoked as describe-role/dr, the argument is always a role name.
When invoked as describe-policy/dp, the argument is always a policy ARN.

```
iamctl describe <role-name | policy-arn> [flags]
```

### Examples

```
  # Describe a role
  iamctl describe my-role
  iamctl describe --output json my-role

  # Describe a managed policy
  iamctl describe arn:aws:iam::aws:policy/ReadOnlyAccess
  iamctl describe --json-policy arn:aws:iam::123456789012:policy/MyPolicy

  # Legacy aliases
  iamctl describe-role my-role
  iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess
```

### Options

```
  -h, --help             help for describe
      --json-policy      Print only the policy JSON document (only with policy ARN)
      --output string    Output format: wide or json (default "wide")
      --profile string   AWS profile to use (defaults to current AWS_PROFILE / default)
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

