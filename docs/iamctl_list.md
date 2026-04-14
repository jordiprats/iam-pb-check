## iamctl list

List IAM roles or policies whose names contain a string

### Synopsis

Search IAM roles or managed policies by name substring.

By default, lists roles. Use --policies to list managed policies instead.

When invoked as role-list/rl/lr/sr/search-roles, lists roles.
When invoked as policy-list/pl/lp/sp/search-policies, lists policies.

```
iamctl list <query> [flags]
```

### Examples

```
  # List roles (default)
  iamctl list app
  iamctl list -1 app
  iamctl list --active-within-days 90 app

  # List policies
  iamctl list --policies read
  iamctl list --policies --scope local app
  iamctl list --policies --description-contains readonly read

  # Legacy aliases still work
  iamctl role-list app
  iamctl policy-list --scope local app
```

### Options

```
      --active-within-days int            Filter to roles active within the last N days (0 disables)
      --description-contains string       Filter policies whose description contains this string
      --description-not-contains string   Filter policies whose description does not contain this string
  -h, --help                              help for list
  -1, --one-per-line                      Print only matching names, one per line
      --output string                     Output format: list or json (default "list")
      --policies                          List managed policies instead of roles
      --profile string                    AWS profile to use (defaults to current AWS_PROFILE / default)
      --scope string                      Policy scope: all, aws, or local (only with --policies) (default "all")
```

### SEE ALSO

* [iamctl](iamctl.md)	 - Inspect IAM and analyze permission boundaries

