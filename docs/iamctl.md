## iamctl

Inspect IAM and analyze permission boundaries

### Synopsis

Inspect AWS IAM roles and policies, validate access against permission boundaries, generate least-privilege policies, and more.

### Options

```
  -h, --help   help for iamctl
```

### SEE ALSO

* [iamctl check-access](iamctl_check-access.md)	 - Check whether actions, policies, roles, or CloudFormation templates are allowed
* [iamctl describe-policy](iamctl_describe-policy.md)	 - Describe a managed policy and show its JSON document
* [iamctl describe-role](iamctl_describe-role.md)	 - Describe an IAM role, including summary, managed policies, and inline policies
* [iamctl diff](iamctl_diff.md)	 - Compare IAM permissions between two sources or permission boundaries
* [iamctl merge-policies](iamctl_merge-policies.md)	 - Merge IAM policies from a role or CloudFormation template into a single unified policy JSON
* [iamctl policy-from-role-usage](iamctl_policy-from-role-usage.md)	 - Generate a least-privilege policy based on a role's actual usage (service last accessed data)
* [iamctl policy-list](iamctl_policy-list.md)	 - List IAM managed policies whose names contain a string
* [iamctl role-list](iamctl_role-list.md)	 - List IAM roles whose names contain a string
* [iamctl shrink-role-policies](iamctl_shrink-role-policies.md)	 - Generate a minimal policy for a role by removing unused actions from its attached policies

