# iamctl — IAM Inspection and Permission-Boundary Analysis

A command-line tool for inspecting **AWS IAM roles and policies**, validating access against **permission boundary policies**, generating least-privilege policies from actual role usage, and more.

## Overview

This tool allows you to:

1. **Permission Boundary Check** (`check-access`): Unified command to check actions, policy files, IAM roles, or CloudFormation templates against a permission boundary.
2. **Describe** (`describe`): Show details for an IAM role or managed policy — auto-detects the type from the argument (ARN = policy, otherwise = role).
3. **List** (`list`): List IAM roles or managed policies whose name contains a given string. Use `--policies` to search policies instead of roles.
4. **Diff** (`diff`): Compare IAM permissions between two sources (roles, CloudFormation templates, policy files) in unified diff format, or compare a policy against two permission boundaries.
5. **Optimize** (`optimize`): Generate a minimal policy for a role based on actual usage. By default, shrinks existing attached policies; use `--from-scratch` to generate a clean-slate policy.
6. **Merge Policies** (`merge-policies`): Merge policies from a role or CloudFormation template into a single unified policy JSON.

## Installation

### Build from Source

```bash
git clone https://github.com/jprats/iamctl
cd iamctl
go build -o iamctl .
```

Or run directly:

```bash
go run . <command> [options]
```

## Usage

### Commands

#### `pb-check` — Unified Permission Boundary Check

Check actions, policy files, IAM roles, or CloudFormation templates against a permission boundary. This single command replaces the old `pb-check-action`, `pb-check-policy`, `pb-check-role`, and `pb-check-cf` commands — all old names still work as aliases.

```bash
# Check specific actions
iamctl pb-check --action <action> [--action <action>...] --pb <boundary-file>

# Check a policy file
iamctl pb-check --pb <boundary-file> [policy-file]

# Check an IAM role
iamctl pb-check --role <role-name> [--pb <boundary-file>]

# Check a CloudFormation template
iamctl pb-check --cf-template <template-file> [--pb <boundary-file>]
```

Exactly one source is required: `--action`, a policy file (positional arg), `--role`, or `--cf-template`.

**Options:**
- `--pb <file>`: Path to permission boundary file (JSON or text format), or `-` for stdin. Required for action and policy checks; optional for role checks (auto-fetches the role's own PB) and CF checks (resolves from template).
- `--action <action>`: Action(s) to check directly (can be repeated)
- `--role <name>`: AWS IAM role name to check (fetches all managed + inline policies)
- `--cf-template <file>`: Path to a CloudFormation template file
- `--output <format>`: Output format — `list`, `json`, `table`, or `sarif` (default: `list`; `sarif` only with `--cf-template`)
- `--profile <name>`: AWS profile to use
- `--policy-file <file>`: Additional policy file to include (can be repeated; only with policy-file mode)
- `--managed-policy <arn>`: ARN of a managed policy to fetch from AWS (can be repeated; only with policy-file mode)
- `--resource <logical-id>`: Logical ID of a specific IAM resource (only with `--cf-template`)

**Examples:**

```bash
# Check if specific actions are allowed
iamctl pb-check --action ec2:RunInstances --pb pb.json
iamctl pb-check --action s3:PutObject --action s3:GetObject --pb pb.json

# Analyze a local policy file
iamctl pb-check --pb pb.json policy.json
iamctl pb-check --pb pb.json --output json policy.json
iamctl pb-check --pb pb.json --output table policy.json

# Check an AWS managed policy by ARN
iamctl pb-check --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Combine a local file with managed policies
iamctl pb-check --pb pb.json --managed-policy arn:aws:iam::aws:policy/ReadOnlyAccess policy.json

# Check a role (auto-fetches its permission boundary)
iamctl pb-check --role my-role
iamctl pb-check --role my-role --pb boundary.json --output json
iamctl pb-check --role my-role --profile staging

# Check a CloudFormation template
iamctl pb-check --cf-template template.yaml
iamctl pb-check --cf-template template.yaml --resource LambdaRole
iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif

# Legacy aliases still work:
iamctl check-action --pb pb.json ec2:RunInstances
iamctl check-policy --pb pb.json policy.json
iamctl check-role my-role
iamctl check-cf template.yaml
```

**Backward Compatibility:**
When invoked as `check-action`/`pb-check-action`/`ca`, positional arguments are treated as action names. When invoked as `check-role`/`pb-check-role`/`cr`, the first positional argument is the role name. When invoked as `check-cf`/`pb-check-cf`/`ccf`, the first positional argument is the template file.

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked/denied

---

#### `describe` — Describe an IAM Role or Managed Policy

Show details for an IAM role or managed policy. The argument type is auto-detected:
- If it starts with `arn:`, it is treated as a **managed policy ARN**
- Otherwise, it is treated as a **role name**

```bash
iamctl describe [options] <role-name | policy-arn>
```

**Options:**
- `--profile <name>`: AWS profile to use
- `--output <format>`: Output format — `wide` or `json` (default: `wide`)
- `--json-policy`: Print only the policy JSON document (only with policy ARN)

**Aliases:** `desc`, `describe-role`, `dr`, `describe-policy`, `dp`

**Examples:**

```bash
# Describe a role
iamctl describe my-role
iamctl describe --output json my-role
iamctl describe --profile staging my-role

# Describe a managed policy
iamctl describe arn:aws:iam::aws:policy/ReadOnlyAccess
iamctl describe --json-policy arn:aws:iam::123456789012:policy/MyPolicy

# Legacy aliases still work
iamctl describe-role my-role
iamctl describe-policy arn:aws:iam::aws:policy/ReadOnlyAccess
```

---

#### `list` — List IAM Roles or Policies

Search IAM roles or managed policies by name substring. By default, lists roles. Use `--policies` to list managed policies instead.

```bash
iamctl list [options] <query>
iamctl list --policies [options] <query>
```

**Options:**
- `--policies`: List managed policies instead of roles
- `--output <format>`: Output format — `list` or `json` (default: `list`)
- `--profile <name>`: AWS profile to use
- `--active-within-days <n>`: Filter roles active within the last N days (roles only)
- `-1, --one-per-line`: Print only matching names, one per line
- `--scope <scope>`: Policy scope — `all`, `aws`, or `local` (policies only, default: `all`)
- `--description-contains <text>`: Keep only policies whose description contains text
- `--description-not-contains <text>`: Exclude policies whose description contains text

**Aliases:** `ls`, `role-list`, `rl`, `lr`, `search-roles`, `sr`, `policy-list`, `pl`, `lp`, `search-policies`, `sp`

**Examples:**

```bash
# List roles containing "app"
iamctl list app
iamctl list -1 app
iamctl list --active-within-days 90 app

# List policies containing "read"
iamctl list --policies read
iamctl list --policies --scope local app
iamctl list --policies --description-contains readonly read

# Legacy aliases still work
iamctl role-list app
iamctl policy-list --scope local app
```

---

#### SARIF Output (CloudFormation mode)

When using `--cf-template` with `--output sarif`, the command produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) document with one result per blocked action. Upload to GitHub Code Scanning to get inline PR annotations:

```yaml
- run: iamctl pb-check --cf-template template.yaml --pb boundary.json --output sarif > results.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF rules emitted:
| Rule | Level | Meaning |
|------|-------|---------|
| `PB001` | `error` | Action blocked by permission boundary |
| `PB002` | `warning` | Resource has wildcard actions requiring manual review |
| `PB003` | `warning` | Resource has a `NotAction` statement requiring manual review |

---

#### `diff` — Compare IAM Permissions

Compare IAM permissions between any two sources using unified diff format (like `diff -u`). Each side can be a live AWS IAM role, a CloudFormation template, or a local policy file.

Also supports the legacy boundary diff mode (`pb-diff`), comparing a policy source's actions against two permission boundaries.

**Source diff mode** — compare two IAM sources:

```bash
# Compare two live AWS roles
iamctl diff --from-role my-role-dev --to-role my-role-prod

# Compare a role to a policy file
iamctl diff --from-role my-role --to-policy desired-policy.json

# Compare a CloudFormation template to a live role
iamctl diff --from-cf template.yaml --to-role my-role
iamctl diff --from-cf template.yaml --from-resource LambdaRole --to-role my-role

# Compare two policy files
iamctl diff --from-policy old.json --to-policy new.json

# Compare two CloudFormation templates
iamctl diff --from-cf old-template.yaml --to-cf new-template.yaml
```

**Boundary diff mode** (legacy `pb-diff`):

```bash
# Compare two permission boundaries directly
iamctl diff --pb old-pb.json --pb-new new-pb.json

# Compare a policy against two permission boundaries
iamctl diff --pb old-pb.json --pb-new new-pb.json policy.json

# Same with a live role
iamctl diff --pb old-pb.json --pb-new new-pb.json --role my-role

# JSON output for CI
iamctl diff --pb old-pb.json --pb-new new-pb.json --output json policy.json

# Legacy list format
iamctl diff --pb old-pb.json --pb-new new-pb.json --output list policy.json
```

**Source flags (source diff mode):**
- `--from-role <name>` / `--to-role <name>`: AWS IAM role name
- `--from-cf <file>` / `--to-cf <file>`: CloudFormation template file
- `--from-policy <file>` / `--to-policy <file>`: Local policy JSON file (or `-` for stdin)
- `--from-resource <id>` / `--to-resource <id>`: Filter a CF template to a specific IAM resource

**Boundary flags (boundary diff mode):**
- `--pb <file>` **(required)**: Path to the old permission boundary file
- `--pb-new <file>` **(required)**: Path to the new permission boundary
- `--role <name>`: IAM role name (mutually exclusive with policy file argument)

**Common flags:**
- `--profile <name>`: AWS profile to use
- `--output <format>`: Output format — `unified` (default), `json`, or `list` (list only for boundary diff)

**Aliases:** `pb-diff`, `compare`, `cmp`, `role-diff`, `rd`

**Output example (unified format):**

```
--- role: my-role-dev
+++ role: my-role-prod
@@ Allow Actions @@
 ec2:DescribeInstances
-ec2:RunInstances
+lambda:InvokeFunction
 s3:GetObject
 s3:ListBucket
-s3:PutObject
```

**Exit Codes:**
- `0`: No differences found (source diff) or no access lost (boundary diff)
- `1`: Differences exist (source diff) or access is lost (boundary diff)

---

#### `optimize` — Generate a Minimal Policy from Actual Usage

Analyze a role's service last accessed data (at ACTION_LEVEL granularity) and generate a minimal policy containing only the actions the role has actually used.

By default (shrink mode), the command fetches attached managed policies and removes unused Allow actions while preserving Deny statements, NotAction statements, Conditions, Resources, and Sids.

Use `--from-scratch` to ignore existing policies and generate a clean-slate policy from the raw usage data.
Use `--strict` to expand wildcard actions to exact observed actions and deduplicate equivalent statements while preserving targeted resources.

AWS IAM tracks action-level usage for up to 400 days.

```bash
iamctl optimize [options] <role-name>
```

**Aliases:** `opt`, `minimize`, `shrink-role-policies`, `shrink`, `srp`, `policy-from-role-usage`, `pfu`, `activity-policy`, `policy-from-usage`

**Options:**
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)
- `--from-scratch`: Generate a clean-slate policy from usage data instead of shrinking existing policies
- `--ignore-deny`: Omit Deny statements from the output policy (shrink mode only)
- `--strict`: Expand wildcard actions to exact observed actions and deduplicate equivalent statements (shrink mode only)

**Examples:**

```bash
# Shrink a role's policies to only used actions (default)
iamctl optimize my-role

# Generate a clean-slate policy from usage data
iamctl optimize --from-scratch my-role

# Quiet mode for piping into a file
iamctl optimize -q my-role > minimal-policy.json

# Omit Deny statements from the output
iamctl optimize --ignore-deny my-role

# Expand wildcards to exact observed actions
iamctl optimize --strict my-role

# Legacy aliases still work
iamctl shrink-role-policies my-role
iamctl policy-from-role-usage my-role
```

---

#### `merge-policies` — Merge Policies

Merge IAM policies from a role or CloudFormation template into a single unified policy JSON. Useful for inspecting the combined effective policy or as input to other tools.

Sources (exactly one required):
- `--role <name>`: Fetch managed policies from a live AWS IAM role
- `--cf-template <file>`: Parse a CloudFormation template and extract policies

Deny statements, NotAction statements, and Conditions are preserved as-is by default.
Use `--strict` to deduplicate and normalize equivalent statements.

```bash
iamctl merge-policies --role <role-name> [options]
iamctl merge-policies --cf-template <template-file> [options]
```

**Options:**
- `--role <name>`: AWS IAM role name to fetch policies from
- `--cf-template <file>`: Path to a CloudFormation template file
- `--resource <logical-id>`: Logical ID of a specific IAM resource (only with `--cf-template`)
- `--profile <name>`: AWS profile to use
- `-q, --quiet`: Suppress informational output, print only the policy JSON (useful for scripts)
- `--ignore-deny`: Omit Deny statements from the output policy
- `--strict`: Compact equivalent statements by normalizing and merging actions with identical Effect/Resource/Condition

**Aliases:** `mp`, `merge-role-policies`, `mrp`, `merge-cf-policies`, `mcp`

**Examples:**

```bash
# Merge all managed policies for a role
iamctl merge-policies --role my-role

# Quiet mode for piping into a file
iamctl merge-policies --role my-role -q > merged-policy.json

# Merge from a CloudFormation template
iamctl merge-policies --cf-template template.yaml
iamctl merge-policies --cf-template template.yaml --resource LambdaRole

# Omit Deny statements
iamctl merge-policies --role my-role --ignore-deny

# Compact and deduplicate equivalent statements
iamctl merge-policies --role my-role --strict

# Use the merged output as input to pb-check
iamctl merge-policies --role my-role -q | iamctl pb-check --pb boundary.json -
```

**Exit Codes:**
- `0`: Merged policy successfully printed
- `1`: Error (role not found, no policies attached, AWS error)

## Permission Boundary Format

The tool supports multiple permission boundary formats with different evaluation behaviors:

### Full Policy Formats (Recommended)

These formats use **proper IAM evaluation logic** including Allow statements, Deny statements, and NotAction handling. Use these for accurate permission boundary validation.

#### AWS IAM GetPolicyVersion Format
Direct output from `aws iam get-policy-version`:

```json
{
  "PolicyVersion": {
    "Document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        },
        {
          "Effect": "Deny",
          "Resource": "*",
          "NotAction": [
            "ec2:Describe*",
            "ec2:CreateTags",
            "kms:Decrypt"
          ]
        }
      ]
    }
  }
}
```

#### Standard Policy Document Format
Standard IAM policy document:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Resource": "*",
      "NotAction": ["ec2:Describe*", "kms:*"]
    }
  ]
}
```

**Evaluation Logic:**
1. Check Allow statements — if action matches, it's potentially allowed
2. Check Deny statements — if action matches, it's explicitly denied
3. Special handling for NotAction in Deny statements — denies everything EXCEPT listed patterns
4. Explicit Deny always wins over Allow

### Simple Pattern Formats

These formats use **basic wildcard pattern matching only**. Use these for simple allowlists where you just want to check if an action matches any pattern.

#### Simple Pattern Array
```json
[
  "ec2:Describe*",
  "ec2:CreateTags",
  "kms:*"
]
```

#### Plain Text (one pattern per line)
```
ec2:Describe*
ec2:CreateTags
kms:*
# Comments are supported
```

**Evaluation Logic:**
- Actions matching any pattern → Allowed
- Actions not matching any pattern → Blocked
- No support for Allow/Deny/NotAction logic

### Which Format Should I Use?

- **Use full policy formats** when validating against real AWS permission boundaries.
- **Use simple formats** for quick checks against a simple allowlist of patterns.

## Output Formats

### List Format (Default)

```
🟢  Allowed actions:
    ec2:CreateFleet
    ec2:DescribeInstances
    ec2:DescribeSubnets

🔴  Blocked actions (not allowed by permission boundary):
    ec2:AttachNetworkInterface
    eks:DescribeCluster

Summary: 28 allowed, 15 blocked
```

### JSON Format

```json
{
  "evaluation_method": "Full IAM policy evaluation",
  "allowed": [
    "ec2:CreateFleet",
    "ec2:DescribeInstances"
  ],
  "blocked": [
    "ec2:AttachNetworkInterface",
    "eks:DescribeCluster"
  ],
  "skipped_deny": [],
  "not_action_statements": [],
  "warnings": [],
  "summary": {
    "allowed": 28,
    "blocked": 15,
    "skipped_deny": 0,
    "not_action_statements": 0
  }
}
```

### Table Format

```
     ACTION                                                     STATUS
---------------------------------------------------------------------------
🟢  ec2:CreateFleet                                            ALLOWED
🟢  ec2:DescribeInstances                                      ALLOWED
🔴  ec2:AttachNetworkInterface                                 BLOCKED
🔴  eks:DescribeCluster                                        BLOCKED

Summary: 28 allowed, 15 blocked, 0 skipped (denied by policy), 0 NotAction statement(s)
```

## Contributing

Contributions welcome! Please open an issue or submit a pull request.