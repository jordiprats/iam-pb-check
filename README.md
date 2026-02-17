# AWS IAM Permission Boundary Checker

A command-line tool for validating **AWS IAM actions** against **permission boundary policies**. Helps identify which actions in your IAM policies are allowed or blocked by your organization's permission boundaries.

## Overview

This tool allows you to:

1. **Single Action Check**: Verify if a specific AWS action is allowed by your permission boundary.
2. **Policy Validation**: Analyze all actions in an IAM policy and identify which are allowed vs blocked.

## Installation

### Build from Source

```bash
git clone https://github.com/jprats/iam-pb-check
cd iam-pb-check
go build -o iam-pb-check main.go
```

Or run directly:

```bash
go run main.go <command> [options]
```

## Usage

### Commands

#### `check-action` - Check Single Action

Verify if a specific AWS action is allowed by your permission boundary.

```bash
iam-pb-check check-action [options] <action>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (default: `pb.json`)

**Examples:**

```bash
# Check if ec2:RunInstances is allowed
iam-pb-check check-action ec2:RunInstances

# Use custom permission boundary file
iam-pb-check check-action --pb custom-pb.json karpenter:CreateNodePool

# Check Karpenter-specific actions
iam-pb-check check-action ec2:CreateFleet

# Check EKS actions
iam-pb-check check-action eks:DescribeCluster
```

**Exit Codes:**
- `0`: Action is allowed by the permission boundary
- `1`: Action is denied by the permission boundary

#### `check-policy` - Validate IAM Policy

Analyze all actions in an IAM policy and determine which are allowed or blocked by the permission boundary.

```bash
iam-pb-check check-policy [options] <policy-file>
```

**Options:**
- `--pb <file>`: Path to permission boundary file (default: `pb.json`)
- `--output <format>`: Output format - `list`, `json`, or `table` (default: `list`)

**Examples:**

```bash
# Analyze a policy with list output (default)
iam-pb-check check-policy karpenter-role.json

# JSON output for programmatic use
iam-pb-check check-policy --output json karpenter-role.json

# Table format for easy reading
iam-pb-check check-policy --output table karpenter-role.json

# Use custom permission boundary
iam-pb-check check-policy --pb ssg-pb.json node-role.json
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

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
1. Check Allow statements - if action matches, it's potentially allowed
2. Check Deny statements - if action matches, it's explicitly denied
3. Special handling for NotAction in Deny statements - denies everything EXCEPT listed patterns
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
- **Use simple formats** for quick checks against a simple allowlist of patterns

## Output Formats

### List Format (Default)

```
✅ Allowed actions:
  ec2:CreateFleet
  ec2:DescribeInstances
  ec2:DescribeSubnets
  
❌ Blocked actions (not allowed by permission boundary):
  ec2:AttachNetworkInterface
  eks:DescribeCluster
  
Summary: 28 allowed, 15 blocked
```

### JSON Format

```json
{
  "allowed": [
    "ec2:CreateFleet",
    "ec2:DescribeInstances"
  ],
  "blocked": [
    "ec2:AttachNetworkInterface",
    "eks:DescribeCluster"
  ],
  "summary": {
    "allowed": 28,
    "blocked": 15
  }
}
```

### Table Format

```
ACTION                                                       STATUS
---------------------------------------------------------------------------
ec2:CreateFleet                                              ✅ ALLOWED
ec2:DescribeInstances                                        ✅ ALLOWED
ec2:AttachNetworkInterface                                   ❌ BLOCKED
eks:DescribeCluster                                          ❌ BLOCKED

Summary: 28 allowed, 15 blocked
```

## Contributing

Contributions welcome! Please open an issue or submit a pull request.