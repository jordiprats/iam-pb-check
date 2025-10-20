# ec2-pb-check

A command-line tool for validating AWS IAM actions against permission boundary patterns. Helps identify which actions in your IAM policies are allowed or blocked by your organization's permission boundaries.

## Overview

This tool provides two main capabilities:

1. **Single Action Check**: Verify if a specific AWS action matches your permission boundary patterns
2. **Policy Analysis**: Extract all actions from an IAM policy and identify which are allowed vs blocked

## Installation

### Prerequisites

- Go 1.16 or later

### Build from Source

```bash
git clone https://github.com/jprats/ec2-pb-check
cd ec2-pb-check
go build -o ec2-pb-check main.go
```

Or run directly:

```bash
go run main.go <command> [options]
```

## Usage

### Commands

#### `ec2-pb-check` - Check Single Action

Verify if a specific AWS action matches your permission boundary patterns.

```bash
ec2-pb-check pb-check [options] <action>
```

**Options:**
- `-pb <file>`: Path to permission boundary file (default: `pb.json`)

**Examples:**

```bash
# Check if ec2:RunInstances is allowed
ec2-pb-check pb-check ec2:RunInstances

# Use custom permission boundary file
ec2-pb-check pb-check -pb custom-pb.json karpenter:CreateNodePool

# Check Karpenter-specific actions
ec2-pb-check pb-check ec2:CreateFleet
```

**Exit Codes:**
- `0`: Action matches at least one pattern (allowed)
- `1`: Action does not match any pattern (blocked)

#### `get-blocked-actions` - Analyze IAM Policy

Extract all actions from an IAM policy and determine which are allowed or blocked by the permission boundary.

```bash
ec2-pb-check get-blocked-actions [options] <policy-file>
```

**Options:**
- `-pb <file>`: Path to permission boundary file (default: `pb.json`)
- `-format <format>`: Output format - `list`, `json`, or `table` (default: `list`)

**Examples:**

```bash
# Analyze a policy with list output (default)
ec2-pb-check get-blocked-actions karpenter-role.json

# JSON output for programmatic use
ec2-pb-check get-blocked-actions -format json karpenter-role.json

# Table format for easy reading
ec2-pb-check get-blocked-actions -format table karpenter-role.json

# Use custom permission boundary
ec2-pb-check get-blocked-actions -pb ssg-pb.json node-role.json
```

**Exit Codes:**
- `0`: All actions are allowed
- `1`: One or more actions are blocked

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