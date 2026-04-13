package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// --- Unit tests for computeActionDiff ---

func TestComputeActionDiff_Basic(t *testing.T) {
	from := []string{"a", "b", "c"}
	to := []string{"b", "c", "d"}
	added, removed, common := computeActionDiff(from, to)

	if len(added) != 1 || added[0] != "d" {
		t.Errorf("expected added=[d], got %v", added)
	}
	if len(removed) != 1 || removed[0] != "a" {
		t.Errorf("expected removed=[a], got %v", removed)
	}
	if len(common) != 2 || common[0] != "b" || common[1] != "c" {
		t.Errorf("expected common=[b,c], got %v", common)
	}
}

func TestComputeActionDiff_Identical(t *testing.T) {
	actions := []string{"s3:GetObject", "s3:PutObject"}
	added, removed, common := computeActionDiff(actions, actions)

	if len(added) != 0 {
		t.Errorf("expected no added, got %v", added)
	}
	if len(removed) != 0 {
		t.Errorf("expected no removed, got %v", removed)
	}
	if len(common) != 2 {
		t.Errorf("expected 2 common, got %d", len(common))
	}
}

func TestComputeActionDiff_Empty(t *testing.T) {
	added, removed, common := computeActionDiff(nil, nil)
	if len(added) != 0 || len(removed) != 0 || len(common) != 0 {
		t.Errorf("expected all empty, got added=%v removed=%v common=%v", added, removed, common)
	}
}

func TestComputeActionDiff_Disjoint(t *testing.T) {
	from := []string{"a", "b"}
	to := []string{"c", "d"}
	added, removed, common := computeActionDiff(from, to)

	if len(added) != 2 {
		t.Errorf("expected 2 added, got %v", added)
	}
	if len(removed) != 2 {
		t.Errorf("expected 2 removed, got %v", removed)
	}
	if len(common) != 0 {
		t.Errorf("expected 0 common, got %v", common)
	}
}

// --- Unit tests for countTrue ---

func TestCountTrue(t *testing.T) {
	if n := countTrue(false, false, false); n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
	if n := countTrue(true, false, false); n != 1 {
		t.Errorf("expected 1, got %d", n)
	}
	if n := countTrue(true, true, true); n != 3 {
		t.Errorf("expected 3, got %d", n)
	}
}

// --- Command validation tests ---

func TestDiff_NoFlags(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff")
	if err == nil {
		t.Fatal("expected error when no flags specified")
	}
}

func TestDiff_MixedModes(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--from-policy", "a.json", "--pb", "b.json")
	if err == nil {
		t.Fatal("expected error when mixing source diff and boundary diff flags")
	}
	if !strings.Contains(err.Error(), "cannot mix") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_SourceNoFromSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--to-policy", "a.json")
	if err == nil {
		t.Fatal("expected error when no 'from' source specified")
	}
	if !strings.Contains(err.Error(), "'from' source") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_SourceNoToSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--from-policy", "a.json")
	if err == nil {
		t.Fatal("expected error when no 'to' source specified")
	}
	if !strings.Contains(err.Error(), "'to' source") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_SourceMultipleFrom(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--from-policy", "a.json", "--from-role", "roleA", "--to-policy", "b.json")
	if err == nil {
		t.Fatal("expected error when multiple 'from' sources specified")
	}
	if !strings.Contains(err.Error(), "only one 'from'") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_SourceMultipleTo(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--from-policy", "a.json", "--to-policy", "b.json", "--to-role", "roleB")
	if err == nil {
		t.Fatal("expected error when multiple 'to' sources specified")
	}
	if !strings.Contains(err.Error(), "only one 'to'") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_SourceFromResourceWithoutCf(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--from-policy", "a.json", "--from-resource", "MyRole", "--to-policy", "b.json")
	if err == nil {
		t.Fatal("expected error when --from-resource used without --from-cf")
	}
	if !strings.Contains(err.Error(), "--from-resource") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_BoundaryMissingPb(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--pb-new", "new.json", "policy.json")
	if err == nil {
		t.Fatal("expected error when --pb missing")
	}
	if !strings.Contains(err.Error(), "--pb is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_BoundaryMissingPbNew(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--pb", "old.json", "policy.json")
	if err == nil {
		t.Fatal("expected error when --pb-new missing")
	}
	if !strings.Contains(err.Error(), "--pb-new is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_BoundaryNoSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--pb", "old.json", "--pb-new", "new.json")
	if err == nil {
		t.Fatal("expected error when no policy source specified for boundary diff")
	}
}

func TestDiff_BoundaryRoleAndPolicyFile(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "diff", "--pb", "old.json", "--pb-new", "new.json", "--role", "my-role", "policy.json")
	if err == nil {
		t.Fatal("expected error when both --role and policy file specified")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiff_PbDiffAlias(t *testing.T) {
	// pb-diff alias should work
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-diff", "--pb", "old.json", "--pb-new", "new.json")
	if err == nil {
		t.Fatal("expected error (no source), but should be a valid command alias")
	}
	// Should NOT be "unknown command" — should be a source validation error
	if strings.Contains(err.Error(), "unknown command") {
		t.Errorf("pb-diff alias not recognized: %v", err)
	}
}

func TestDiff_RoleDiffAlias(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "role-diff", "--from-policy", "nonexistent.json", "--to-policy", "also-nonexistent.json")
	if err == nil {
		t.Fatal("expected error (bad files), but should be a valid command alias")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Errorf("role-diff alias not recognized: %v", err)
	}
}

// --- Subprocess tests for full diff with policy files (exits non-zero on diff) ---

func TestDiff_SourcePolicyFiles(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") != "1" {
		out, exitCode := runSubprocessTest(t)
		if exitCode != 1 {
			t.Fatalf("expected exit code 1 (differences found), got %d\noutput:\n%s", exitCode, out)
		}
		// Verify unified diff format
		if !strings.Contains(out, "--- policy:") {
			t.Errorf("missing '--- policy:' header:\n%s", out)
		}
		if !strings.Contains(out, "+++ policy:") {
			t.Errorf("missing '+++ policy:' header:\n%s", out)
		}
		if !strings.Contains(out, "Allow Actions") {
			t.Errorf("missing section header:\n%s", out)
		}
		// test-policy.json has ec2:RunInstances, test-extra-policy.json does not
		if !strings.Contains(out, "🔴 ec2:RunInstances") {
			t.Errorf("expected 🔴 ec2:RunInstances in output:\n%s", out)
		}
		// test-extra-policy.json has logs:CreateLogStream, test-policy.json does not
		if !strings.Contains(out, "🟢 logs:CreateLogStream") {
			t.Errorf("expected 🟢 logs:CreateLogStream in output:\n%s", out)
		}
		// Both have s3:GetObject
		if !strings.Contains(out, "   s3:GetObject") {
			t.Errorf("expected '   s3:GetObject' (common) in output:\n%s", out)
		}
		return
	}

	root := NewRootCmd("test")
	root.SetArgs([]string{
		"diff",
		"--from-policy", "../testdata/test-policy.json",
		"--to-policy", "../testdata/test-extra-policy.json",
	})
	_ = root.Execute()
}

func TestDiff_SourcePolicyFilesNoDiff(t *testing.T) {
	root := NewRootCmd("test")
	root.SetOut(os.Stdout)
	root.SetArgs([]string{
		"diff",
		"--from-policy", "../testdata/test-policy.json",
		"--to-policy", "../testdata/test-policy.json",
	})
	err := root.Execute()
	if err != nil {
		t.Fatalf("expected no error for identical policies, got: %v", err)
	}
}

func TestDiff_SourcePolicyFilesJSON(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") != "1" {
		out, exitCode := runSubprocessTest(t)
		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d\noutput:\n%s", exitCode, out)
		}
		if !strings.Contains(out, `"from"`) || !strings.Contains(out, `"to"`) {
			t.Errorf("expected JSON with from/to fields:\n%s", out)
		}
		if !strings.Contains(out, `"added"`) || !strings.Contains(out, `"removed"`) {
			t.Errorf("expected JSON with added/removed fields:\n%s", out)
		}
		return
	}

	root := NewRootCmd("test")
	root.SetArgs([]string{
		"diff",
		"--from-policy", "../testdata/test-policy.json",
		"--to-policy", "../testdata/test-extra-policy.json",
		"--output", "json",
	})
	_ = root.Execute()
}

func TestDiff_BoundaryPolicyFile(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
		out, err := cmd.CombinedOutput()
		exitCode := 0
		if e, ok := err.(*exec.ExitError); ok {
			exitCode = e.ExitCode()
		} else if err != nil {
			t.Fatalf("subprocess failed: %v\n%s", err, string(out))
		}

		output := string(out)

		// old boundary allows: s3:Get/List/Put, ec2:Describe*, iam:GetUser
		// new boundary allows: s3:Get/List, ec2:Describe*, ec2:RunInstances, logs:CreateLogGroup
		// policy has: s3:Get/List/Put, ec2:Describe*, ec2:RunInstances, iam:GetUser, logs:CreateLogGroup
		// lost = s3:PutObject (in old, not in new), iam:GetUser (in old, not in new)
		// gained = ec2:RunInstances (not in old, in new), logs:CreateLogGroup (not in old, in new)
		if exitCode != 1 {
			t.Fatalf("expected exit code 1 (lost access), got %d\noutput:\n%s", exitCode, output)
		}
		if !strings.Contains(output, "--- allowed by:") {
			t.Errorf("missing boundary diff header:\n%s", output)
		}
		if !strings.Contains(output, "+++ allowed by:") {
			t.Errorf("missing boundary diff header:\n%s", output)
		}
		return
	}

	root := NewRootCmd("test")
	root.SetArgs([]string{
		"diff",
		"--pb", "../testdata/test-diff-old-pb.json",
		"--pb-new", "../testdata/test-diff-new-pb.json",
		"../testdata/test-diff-policy.json",
	})
	_ = root.Execute()
}
