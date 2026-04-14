package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runSubprocessTest re-invokes the named test in a subprocess and returns combined output and exit code.
func runSubprocessTest(t *testing.T) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if e, ok := err.(*exec.ExitError); ok {
		exitCode = e.ExitCode()
	} else if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, string(out))
	}
	return string(out), exitCode
}

// executeCommand runs a cobra command with the given args and returns stdout, stderr, and error.
func executeCommand(root *cobra.Command, args ...string) (string, error) {
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestPbCheck_NoSource(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check")
	if err == nil {
		t.Fatal("expected error when no source is specified")
	}
}

func TestPbCheck_MultipleSources(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject", "--role", "my-role", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when multiple sources are specified")
	}
}

func TestPbCheck_PolicyFileWithRole(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--role", "my-role", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when policy file is combined with --role")
	}
}

func TestPbCheck_PolicyFileWithCfTemplate(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--cf-template", "tmpl.yaml", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when policy file is combined with --cf-template")
	}
}

func TestPbCheck_PolicyFileFlagsWithRole(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--role", "my-role", "--policy-file", "extra.json", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --policy-file is used with --role")
	}
}

func TestPbCheck_ManagedPolicyWithAction(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject", "--managed-policy", "arn:aws:iam::aws:policy/test", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --managed-policy is used with --action")
	}
}

func TestPbCheck_ResourceWithoutCf(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "policy.json", "--resource", "MyRole", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --resource is used without --cf-template")
	}
}

func TestPbCheck_ActionRequiresPb(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--action", "s3:GetObject")
	if err == nil {
		t.Fatal("expected error when --pb is not specified for action check")
	}
}

func TestPbCheck_PolicyRequiresPb(t *testing.T) {
	root := NewRootCmd("test")
	policyFile := filepath.Join("..", "testdata", "test-policy.json")
	_, err := executeCommand(root, "pb-check", policyFile)
	if err == nil {
		t.Fatal("expected error when --pb is not specified for policy check")
	}
}

func TestPbCheck_ActionMode_AllAllowed(t *testing.T) {
	// Use the simple allow PB which allows s3/ec2/iam actions
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	// Capture stdout to check output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"pb-check", "--action", "s3:GetObject", "--action", "s3:PutObject", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output == "" {
		t.Fatal("expected some output")
	}
}

func TestPbCheck_CfMode_NoTemplate(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "pb-check", "--cf-template", "nonexistent.yaml", "--pb", filepath.Join("..", "testdata", "test-pb-simple-allow.json"))
	if err == nil {
		t.Fatal("expected error for nonexistent template file")
	}
}

func TestPbCheck_LegacyAliases(t *testing.T) {
	// Verify legacy aliases are registered by checking the command can be found
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"check-action"})
	if err != nil {
		t.Fatalf("check-action alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-policy"})
	if err != nil {
		t.Fatalf("check-policy alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-role"})
	if err != nil {
		t.Fatalf("check-role alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"check-cf"})
	if err != nil {
		t.Fatalf("check-cf alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}

	cmd, _, err = root.Find([]string{"pb-check-action"})
	if err != nil {
		t.Fatalf("pb-check-action alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}
}

func TestPbCheck_PolicyMode_WithPolicyFile(t *testing.T) {
	// Create a policy that only uses actions allowed by the simple PB
	// (s3:GetObject, s3:ListBuckets, s3:PutObject, ec2:Describe*, iam:Get*, iam:List*)
	// to avoid os.Exit(1) from blocked actions
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "*"
		}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "allowed-policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"pb-check", "--pb", pbFile, tmpFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected some output from policy check")
	}
}

// --- Tests for the new "check-access" / "can" primary command name ---

func TestCheckAccess_PrimaryName(t *testing.T) {
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"check-access"})
	if err != nil {
		t.Fatalf("check-access command not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access, got %s", cmd.Name())
	}
}

func TestCheckAccess_CanAlias(t *testing.T) {
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"can"})
	if err != nil {
		t.Fatalf("can alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}
}

func TestCheckAccess_CheckAlias(t *testing.T) {
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"check"})
	if err != nil {
		t.Fatalf("check alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}
}

func TestCheckAccess_PbcAlias(t *testing.T) {
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"pbc"})
	if err != nil {
		t.Fatalf("pbc alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}
}

func TestCheckAccess_PbCheckAlias(t *testing.T) {
	root := NewRootCmd("test")
	cmd, _, err := root.Find([]string{"pb-check"})
	if err != nil {
		t.Fatalf("pb-check alias not found: %v", err)
	}
	if cmd.Name() != "check-access" {
		t.Errorf("expected check-access command, got %s", cmd.Name())
	}
}

// --- Tests for --role + --action combination validation errors ---

func TestCheckAccess_RoleActionWithCfTemplate(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--role", "my-role", "--action", "s3:GetObject", "--cf-template", "tmpl.yaml")
	if err == nil {
		t.Fatal("expected error when --cf-template is combined with --role and --action")
	}
	if !strings.Contains(err.Error(), "--cf-template cannot be combined") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAccess_RoleActionWithPolicyFile(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--role", "my-role", "--action", "s3:GetObject", "policy.json")
	if err == nil {
		t.Fatal("expected error when policy file is combined with --role and --action")
	}
	if !strings.Contains(err.Error(), "policy file argument cannot be combined") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- Tests with specific error message assertions ---

func TestCheckAccess_NoSource_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access")
	if err == nil {
		t.Fatal("expected error when no source is specified")
	}
	if !strings.Contains(err.Error(), "at least one of") {
		t.Errorf("expected 'at least one of' in error, got: %v", err)
	}
}

func TestCheckAccess_MultipleSources_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--role", "x", "--cf-template", "y")
	if err == nil {
		t.Fatal("expected error when multiple sources specified")
	}
	if !strings.Contains(err.Error(), "specify only one source") {
		t.Errorf("expected 'specify only one source' in error, got: %v", err)
	}
}

func TestCheckAccess_PolicyFileWithAction_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "policy.json", "--action", "s3:GetObject", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when policy file combined with --action")
	}
	if !strings.Contains(err.Error(), "policy file argument cannot be combined") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAccess_PolicyFileFlagsWithAction_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--action", "s3:GetObject", "--policy-file", "extra.json", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --policy-file is used with --action")
	}
	if !strings.Contains(err.Error(), "--policy-file and --managed-policy can only be used") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAccess_ResourceWithoutCf_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "policy.json", "--resource", "MyRole", "--pb", "test.json")
	if err == nil {
		t.Fatal("expected error when --resource is used without --cf-template")
	}
	if !strings.Contains(err.Error(), "--resource can only be used with --cf-template") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAccess_ActionRequiresPb_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--action", "s3:GetObject")
	if err == nil {
		t.Fatal("expected error when --pb is not specified for action check")
	}
	if !strings.Contains(err.Error(), "--pb is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAccess_PolicyRequiresPb_ErrorMessage(t *testing.T) {
	root := NewRootCmd("test")
	pf := filepath.Join("..", "testdata", "test-policy.json")
	_, err := executeCommand(root, "check-access", pf)
	if err == nil {
		t.Fatal("expected error when --pb is not specified for policy check")
	}
	if !strings.Contains(err.Error(), "--pb is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- Action mode: denied action ---

func TestCheckAccess_ActionMode_Denied(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
		root := NewRootCmd("test")
		root.SetArgs([]string{"check-access", "--action", "lambda:InvokeFunction", "--pb", pbFile})
		root.Execute()
		return
	}
	output, exitCode := runSubprocessTest(t)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "DENIED") {
		t.Errorf("expected DENIED in output, got: %s", output)
	}
}

// --- Action mode with wildcard action ---

func TestCheckAccess_ActionMode_Wildcard(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--action", "ec2:Describe*", "--pb", pbFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var errBuf bytes.Buffer
	errBuf.ReadFrom(rErr)

	if !strings.Contains(errBuf.String(), "wildcard") {
		t.Errorf("expected wildcard warning in stderr, got: %s", errBuf.String())
	}
	if !strings.Contains(buf.String(), "ec2:Describe*") {
		t.Errorf("expected action in output, got: %s", buf.String())
	}
}

// --- Policy mode: JSON output ---

func TestCheckAccess_PolicyMode_JSONOutput(t *testing.T) {
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject"],
			"Resource": "*"
		}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, "--output", "json", tmpFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, `"evaluation_method"`) {
		t.Errorf("expected JSON with evaluation_method, got: %s", output)
	}
	if !strings.Contains(output, `"allowed"`) {
		t.Errorf("expected JSON with allowed field, got: %s", output)
	}
	if !strings.Contains(output, `"summary"`) {
		t.Errorf("expected JSON with summary field, got: %s", output)
	}
}

// --- Policy mode: table output ---

func TestCheckAccess_PolicyMode_TableOutput(t *testing.T) {
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject"],
			"Resource": "*"
		}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, "--output", "table", tmpFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "ACTION") || !strings.Contains(output, "STATUS") {
		t.Errorf("expected table header with ACTION and STATUS, got: %s", output)
	}
	if !strings.Contains(output, "ALLOWED") {
		t.Errorf("expected ALLOWED in table output, got: %s", output)
	}
}

// --- Policy mode: blocked actions ---

func TestCheckAccess_PolicyMode_BlockedActions(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		// test-policy.json contains ec2:CreateTags, ec2:RunInstances, iam:CreateRole which are not in the simple PB
		pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
		policyFile := filepath.Join("..", "testdata", "test-policy.json")
		root := NewRootCmd("test")
		root.SetArgs([]string{"check-access", "--pb", pbFile, policyFile})
		root.Execute()
		return
	}
	output, exitCode := runSubprocessTest(t)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "Blocked") {
		t.Errorf("expected Blocked in output, got: %s", output)
	}
	if !strings.Contains(output, "ec2:CreateTags") {
		t.Errorf("expected ec2:CreateTags in output, got: %s", output)
	}
}

// --- Policy mode: blocked actions JSON output ---

func TestCheckAccess_PolicyMode_BlockedJSON(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
		policyFile := filepath.Join("..", "testdata", "test-policy.json")
		root := NewRootCmd("test")
		root.SetArgs([]string{"check-access", "--pb", pbFile, "--output", "json", policyFile})
		root.Execute()
		return
	}
	output, exitCode := runSubprocessTest(t)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, `"blocked"`) {
		t.Errorf("expected blocked field in JSON, got: %s", output)
	}
	if !strings.Contains(output, "ec2:CreateTags") {
		t.Errorf("expected ec2:CreateTags in JSON output, got: %s", output)
	}
}

// --- Policy mode: deny + NotAction statements ---

func TestCheckAccess_PolicyMode_DenyAndNotAction(t *testing.T) {
	// Use inline data with only PB-allowed actions to avoid os.Exit(1)
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
			{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
			{"Effect": "Deny", "Action": ["s3:PutObject"], "Resource": "*"}
		]
	}`
	tmpFile := filepath.Join(t.TempDir(), "notaction-policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, tmpFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Skipped") {
		t.Errorf("expected Skipped (deny) section in output, got: %s", output)
	}
	if !strings.Contains(output, "NotAction") {
		t.Errorf("expected NotAction section in output, got: %s", output)
	}
}

// --- Policy mode: conditions and NotResource warnings ---

func TestCheckAccess_PolicyMode_ConditionsWarnings(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	policyFile := filepath.Join("..", "testdata", "test-conditions-policy.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, policyFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var errBuf bytes.Buffer
	errBuf.ReadFrom(rErr)
	stderrOutput := errBuf.String()

	// Conditions and NotResource should trigger warnings on stderr
	if !strings.Contains(stderrOutput, "Condition") {
		t.Errorf("expected Condition warning in stderr, got: %s", stderrOutput)
	}
	if !strings.Contains(stderrOutput, "NotResource") {
		t.Errorf("expected NotResource warning in stderr, got: %s", stderrOutput)
	}
	if buf.Len() == 0 {
		t.Error("expected some stdout output")
	}
}

// --- Policy mode: wildcard actions ---

func TestCheckAccess_PolicyMode_WildcardActions(t *testing.T) {
	// Use inline data with only PB-matching wildcards to avoid os.Exit(1)
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["ec2:Describe*", "iam:Get*"],
			"Resource": "*"
		}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "wildcard-policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, tmpFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var errBuf bytes.Buffer
	errBuf.ReadFrom(rErr)

	if !strings.Contains(errBuf.String(), "wildcard") {
		t.Errorf("expected wildcard warning in stderr, got: %s", errBuf.String())
	}
	if buf.Len() == 0 {
		t.Error("expected some stdout output")
	}
}

// --- Policy mode: extra --policy-file flag ---

func TestCheckAccess_PolicyMode_WithExtraPolicyFile(t *testing.T) {
	mainPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject"],
			"Resource": "*"
		}]
	}`
	extraPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:PutObject"],
			"Resource": "*"
		}]
	}`
	dir := t.TempDir()
	mainFile := filepath.Join(dir, "main.json")
	extraFile := filepath.Join(dir, "extra.json")
	if err := os.WriteFile(mainFile, []byte(mainPolicy), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extraFile, []byte(extraPolicy), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, "--policy-file", extraFile, mainFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both s3:GetObject and s3:PutObject should be in the output
	if !strings.Contains(output, "s3:GetObject") {
		t.Errorf("expected s3:GetObject from main policy in output, got: %s", output)
	}
	if !strings.Contains(output, "s3:PutObject") {
		t.Errorf("expected s3:PutObject from extra policy in output, got: %s", output)
	}
}

// --- Policy mode: no actions found ---

func TestCheckAccess_PolicyMode_NoActions(t *testing.T) {
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": []
	}`
	tmpFile := filepath.Join(t.TempDir(), "empty-policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--pb", pbFile, tmpFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No actions found") {
		t.Errorf("expected 'No actions found' message, got: %s", buf.String())
	}
}

// --- Policy mode: invalid policy JSON ---

func TestCheckAccess_PolicyMode_InvalidJSON(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmpFile, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--pb", pbFile, tmpFile)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing policy JSON") {
		t.Errorf("expected 'parsing policy JSON' in error, got: %v", err)
	}
}

// --- Policy mode: nonexistent policy file ---

func TestCheckAccess_PolicyMode_NonexistentFile(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--pb", pbFile, "/nonexistent/policy.json")
	if err == nil {
		t.Fatal("expected error for nonexistent policy file")
	}
	if !strings.Contains(err.Error(), "reading policy file") {
		t.Errorf("expected 'reading policy file' in error, got: %v", err)
	}
}

// --- Policy mode: invalid PB file ---

func TestCheckAccess_PolicyMode_InvalidPb(t *testing.T) {
	policyContent := `{
		"Version": "2012-10-17",
		"Statement": [{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]
	}`
	tmpFile := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--pb", "/nonexistent/pb.json", tmpFile)
	if err == nil {
		t.Fatal("expected error for invalid pb file")
	}
	if !strings.Contains(err.Error(), "loading permission boundary") {
		t.Errorf("expected 'loading permission boundary' in error, got: %v", err)
	}
}

// writeSafeCfTemplate creates a temp CF template with only PB-allowed actions.
func writeSafeCfTemplate(t *testing.T) string {
	t.Helper()
	cf := `AWSTemplateFormatVersion: 2010-09-09
Resources:
  AllowedPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
            Resource: "*"
  OtherPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: OtherPolicy
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - ec2:DescribeInstances
            Resource: "*"
      Roles:
        - SomeRole
`
	f := filepath.Join(t.TempDir(), "cf.yaml")
	if err := os.WriteFile(f, []byte(cf), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// --- CF mode: standalone policy resource ---

func TestCheckAccess_CfMode_StandalonePolicy(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	cfFile := writeSafeCfTemplate(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--cf-template", cfFile, "--pb", pbFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "s3:GetObject") {
		t.Errorf("expected s3:GetObject in CF output, got: %s", output)
	}
	if !strings.Contains(output, "ec2:DescribeInstances") {
		t.Errorf("expected ec2:DescribeInstances in CF output, got: %s", output)
	}
}

// --- CF mode: filter by resource ---

func TestCheckAccess_CfMode_FilterResource(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	cfFile := writeSafeCfTemplate(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--cf-template", cfFile, "--pb", pbFile, "--resource", "AllowedPolicy"})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "s3:GetObject") {
		t.Errorf("expected s3:GetObject for AllowedPolicy, got: %s", output)
	}
	// Should NOT contain ec2 actions from OtherPolicy
	if strings.Contains(output, "ec2:DescribeInstances") {
		t.Error("did not expect OtherPolicy actions when filtering to AllowedPolicy")
	}
}

// --- CF mode: resource not found ---

func TestCheckAccess_CfMode_ResourceNotFound(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	cfFile := filepath.Join("..", "testdata", "test-cf-policies.yaml")

	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--cf-template", cfFile, "--pb", pbFile, "--resource", "NonExistent")
	if err == nil {
		t.Fatal("expected error for nonexistent resource")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

// --- CF mode: JSON output ---

func TestCheckAccess_CfMode_JSONOutput(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	cfFile := writeSafeCfTemplate(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--cf-template", cfFile, "--pb", pbFile, "--resource", "AllowedPolicy", "--output", "json"})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, `"resource"`) {
		t.Errorf("expected JSON with resource field, got: %s", output)
	}
	if !strings.Contains(output, `"evaluation_method"`) {
		t.Errorf("expected JSON with evaluation_method field, got: %s", output)
	}
}

// --- CF mode: SARIF output ---

func TestCheckAccess_CfMode_SARIFOutput(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	cfFile := writeSafeCfTemplate(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--cf-template", cfFile, "--pb", pbFile, "--output", "sarif"})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, `"$schema"`) {
		t.Errorf("expected SARIF $schema field, got: %s", output)
	}
	if !strings.Contains(output, `"version": "2.1.0"`) {
		t.Errorf("expected SARIF version 2.1.0, got: %s", output)
	}
	if !strings.Contains(output, `"results"`) {
		t.Errorf("expected SARIF results array, got: %s", output)
	}
}

// --- CF mode: standalone policy without pb ---

func TestCheckAccess_CfMode_PolicyRequiresPb(t *testing.T) {
	cfFile := filepath.Join("..", "testdata", "test-cf-policies.yaml")
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "--cf-template", cfFile, "--resource", "MyManagedPolicy")
	if err == nil {
		t.Fatal("expected error when --pb not provided for standalone CF policy")
	}
	if !strings.Contains(err.Error(), "requires --pb") {
		t.Errorf("expected 'requires --pb' in error, got: %v", err)
	}
}

// --- Action mode: using primary "check-access" name ---

func TestCheckAccess_ActionMode_PrimaryName(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--action", "s3:GetObject", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ALLOWED") && !strings.Contains(buf.String(), "matches:") {
		t.Errorf("expected ALLOWED or matches: in output, got: %s", buf.String())
	}
}

// --- Action mode: using "can" alias ---

func TestCheckAccess_ActionMode_CanAlias(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"can", "--action", "s3:GetObject", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "ALLOWED") && !strings.Contains(buf.String(), "matches:") {
		t.Errorf("expected ALLOWED or matches: in output, got: %s", buf.String())
	}
}

// --- Action mode: verify matching pattern is shown ---

func TestCheckAccess_ActionMode_ShowsMatchingPattern(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--action", "ec2:DescribeInstances", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "matches:") {
		t.Errorf("expected 'matches:' showing the matching rule, got: %s", output)
	}
	if !strings.Contains(output, "ec2:Describe*") {
		t.Errorf("expected 'ec2:Describe*' pattern in output, got: %s", output)
	}
}

// --- Legacy alias edge cases ---

func TestCheckAccess_LegacyCheckActionPositionalArgs(t *testing.T) {
	// When invoked as "check-action", positional args should be treated as actions
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-action", "s3:GetObject")
	// Should fail with --pb required, NOT with "at least one of" (meaning the action was recognized)
	if err == nil {
		t.Fatal("expected error (--pb required)")
	}
	if !strings.Contains(err.Error(), "--pb is required") {
		t.Errorf("expected --pb required error for legacy alias, got: %v", err)
	}
}

func TestCheckAccess_LegacyCheckRolePositionalArg(t *testing.T) {
	// When invoked as "check-role", first positional arg should be treated as role name
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-role", "my-role")
	// Should try to resolve role (fail with AWS error or similar), NOT with "at least one of"
	if err == nil {
		t.Fatal("expected error (AWS/role resolution)")
	}
	// Should NOT be a usage validation error
	if strings.Contains(err.Error(), "at least one of") {
		t.Errorf("legacy check-role alias should treat positional arg as role name, got: %v", err)
	}
}

func TestCheckAccess_LegacyCfPositionalArg(t *testing.T) {
	// When invoked as "check-cf", first positional arg should be treated as cf-template
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-cf", "nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error (file not found)")
	}
	// Should NOT be a usage validation error
	if strings.Contains(err.Error(), "at least one of") {
		t.Errorf("legacy check-cf alias should treat positional arg as template, got: %v", err)
	}
}

// --- SARIF output requires --cf-template ---

func TestCheckAccess_SarifWithoutCf(t *testing.T) {
	root := NewRootCmd("test")
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")
	policyContent := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	tmpFile := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(tmpFile, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root.SetArgs([]string{"check-access", "--pb", pbFile, "--output", "sarif", tmpFile})
	_ = root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// sarif is only meant for --cf-template; with policy file it should still produce output
	// (or handle gracefully)
	_ = buf.String()
}

// --- Multiple --action flags ---

func TestCheckAccess_MultipleActions_AllAllowed(t *testing.T) {
	pbFile := filepath.Join("..", "testdata", "test-pb-simple-allow.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	oldStderr := os.Stderr
	_, wErr, _ := os.Pipe()
	os.Stderr = wErr

	root := NewRootCmd("test")
	root.SetArgs([]string{"check-access", "--action", "s3:GetObject", "--action", "s3:PutObject", "--action", "s3:ListBuckets", "--pb", pbFile})
	err := root.Execute()

	w.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "s3:GetObject") {
		t.Errorf("expected s3:GetObject in output, got: %s", output)
	}
}

// --- Stdin as "-" for policy file ---

func TestCheckAccess_StdinDashWithoutPb(t *testing.T) {
	root := NewRootCmd("test")
	_, err := executeCommand(root, "check-access", "-")
	if err == nil {
		t.Fatal("expected error when --pb not specified")
	}
	if !strings.Contains(err.Error(), "--pb is required") {
		t.Errorf("expected --pb required, got: %v", err)
	}
}
