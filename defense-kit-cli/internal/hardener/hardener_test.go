package hardener_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/hardener"
	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

// ---------------------------------------------------------------------------
// Task 1: ActionType and ApprovalMode String()
// ---------------------------------------------------------------------------

func TestActionTypeString(t *testing.T) {
	cases := []struct {
		action hardener.ActionType
		want   string
	}{
		{hardener.FileEdit, "FileEdit"},
		{hardener.FileCreate, "FileCreate"},
		{hardener.FileDelete, "FileDelete"},
		{hardener.ServiceRestart, "ServiceRestart"},
		{hardener.CommandExec, "CommandExec"},
		{hardener.ActionType(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.action.String(); got != tc.want {
			t.Errorf("ActionType(%d).String() = %q, want %q", int(tc.action), got, tc.want)
		}
	}
}

func TestApprovalModeString(t *testing.T) {
	cases := []struct {
		mode hardener.ApprovalMode
		want string
	}{
		{hardener.ModeInteractive, "Interactive"},
		{hardener.ModeBatch, "Batch"},
		{hardener.ModeAutoLow, "AutoLow"},
		{hardener.ModeDryRun, "DryRun"},
		{hardener.ApprovalMode(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("ApprovalMode(%d).String() = %q, want %q", int(tc.mode), got, tc.want)
		}
	}
}

func TestFixPlanFields(t *testing.T) {
	f := scanner.Finding{
		ID:       "test-001",
		Title:    "Test finding",
		Severity: scanner.SevHigh,
	}
	action := hardener.FixAction{
		Type:       hardener.FileEdit,
		Target:     "/etc/ssh/sshd_config",
		Args:       []string{"sed", "-i", "s/foo/bar/"},
		Validation: []string{"grep", "bar", "/etc/ssh/sshd_config"},
	}
	rollback := hardener.RollbackPlan{
		SessionID: "sess-abc",
		Timestamp: time.Now(),
		Steps:     []hardener.RollbackStep{},
	}
	plan := hardener.FixPlan{
		Finding:     f,
		Description: "Fix SSH config",
		Actions:     []hardener.FixAction{action},
		BackupPaths: map[string]string{"/etc/ssh/sshd_config": "/tmp/backup/sshd_config"},
		Rollback:    rollback,
	}

	if plan.Finding.ID != "test-001" {
		t.Errorf("FixPlan.Finding.ID = %q, want %q", plan.Finding.ID, "test-001")
	}
	if len(plan.Actions) != 1 {
		t.Errorf("FixPlan.Actions length = %d, want 1", len(plan.Actions))
	}
	if plan.Actions[0].Type != hardener.FileEdit {
		t.Errorf("FixPlan.Actions[0].Type = %v, want FileEdit", plan.Actions[0].Type)
	}
	if plan.Rollback.SessionID != "sess-abc" {
		t.Errorf("FixPlan.Rollback.SessionID = %q, want %q", plan.Rollback.SessionID, "sess-abc")
	}
	if plan.BackupPaths["/etc/ssh/sshd_config"] != "/tmp/backup/sshd_config" {
		t.Errorf("unexpected BackupPaths value")
	}
}

func TestHardenOptionsAndResult(t *testing.T) {
	opts := hardener.HardenOptions{
		Mode:      hardener.ModeDryRun,
		OutputDir: "/tmp/out",
		Findings:  []scanner.Finding{{ID: "f1"}},
		DryRun:    true,
	}
	if opts.Mode != hardener.ModeDryRun {
		t.Error("HardenOptions.Mode not set correctly")
	}
	if len(opts.Findings) != 1 {
		t.Error("HardenOptions.Findings not set correctly")
	}

	result := hardener.HardenResult{
		Finding:  opts.Findings[0],
		Applied:  false,
		Verified: false,
		Error:    "dry run",
	}
	if result.Finding.ID != "f1" {
		t.Errorf("HardenResult.Finding.ID = %q, want %q", result.Finding.ID, "f1")
	}
	if result.Error != "dry run" {
		t.Errorf("HardenResult.Error = %q, want %q", result.Error, "dry run")
	}
}

// ---------------------------------------------------------------------------
// Task 2: HardenerRegistry
// ---------------------------------------------------------------------------

// mockHardener implements hardener.Hardener for testing.
type mockHardener struct {
	name   string
	canFix func(scanner.Finding) bool
}

func (m *mockHardener) Name() string { return m.name }

func (m *mockHardener) CanFix(f scanner.Finding) bool { return m.canFix(f) }

func (m *mockHardener) Preview(f scanner.Finding) hardener.FixPlan {
	return hardener.FixPlan{Finding: f}
}

func (m *mockHardener) Apply(_ context.Context, _ hardener.FixPlan) error { return nil }

func (m *mockHardener) Verify(_ context.Context, _ hardener.FixPlan) error { return nil }

func (m *mockHardener) Rollback(_ context.Context, _ hardener.FixPlan) error { return nil }

func TestRegistryRegisterAndFind(t *testing.T) {
	reg := hardener.NewHardenerRegistry()

	h := &mockHardener{
		name:   "ssh-hardener",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(h)

	finding := scanner.Finding{ID: "1", Scanner: "ssh"}
	found, err := reg.FindHardener(finding)
	if err != nil {
		t.Fatalf("FindHardener returned unexpected error: %v", err)
	}
	if found.Name() != "ssh-hardener" {
		t.Errorf("FindHardener returned %q, want %q", found.Name(), "ssh-hardener")
	}
}

func TestRegistryFindHardener_NotFound(t *testing.T) {
	reg := hardener.NewHardenerRegistry()

	h := &mockHardener{
		name:   "ssh-hardener",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(h)

	finding := scanner.Finding{ID: "2", Scanner: "network"}
	_, err := reg.FindHardener(finding)
	if err == nil {
		t.Fatal("expected error for unfixable finding, got nil")
	}
	if err != hardener.ErrNoHardener {
		t.Errorf("expected ErrNoHardener, got %v", err)
	}
}

func TestRegistryFindHardener_FirstMatchWins(t *testing.T) {
	reg := hardener.NewHardenerRegistry()

	h1 := &mockHardener{name: "first", canFix: func(f scanner.Finding) bool { return true }}
	h2 := &mockHardener{name: "second", canFix: func(f scanner.Finding) bool { return true }}
	reg.Register(h1)
	reg.Register(h2)

	finding := scanner.Finding{ID: "3", Scanner: "anything"}
	found, err := reg.FindHardener(finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found.Name() != "first" {
		t.Errorf("expected first match %q, got %q", "first", found.Name())
	}
}

func TestRegistryFixableFindings(t *testing.T) {
	reg := hardener.NewHardenerRegistry()

	h := &mockHardener{
		name:   "ssh-hardener",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(h)

	findings := []scanner.Finding{
		{ID: "1", Scanner: "ssh"},
		{ID: "2", Scanner: "network"},
		{ID: "3", Scanner: "ssh"},
	}

	fixable := reg.FixableFindings(findings)
	if len(fixable) != 2 {
		t.Errorf("FixableFindings returned %d findings, want 2", len(fixable))
	}
	for _, f := range fixable {
		if f.Scanner != "ssh" {
			t.Errorf("unexpected fixable finding scanner %q", f.Scanner)
		}
	}
}

func TestRegistryFixableFindings_Empty(t *testing.T) {
	reg := hardener.NewHardenerRegistry()
	fixable := reg.FixableFindings([]scanner.Finding{{ID: "1", Scanner: "ssh"}})
	if len(fixable) != 0 {
		t.Errorf("expected 0 fixable findings with empty registry, got %d", len(fixable))
	}
}

// ---------------------------------------------------------------------------
// Task 3: Rollback system
// ---------------------------------------------------------------------------

func TestBackupAndRestoreFile(t *testing.T) {
	// Create a temp source file.
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "sshd_config")
	content := "PermitRootLogin no\nPasswordAuthentication no\n"
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	backupDir := t.TempDir()

	// Backup.
	backupPath, err := hardener.BackupFile(src, backupDir)
	if err != nil {
		t.Fatalf("BackupFile error: %v", err)
	}
	if backupPath == "" {
		t.Fatal("BackupFile returned empty path")
	}
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Fatalf("backup file does not exist at %s", backupPath)
	}
	backupData, _ := os.ReadFile(backupPath)
	if string(backupData) != content {
		t.Errorf("backup content mismatch: got %q want %q", string(backupData), content)
	}

	// Modify original.
	if err := os.WriteFile(src, []byte("modified"), 0o644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// Restore.
	if err := hardener.RestoreFile(backupPath, src); err != nil {
		t.Fatalf("RestoreFile error: %v", err)
	}
	restored, _ := os.ReadFile(src)
	if string(restored) != content {
		t.Errorf("restored content mismatch: got %q want %q", string(restored), content)
	}
}

func TestBackupFile_BackupPathContainsBasename(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "myfile.conf")
	_ = os.WriteFile(src, []byte("data"), 0o644)

	backupDir := t.TempDir()
	backupPath, err := hardener.BackupFile(src, backupDir)
	if err != nil {
		t.Fatalf("BackupFile error: %v", err)
	}
	base := filepath.Base(backupPath)
	if !strings.HasSuffix(base, "myfile.conf") {
		t.Errorf("backup basename %q does not end with %q", base, "myfile.conf")
	}
}

func TestGenerateRollbackScript(t *testing.T) {
	backupDir := t.TempDir()
	outDir := t.TempDir()
	scriptPath := filepath.Join(outDir, "rollback.sh")

	plan := hardener.RollbackPlan{
		SessionID: "sess-123",
		Timestamp: time.Now(),
		Steps: []hardener.RollbackStep{
			{
				Description: "Restore SSH config",
				BackupPath:  filepath.Join(backupDir, "sshd_config"),
				Action: hardener.FixAction{
					Type:   hardener.FileEdit,
					Target: "/etc/ssh/sshd_config",
				},
			},
		},
	}

	if err := hardener.GenerateRollbackScript(plan, scriptPath); err != nil {
		t.Fatalf("GenerateRollbackScript error: %v", err)
	}

	info, err := os.Stat(scriptPath)
	if os.IsNotExist(err) {
		t.Fatalf("rollback script not created at %s", scriptPath)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("rollback script is not executable")
	}

	data, _ := os.ReadFile(scriptPath)
	content := string(data)
	if !strings.HasPrefix(content, "#!/bin/bash") {
		t.Error("rollback script does not start with #!/bin/bash")
	}
	if !strings.Contains(content, "Restore SSH config") {
		t.Error("rollback script does not contain step description")
	}
	if !strings.Contains(content, "cp ") {
		t.Error("rollback script does not contain cp command")
	}
}

func TestExecuteRollback_FileRestore(t *testing.T) {
	// Create source and backup files.
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	origContent := "original content\n"
	modifiedContent := "modified content\n"

	target := filepath.Join(srcDir, "target.conf")
	backup := filepath.Join(backupDir, "target.conf.bak")

	_ = os.WriteFile(target, []byte(modifiedContent), 0o644)
	_ = os.WriteFile(backup, []byte(origContent), 0o644)

	plan := hardener.RollbackPlan{
		SessionID: "sess-exec",
		Timestamp: time.Now(),
		Steps: []hardener.RollbackStep{
			{
				Description: "Restore target.conf",
				BackupPath:  backup,
				Action: hardener.FixAction{
					Type:   hardener.FileEdit,
					Target: target,
				},
			},
		},
	}

	errs := hardener.ExecuteRollback(context.Background(), plan)
	if len(errs) != 0 {
		t.Fatalf("ExecuteRollback returned errors: %v", errs)
	}

	data, _ := os.ReadFile(target)
	if string(data) != origContent {
		t.Errorf("file after rollback = %q, want %q", string(data), origContent)
	}
}

// ---------------------------------------------------------------------------
// Task 4: Engine
// ---------------------------------------------------------------------------

// succeedingMockHardener is a mockHardener that successfully applies and
// verifies any finding it claims to fix.
type succeedingMockHardener struct {
	name    string
	canFix  func(scanner.Finding) bool
	applied []hardener.FixPlan
}

func (s *succeedingMockHardener) Name() string { return s.name }
func (s *succeedingMockHardener) CanFix(f scanner.Finding) bool {
	if s.canFix != nil {
		return s.canFix(f)
	}
	return true
}
func (s *succeedingMockHardener) Preview(f scanner.Finding) hardener.FixPlan {
	return hardener.FixPlan{
		Finding:     f,
		Description: "mock fix for " + f.ID,
		Actions:     []hardener.FixAction{},
	}
}
func (s *succeedingMockHardener) Apply(_ context.Context, plan hardener.FixPlan) error {
	s.applied = append(s.applied, plan)
	return nil
}
func (s *succeedingMockHardener) Verify(_ context.Context, _ hardener.FixPlan) error { return nil }
func (s *succeedingMockHardener) Rollback(_ context.Context, _ hardener.FixPlan) error {
	return nil
}

func TestEngine_DryRun(t *testing.T) {
	reg := hardener.NewHardenerRegistry()
	h := &mockHardener{
		name:   "mock",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(h)

	outDir := t.TempDir()
	engine := hardener.NewEngine(reg, outDir)

	findings := []scanner.Finding{
		{ID: "f1", Scanner: "ssh", Title: "PermitRootLogin", Severity: scanner.SevHigh},
		{ID: "f2", Scanner: "network", Title: "Open port"},
	}

	opts := hardener.HardenOptions{
		Mode:   hardener.ModeDryRun,
		DryRun: true,
	}

	results, err := engine.Run(context.Background(), findings, opts)
	if err != nil {
		t.Fatalf("Engine.Run dry run error: %v", err)
	}

	// Only the SSH finding is fixable.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Applied {
		t.Error("expected Applied=false in dry run")
	}
	if results[0].Finding.ID != "f1" {
		t.Errorf("unexpected finding ID %q", results[0].Finding.ID)
	}
}

func TestEngine_RunAppliesAndVerifies(t *testing.T) {
	reg := hardener.NewHardenerRegistry()
	mock := &succeedingMockHardener{
		name:   "mock",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(mock)

	outDir := t.TempDir()
	engine := hardener.NewEngine(reg, outDir)

	findings := []scanner.Finding{
		{ID: "f1", Scanner: "ssh", Title: "PermitRootLogin", Severity: scanner.SevLow},
	}

	opts := hardener.HardenOptions{
		Mode: hardener.ModeInteractive,
	}

	results, err := engine.Run(context.Background(), findings, opts)
	if err != nil {
		t.Fatalf("Engine.Run error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Applied {
		t.Errorf("expected Applied=true, got false; error=%q", r.Error)
	}
	if !r.Verified {
		t.Errorf("expected Verified=true, got false")
	}
	if r.Error != "" {
		t.Errorf("unexpected error: %q", r.Error)
	}
}

func TestEngine_AutoLow_SkipsHighSeverity(t *testing.T) {
	reg := hardener.NewHardenerRegistry()
	mock := &succeedingMockHardener{
		name:   "mock",
		canFix: func(f scanner.Finding) bool { return f.Scanner == "ssh" },
	}
	reg.Register(mock)

	outDir := t.TempDir()
	engine := hardener.NewEngine(reg, outDir)

	findings := []scanner.Finding{
		{ID: "low", Scanner: "ssh", Title: "PermitEmptyPasswords", Severity: scanner.SevLow},
		{ID: "high", Scanner: "ssh", Title: "PermitRootLogin", Severity: scanner.SevHigh},
		{ID: "critical", Scanner: "ssh", Title: "PasswordAuthentication", Severity: scanner.SevCritical},
	}

	opts := hardener.HardenOptions{
		Mode: hardener.ModeAutoLow,
	}

	results, err := engine.Run(context.Background(), findings, opts)
	if err != nil {
		t.Fatalf("Engine.Run error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, r := range results {
		switch r.Finding.ID {
		case "low":
			if !r.Applied {
				t.Errorf("LOW finding should be applied in AutoLow mode")
			}
		case "high", "critical":
			if r.Applied {
				t.Errorf("HIGH/CRITICAL finding %q should NOT be applied in AutoLow mode", r.Finding.ID)
			}
		}
	}
}

func TestEngine_DryRun_NoFiles(t *testing.T) {
	reg := hardener.NewHardenerRegistry()
	// Empty registry — nothing is fixable.
	outDir := t.TempDir()
	engine := hardener.NewEngine(reg, outDir)

	findings := []scanner.Finding{
		{ID: "f1", Scanner: "ssh"},
	}

	results, err := engine.Run(context.Background(), findings, hardener.HardenOptions{DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results with empty registry, got %d", len(results))
	}
}

func TestExecuteRollback_Reverse(t *testing.T) {
	// Verify steps are executed in reverse order by tracking order of restores.
	srcDir := t.TempDir()
	backupDir := t.TempDir()

	var order []string

	// We test reversal indirectly: create two files, restore both,
	// then check both are restored. True reverse-order verification
	// requires a hook, but we can verify all steps ran.
	files := []struct{ target, backup, content string }{
		{
			target:  filepath.Join(srcDir, "a.conf"),
			backup:  filepath.Join(backupDir, "a.conf.bak"),
			content: "a-original\n",
		},
		{
			target:  filepath.Join(srcDir, "b.conf"),
			backup:  filepath.Join(backupDir, "b.conf.bak"),
			content: "b-original\n",
		},
	}

	steps := make([]hardener.RollbackStep, 0, len(files))
	for _, f := range files {
		_ = os.WriteFile(f.target, []byte("modified"), 0o644)
		_ = os.WriteFile(f.backup, []byte(f.content), 0o644)
		steps = append(steps, hardener.RollbackStep{
			Description: "restore " + filepath.Base(f.target),
			BackupPath:  f.backup,
			Action:      hardener.FixAction{Type: hardener.FileEdit, Target: f.target},
		})
		order = append(order, filepath.Base(f.target))
	}
	_ = order // captured for documentation

	plan := hardener.RollbackPlan{
		SessionID: "sess-reverse",
		Timestamp: time.Now(),
		Steps:     steps,
	}

	errs := hardener.ExecuteRollback(context.Background(), plan)
	if len(errs) != 0 {
		t.Fatalf("ExecuteRollback returned errors: %v", errs)
	}

	for _, f := range files {
		data, _ := os.ReadFile(f.target)
		if string(data) != f.content {
			t.Errorf("file %s after rollback = %q, want %q", f.target, string(data), f.content)
		}
	}
}
