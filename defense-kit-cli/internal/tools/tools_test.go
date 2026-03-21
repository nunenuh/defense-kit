package tools

import (
	"testing"
)

// ---------------------------------------------------------------------------
// ToolDef field tests
// ---------------------------------------------------------------------------

func TestToolDef_Fields(t *testing.T) {
	td := ToolDef{
		Name:       "lynis",
		Binary:     "lynis",
		Purpose:    "System auditing tool",
		Category:   "system",
		MinVersion: "3.0",
		VersionCmd: []string{"lynis", "--version"},
		VersionRe:  `(\d+\.\d+\.\d+)`,
	}

	if td.Name != "lynis" {
		t.Errorf("expected Name 'lynis', got %q", td.Name)
	}
	if td.Binary != "lynis" {
		t.Errorf("expected Binary 'lynis', got %q", td.Binary)
	}
	if td.Purpose != "System auditing tool" {
		t.Errorf("unexpected Purpose: %q", td.Purpose)
	}
	if td.Category != "system" {
		t.Errorf("unexpected Category: %q", td.Category)
	}
	if td.MinVersion != "3.0" {
		t.Errorf("unexpected MinVersion: %q", td.MinVersion)
	}
	if len(td.VersionCmd) != 2 {
		t.Errorf("expected 2 VersionCmd args, got %d", len(td.VersionCmd))
	}
	if td.VersionRe == "" {
		t.Error("VersionRe must not be empty")
	}
}

// ---------------------------------------------------------------------------
// ToolRegistry Add / Get / All tests
// ---------------------------------------------------------------------------

func TestNewToolRegistry_IsEmpty(t *testing.T) {
	r := NewToolRegistry()
	if got := r.All(); len(got) != 0 {
		t.Fatalf("expected empty registry, got %d tools", len(got))
	}
}

func TestAdd_And_Get(t *testing.T) {
	r := NewToolRegistry()
	td := ToolDef{Name: "trivy", Binary: "trivy", Category: "dependencies"}
	r.Add(td)

	got, ok := r.Get("trivy")
	if !ok {
		t.Fatal("expected to find 'trivy'")
	}
	if got.Name != "trivy" {
		t.Errorf("unexpected name: %q", got.Name)
	}
}

func TestGet_NotFound(t *testing.T) {
	r := NewToolRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected Get to return false for unknown tool")
	}
}

func TestAll_InsertionOrder(t *testing.T) {
	r := NewToolRegistry()
	names := []string{"alpha", "beta", "gamma"}
	for _, n := range names {
		r.Add(ToolDef{Name: n, Binary: n})
	}

	all := r.All()
	if len(all) != len(names) {
		t.Fatalf("expected %d tools, got %d", len(names), len(all))
	}
	for i, td := range all {
		if td.Name != names[i] {
			t.Errorf("position %d: expected %q, got %q", i, names[i], td.Name)
		}
	}
}

func TestAll_ReturnsCopy(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "tool1", Binary: "tool1"})

	all := r.All()
	all[0] = ToolDef{Name: "mutated"}

	if r.All()[0].Name == "mutated" {
		t.Fatal("All() must return a copy; internal slice was mutated")
	}
}

// ---------------------------------------------------------------------------
// ByCategory tests
// ---------------------------------------------------------------------------

func TestByCategory_ReturnsOnlyMatchingCategory(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "rkhunter", Binary: "rkhunter", Category: "system"})
	r.Add(ToolDef{Name: "lynis", Binary: "lynis", Category: "system"})
	r.Add(ToolDef{Name: "gitleaks", Binary: "gitleaks", Category: "secrets"})

	got := r.ByCategory("system")
	if len(got) != 2 {
		t.Fatalf("expected 2 system tools, got %d", len(got))
	}
	for _, td := range got {
		if td.Category != "system" {
			t.Errorf("unexpected category %q for tool %q", td.Category, td.Name)
		}
	}
}

func TestByCategory_Nonexistent(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "t1", Binary: "t1", Category: "system"})
	got := r.ByCategory("nonexistent")
	if len(got) != 0 {
		t.Fatalf("expected 0 tools for nonexistent category, got %d", len(got))
	}
}

func TestByCategory_Empty(t *testing.T) {
	r := NewToolRegistry()
	got := r.ByCategory("system")
	if len(got) != 0 {
		t.Fatalf("expected 0 tools in empty registry, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Installed tests
// ---------------------------------------------------------------------------

func TestInstalled_FindsLS(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "ls", Binary: "ls", Category: "test"})
	r.Add(ToolDef{Name: "nonexistent_xyz_abc", Binary: "nonexistent_xyz_abc", Category: "test"})

	installed := r.Installed()
	found := false
	for _, td := range installed {
		if td.Name == "ls" {
			found = true
		}
		if td.Name == "nonexistent_xyz_abc" {
			t.Error("nonexistent_xyz_abc must not appear in Installed()")
		}
	}
	if !found {
		t.Error("expected 'ls' to be in Installed()")
	}
}

func TestInstalled_EmptyRegistry(t *testing.T) {
	r := NewToolRegistry()
	if got := r.Installed(); len(got) != 0 {
		t.Fatalf("expected 0 installed tools for empty registry, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Check / CheckAll tests
// ---------------------------------------------------------------------------

func TestCheck_InstalledTool(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{
		Name:       "ls",
		Binary:     "ls",
		Category:   "test",
		VersionCmd: []string{"ls", "--version"},
		VersionRe:  `(\d+\.\d+)`,
	})

	status := r.Check("ls")
	if !status.Installed {
		t.Error("expected 'ls' to be installed")
	}
	if status.Path == "" {
		t.Error("expected non-empty Path for installed tool")
	}
	if status.Def.Name != "ls" {
		t.Errorf("unexpected Def.Name: %q", status.Def.Name)
	}
}

func TestCheck_NotInstalledTool(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{
		Name:   "nonexistent_xyz_abc",
		Binary: "nonexistent_xyz_abc",
	})

	status := r.Check("nonexistent_xyz_abc")
	if status.Installed {
		t.Error("expected 'nonexistent_xyz_abc' to not be installed")
	}
	if status.Path != "" {
		t.Errorf("expected empty Path for uninstalled tool, got %q", status.Path)
	}
}

func TestCheck_UnknownName_NotInstalled(t *testing.T) {
	r := NewToolRegistry()
	status := r.Check("completely_unknown_tool")
	if status.Installed {
		t.Error("expected unknown tool to report not installed")
	}
}

func TestCheckAll_ReturnsStatusForEachTool(t *testing.T) {
	r := NewToolRegistry()
	r.Add(ToolDef{Name: "ls", Binary: "ls", Category: "test"})
	r.Add(ToolDef{Name: "bash", Binary: "bash", Category: "test"})
	r.Add(ToolDef{Name: "nonexistent_xyz_abc", Binary: "nonexistent_xyz_abc", Category: "test"})

	statuses := r.CheckAll()
	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}

	byName := make(map[string]ToolStatus)
	for _, s := range statuses {
		byName[s.Def.Name] = s
	}

	if !byName["ls"].Installed {
		t.Error("expected 'ls' to be installed")
	}
	if !byName["bash"].Installed {
		t.Error("expected 'bash' to be installed")
	}
	if byName["nonexistent_xyz_abc"].Installed {
		t.Error("expected 'nonexistent_xyz_abc' to not be installed")
	}
}

// ---------------------------------------------------------------------------
// DefaultToolRegistry tests
// ---------------------------------------------------------------------------

func TestDefaultToolRegistry_Has17Tools(t *testing.T) {
	r := DefaultToolRegistry()
	all := r.All()
	if len(all) != 17 {
		t.Fatalf("expected 17 tools in DefaultToolRegistry, got %d", len(all))
	}
}

func TestDefaultToolRegistry_ContainsExpectedTools(t *testing.T) {
	r := DefaultToolRegistry()
	expected := []string{
		"rkhunter", "chkrootkit", "lynis",
		"clamscan",
		"gitleaks", "trufflehog",
		"trivy", "grype",
		"hadolint", "dockle",
		"ssh-audit",
		"semgrep", "bandit",
		"nmap", "ss",
		"aide",
		"debsums",
	}

	for _, name := range expected {
		if _, ok := r.Get(name); !ok {
			t.Errorf("DefaultToolRegistry missing expected tool: %q", name)
		}
	}
}

func TestDefaultToolRegistry_CategoriesPresent(t *testing.T) {
	r := DefaultToolRegistry()
	expectedCategories := map[string]bool{
		"system":       false,
		"malware":      false,
		"secrets":      false,
		"dependencies": false,
		"containers":   false,
		"ssh":          false,
		"code":         false,
		"network":      false,
		"filesystem":   false,
		"forensics":    false,
	}

	for _, td := range r.All() {
		if _, known := expectedCategories[td.Category]; known {
			expectedCategories[td.Category] = true
		}
	}

	for cat, found := range expectedCategories {
		if !found {
			t.Errorf("expected category %q not found in DefaultToolRegistry", cat)
		}
	}
}

func TestDefaultToolRegistry_AllToolsHaveRequiredFields(t *testing.T) {
	r := DefaultToolRegistry()
	for _, td := range r.All() {
		if td.Name == "" {
			t.Error("tool has empty Name")
		}
		if td.Binary == "" {
			t.Errorf("tool %q has empty Binary", td.Name)
		}
		if td.Category == "" {
			t.Errorf("tool %q has empty Category", td.Name)
		}
		if td.Purpose == "" {
			t.Errorf("tool %q has empty Purpose", td.Name)
		}
	}
}
