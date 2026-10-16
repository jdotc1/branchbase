package mongodb

import (
	"strings"
	"testing"

	"github.com/branchbase/branchbase/internal/driver"
)

func TestMongoDBDriverRegistration(t *testing.T) {
	t.Parallel()

	// Test missing URI
	_, err := driver.GetDriver("mongodb", map[string]interface{}{
		"base_database": "testdb",
	})
	if err == nil {
		t.Error("expected error when uri is missing, got nil")
	}

	// Test missing BaseDatabase
	_, err = driver.GetDriver("mongodb", map[string]interface{}{
		"uri": "mongodb://localhost:27017",
	})
	if err == nil {
		t.Error("expected error when base_database is missing, got nil")
	}
}

func TestFormatDBName(t *testing.T) {
	t.Parallel()

	d := &MongoDBDriver{
		cfg: Config{
			BaseDatabase:  "app_dev",
			DefaultBranch: "main",
		},
	}

	tests := []struct {
		name     string
		branch   string
		expected string
	}{
		{
			name:     "default branch matches base database",
			branch:   "main",
			expected: "app_dev",
		},
		{
			name:     "feature branch with slash",
			branch:   "feature/auth",
			expected: "app_dev_feature_auth",
		},
		{
			name:     "hotfix branch with dashes and special characters",
			branch:   "hotfix-123.4",
			expected: "app_dev_hotfix_123_4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := d.formatDBName(tt.branch)
			if got != tt.expected {
				t.Errorf("formatDBName(%q) = %q, want %q", tt.branch, got, tt.expected)
			}
		})
	}
}

func TestMongoDBDriverName(t *testing.T) {
	t.Parallel()

	d := &MongoDBDriver{}
	if d.Name() != "mongodb" {
		t.Errorf("expected driver name 'mongodb', got %q", d.Name())
	}
}

func TestMongoDBIsBaseBranch(t *testing.T) {
	t.Parallel()

	// Default when empty defaultBranch
	dDefault := &MongoDBDriver{cfg: Config{BaseDatabase: "app", DefaultBranch: ""}}
	if !dDefault.isBaseBranch("main") {
		t.Error("expected 'main' to be base branch by default")
	}
	if !dDefault.isBaseBranch("master") {
		t.Error("expected 'master' to be base branch by default")
	}
	if !dDefault.isBaseBranch("default") {
		t.Error("expected 'default' to be base branch by default")
	}
	if dDefault.isBaseBranch("feature") {
		t.Error("expected 'feature' not to be base branch")
	}

	// Custom default branch
	dCustom := &MongoDBDriver{cfg: Config{BaseDatabase: "app", DefaultBranch: "develop"}}
	if !dCustom.isBaseBranch("develop") {
		t.Error("expected 'develop' to be base branch")
	}
	if dCustom.isBaseBranch("main") {
		t.Error("expected 'main' not to be base branch when defaultBranch is develop")
	}
}

func TestMongoDBFormatDBNameCustomDefault(t *testing.T) {
	t.Parallel()

	d := &MongoDBDriver{
		cfg: Config{
			BaseDatabase:  "app_store",
			DefaultBranch: "develop",
		},
	}

	if got := d.formatDBName("develop"); got != "app_store" {
		t.Errorf("expected base database %q for develop branch, got %q", "app_store", got)
	}
	if got := d.formatDBName("main"); got != "app_store_main" {
		t.Errorf("expected %q for main branch, got %q", "app_store_main", got)
	}
}

func TestMongoDBNilClientErrorHandling(t *testing.T) {
	t.Parallel()

	d := NewWithClient(Config{BaseDatabase: "testdb"}, nil)
	ctx := t.Context()

	if err := d.Ping(ctx); err == nil {
		t.Error("expected error from Ping with nil client, got nil")
	}
	if _, err := d.BranchExists(ctx, "feat"); err == nil {
		t.Error("expected error from BranchExists with nil client, got nil")
	}
	if err := d.CreateBranch(ctx, "main", "feat"); err == nil {
		t.Error("expected error from CreateBranch with nil client, got nil")
	}
	if err := d.DeleteBranch(ctx, "feat"); err == nil {
		t.Error("expected error from DeleteBranch with nil client, got nil")
	}
	if _, err := d.ListBranches(ctx); err == nil {
		t.Error("expected error from ListBranches with nil client, got nil")
	}
	if err := d.Close(); err != nil {
		t.Errorf("expected nil error from Close with nil client, got %v", err)
	}
}

func TestMongoDBDeleteBranchProtectedGuard(t *testing.T) {
	t.Parallel()

	d := NewWithClient(Config{BaseDatabase: "production_db", DefaultBranch: "main"}, nil)
	ctx := t.Context()

	protectedBranches := []string{"main", "master", "default"}
	for _, b := range protectedBranches {
		err := d.DeleteBranch(ctx, b)
		if err == nil {
			t.Errorf("expected error when deleting protected branch %q, got nil", b)
		}
	}
}

func TestMongoDBCreateBranchSameBranch(t *testing.T) {
	t.Parallel()

	d := NewWithClient(Config{BaseDatabase: "testdb"}, nil)
	ctx := t.Context()

	err := d.CreateBranch(ctx, "feature-x", "feature-x")
	if err == nil {
		t.Error("expected error when source and target branches are identical, got nil")
	}
}

func TestMongoDBDriverRegistrationWithHostPort(t *testing.T) {
	t.Parallel()

	drv, err := driver.GetDriver("mongodb", map[string]interface{}{
		"host":          "127.0.0.1",
		"port":          27017,
		"user":          "mongouser",
		"password":      "secret",
		"base_database": "orders",
	})
	// Connect may fail or succeed depending on live mongo, but factory parsing should succeed
	if err != nil && !strings.Contains(err.Error(), "failed to connect") && !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("unexpected error from GetDriver: %v", err)
	}
	if drv != nil {
		_ = drv.Close()
	}
}

func TestMongoDBDriverRegistrationHostWithoutAuth(t *testing.T) {
	t.Parallel()

	drv, err := driver.GetDriver("mongodb", map[string]interface{}{
		"host":          "127.0.0.1",
		"port":          0, // should default to 27017
		"base_database": "orders",
	})
	if err != nil && !strings.Contains(err.Error(), "failed to connect") && !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("unexpected error from GetDriver: %v", err)
	}
	if drv != nil {
		_ = drv.Close()
	}
}

