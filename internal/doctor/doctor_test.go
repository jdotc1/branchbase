package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/branchbase/branchbase/internal/driver"
)

type doctorMockDriver struct{}

func (d *doctorMockDriver) Name() string                        { return "mockdoc" }
func (d *doctorMockDriver) Ping(ctx context.Context) error      { return nil }
func (d *doctorMockDriver) Close() error                        { return nil }
func (d *doctorMockDriver) BranchExists(ctx context.Context, branchName string) (bool, error) {
	return true, nil
}
func (d *doctorMockDriver) CreateBranch(ctx context.Context, sourceBranch, targetBranch string) error {
	return nil
}
func (d *doctorMockDriver) DeleteBranch(ctx context.Context, branchName string) error {
	return nil
}
func (d *doctorMockDriver) ListBranches(ctx context.Context) ([]driver.BranchInfo, error) {
	return nil, nil
}

func init() {
	driver.Register("mockdoc", func(params map[string]interface{}) (driver.Driver, error) {
		return &doctorMockDriver{}, nil
	})
}

func TestDoctorRun(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	_ = os.MkdirAll(gitDir, 0755)
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)

	cfgPath := filepath.Join(tempDir, ".branchbase.json")
	cfgContent := `{
		"driver": "mockdoc",
		"connection": {
			"host": "127.0.0.1",
			"port": 5433,
			"base_database": "myapp_dev"
		},
		"proxy": {
			"listen_port": 64321,
			"default_branch": "main"
		}
	}`
	_ = os.WriteFile(cfgPath, []byte(cfgContent), 0644)

	ctx := context.Background()
	report := Run(ctx, tempDir, cfgPath)

	if len(report.Checks) == 0 {
		t.Fatalf("expected checks in doctor report, got 0")
	}

	formatted := FormatReport(report)
	if !strings.Contains(formatted, "BranchBase Doctor") {
		t.Errorf("expected formatted report to contain header, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "Git Repository") {
		t.Errorf("expected Git Repository check, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "Config") {
		t.Errorf("expected Config check, got:\n%s", formatted)
	}
}

type failingMockDriver struct {
	pingErr error
}

func (d *failingMockDriver) Name() string                        { return "failingdoc" }
func (d *failingMockDriver) Ping(ctx context.Context) error      { return d.pingErr }
func (d *failingMockDriver) Close() error                        { return nil }
func (d *failingMockDriver) BranchExists(ctx context.Context, branchName string) (bool, error) {
	return false, nil
}
func (d *failingMockDriver) CreateBranch(ctx context.Context, sourceBranch, targetBranch string) error {
	return nil
}
func (d *failingMockDriver) DeleteBranch(ctx context.Context, branchName string) error {
	return nil
}
func (d *failingMockDriver) ListBranches(ctx context.Context) ([]driver.BranchInfo, error) {
	return nil, nil
}

func init() {
	driver.Register("failingdoc", func(params map[string]interface{}) (driver.Driver, error) {
		return &failingMockDriver{pingErr: context.DeadlineExceeded}, nil
	})
}

func TestDoctorRun_FailureModes(t *testing.T) {
	t.Run("non-git repository", func(t *testing.T) {
		emptyDir := t.TempDir()
		report := Run(context.Background(), emptyDir, "")
		if report.AllPassed {
			t.Error("expected doctor to fail on non-git repository, but passed")
		}
		var foundGitFail bool
		for _, c := range report.Checks {
			if c.Name == "Git Repository" && !c.Passed {
				foundGitFail = true
				break
			}
		}
		if !foundGitFail {
			t.Error("expected failed 'Git Repository' check")
		}
	})

	t.Run("missing configuration file", func(t *testing.T) {
		tempDir := t.TempDir()
		gitDir := filepath.Join(tempDir, ".git")
		_ = os.MkdirAll(gitDir, 0755)
		_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)

		missingCfg := filepath.Join(tempDir, "missing.json")
		report := Run(context.Background(), tempDir, missingCfg)
		if report.AllPassed {
			t.Error("expected doctor to fail on missing config, but passed")
		}
		var foundConfigFail bool
		for _, c := range report.Checks {
			if c.Name == "Config" && !c.Passed {
				foundConfigFail = true
				break
			}
		}
		if !foundConfigFail {
			t.Error("expected failed 'Config' check")
		}
	})

	t.Run("unreachable driver", func(t *testing.T) {
		tempDir := t.TempDir()
		gitDir := filepath.Join(tempDir, ".git")
		_ = os.MkdirAll(gitDir, 0755)
		_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)

		cfgPath := filepath.Join(tempDir, ".branchbase.json")
		cfgContent := `{
			"driver": "failingdoc",
			"connection": {
				"host": "127.0.0.1",
				"port": 9999,
				"base_database": "test_db"
			},
			"proxy": {
				"listen_port": 64322,
				"default_branch": "main"
			}
		}`
		_ = os.WriteFile(cfgPath, []byte(cfgContent), 0644)

		report := Run(context.Background(), tempDir, cfgPath)
		if report.AllPassed {
			t.Error("expected doctor to fail with unreachable driver, but passed")
		}
		var foundDbFail bool
		for _, c := range report.Checks {
			if c.Name == "Database Backend" && !c.Passed {
				foundDbFail = true
				break
			}
		}
		if !foundDbFail {
			t.Error("expected failed 'Database Backend' check")
		}
	})

	t.Run("proxy port already in use", func(t *testing.T) {
		// Listen on an ephemeral port
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on test port: %v", err)
		}
		defer func() { _ = l.Close() }()

		busyPort := l.Addr().(*net.TCPAddr).Port

		tempDir := t.TempDir()
		gitDir := filepath.Join(tempDir, ".git")
		_ = os.MkdirAll(gitDir, 0755)
		_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)

		cfgPath := filepath.Join(tempDir, ".branchbase.json")
		cfgContent := fmt.Sprintf(`{
			"driver": "mockdoc",
			"connection": {
				"host": "127.0.0.1",
				"port": 5433,
				"base_database": "myapp_dev"
			},
			"proxy": {
				"listen_port": %d,
				"default_branch": "main"
			}
		}`, busyPort)
		_ = os.WriteFile(cfgPath, []byte(cfgContent), 0644)

		report := Run(context.Background(), tempDir, cfgPath)
		if report.AllPassed {
			t.Error("expected doctor to fail when port is in use, but passed")
		}
		var foundPortFail bool
		for _, c := range report.Checks {
			if c.Name == "Proxy Port" && !c.Passed {
				foundPortFail = true
				break
			}
		}
		if !foundPortFail {
			t.Error("expected failed 'Proxy Port' check")
		}

		formatted := FormatReport(report)
		if !strings.Contains(formatted, "[✖]") {
			t.Errorf("expected [✖] failure icon in report:\n%s", formatted)
		}
		if !strings.Contains(formatted, "Some checks failed") {
			t.Errorf("expected failure footer in report:\n%s", formatted)
		}
	})
}

