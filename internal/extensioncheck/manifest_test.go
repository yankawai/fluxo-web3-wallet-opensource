package extensioncheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestV3Shape(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "extension", "manifest.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var manifest struct {
		ManifestVersion int      `json:"manifest_version"`
		Name            string   `json:"name"`
		Version         string   `json:"version"`
		Permissions     []string `json:"permissions"`
		Action          struct {
			DefaultPopup string `json:"default_popup"`
		} `json:"action"`
		ContentSecurityPolicy struct {
			ExtensionPages string `json:"extension_pages"`
		} `json:"content_security_policy"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if manifest.ManifestVersion != 3 {
		t.Fatalf("manifest_version = %d, want 3", manifest.ManifestVersion)
	}
	if strings.TrimSpace(manifest.Name) == "" || strings.TrimSpace(manifest.Version) == "" {
		t.Fatalf("manifest name/version must be set")
	}
	if manifest.Action.DefaultPopup != "popup.html" {
		t.Fatalf("default_popup = %q, want popup.html", manifest.Action.DefaultPopup)
	}
	if !contains(manifest.Permissions, "storage") {
		t.Fatalf("storage permission is required")
	}
	csp := manifest.ContentSecurityPolicy.ExtensionPages
	if !strings.Contains(csp, "'self'") || !strings.Contains(csp, "'wasm-unsafe-eval'") {
		t.Fatalf("extension CSP must allow self-hosted WASM, got %q", csp)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repo root not found from %s", dir)
		}
		dir = parent
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
