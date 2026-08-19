package cf_secrets

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateProvider(t *testing.T) {
	err := validateProvider("bao", ProviderConfig{Kind: "openbao", Address: "https://bao.example"})
	if err == nil {
		t.Fatal("expected error without token or k8s_role")
	}
	if err := validateProvider("bao", ProviderConfig{Kind: "openbao", Address: "https://bao.example", Token: "s.x"}); err != nil {
		t.Fatal(err)
	}
	if err := validateProvider("aws", ProviderConfig{Kind: "aws"}); err == nil {
		t.Fatal("expected region required")
	}
	if err := validateProvider("gcp", ProviderConfig{Kind: "gcp", Project: "p"}); err != nil {
		t.Fatal(err)
	}
}

func TestExtractJSONKey(t *testing.T) {
	raw := []byte(`{"webhook-secret":"abc","n":1}`)
	got, err := extractJSONKey(raw, "webhook-secret")
	if err != nil || string(got) != "abc" {
		t.Fatalf("got %q err %v", got, err)
	}
	got, err = extractJSONKey(raw, "")
	if err != nil || string(got) != string(raw) {
		t.Fatalf("whole payload: %q err %v", got, err)
	}
	if _, err := extractJSONKey(raw, "missing"); err == nil {
		t.Fatal("expected missing key")
	}
}

func TestFileDriverGet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "webhook"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	obj := []byte(`{"private-key.pem":"PEMDATA"}`)
	if err := os.WriteFile(filepath.Join(dir, "blob.json"), obj, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := newFileDriver(ProviderConfig{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.ping(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := d.get(ctx, Ref{Path: "webhook"})
	if err != nil || string(b) != "s3cret\n" {
		t.Fatalf("got %q err %v", b, err)
	}
	b, err = d.get(ctx, Ref{Path: "blob.json", Key: "private-key.pem"})
	if err != nil || string(b) != "PEMDATA" {
		t.Fatalf("json key: %q err %v", b, err)
	}
	if _, err := d.get(ctx, Ref{Path: "../etc/passwd"}); err == nil {
		t.Fatal("expected path escape reject")
	}
}

func TestVaultDriverKV(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"initialized":true}`))
	})
	mux.HandleFunc("/v1/secret/data/caerus-framework/release-train-gh-app", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.test" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"webhook-secret":  "hexsecret",
					"private-key.pem": "-----BEGIN RSA PRIVATE KEY-----\nX\n-----END RSA PRIVATE KEY-----",
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	d, err := newVaultDriver(kindOpenBao, ProviderConfig{
		Address: srv.URL,
		KVMount: "secret",
		Token:   "s.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.ping(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := d.get(ctx, Ref{Path: "caerus-framework/release-train-gh-app", Key: "webhook-secret"})
	if err != nil || string(got) != "hexsecret" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestCFSecretsFileProvider(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(WithConfig(SecretsConfig{
		Providers: map[string]ProviderConfig{
			"local": {Kind: "file", Root: dir},
		},
	}), WithLogger(discardLogger()))
	ctx := context.Background()
	if err := c.Init(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Shutdown(ctx) })
	s, err := c.GetString(ctx, "local", Ref{Path: "token"})
	if err != nil || s != "tok" {
		t.Fatalf("got %q err %v", s, err)
	}
	if _, err := c.Get(ctx, "nope", Ref{Path: "token"}); err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("unknown provider: %v", err)
	}
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	m := c.Metrics()
	if len(m) == 0 {
		t.Fatal("expected metrics")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(ioDiscard{}, nil))
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
