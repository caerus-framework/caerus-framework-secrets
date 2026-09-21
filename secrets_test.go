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

	cf_observability "github.com/caerus-framework/caerus-framework-observability"
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
	}, discardLogger())
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

func TestSanitizeKVSecretPath(t *testing.T) {
	ok, err := sanitizeKVSecretPath("caerus-framework/release-train-gh-app")
	if err != nil || ok != "caerus-framework/release-train-gh-app" {
		t.Fatalf("got %q err %v", ok, err)
	}
	for _, raw := range []string{
		"../sys/raw",
		"foo/../bar",
		"foo/./bar",
		"foo//bar",
		`foo\bar`,
		"data/caerus-framework/release-train-gh-app",
		"data",
		"",
	} {
		if _, err := sanitizeKVSecretPath(raw); err == nil {
			t.Fatalf("expected reject for %q", raw)
		}
	}
	u, err := kvReadURL("https://vault.example:8200", "secret", "app/db", "")
	if err != nil {
		t.Fatal(err)
	}
	if u != "https://vault.example:8200/v1/secret/data/app/db" {
		t.Fatalf("url = %q", u)
	}
}

func TestVaultGetRejectsTraversal(t *testing.T) {
	d, err := newVaultDriver(kindVault, ProviderConfig{
		Address: "https://vault.example:8200",
		Token:   "s.test",
	}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.get(context.Background(), Ref{Path: "../sys/policy"}); err == nil {
		t.Fatal("expected path reject")
	}
	if _, err := d.get(context.Background(), Ref{Path: "data/app/db"}); err == nil {
		t.Fatal("expected data/ prefix reject")
	}
}

func TestVaultErrorBodyNotInPublicError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/secret/data/app/db", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied: leaked-fixture-secret"]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	d, err := newVaultDriver(kindOpenBao, ProviderConfig{
		Address: srv.URL,
		Token:   "s.test",
	}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.get(context.Background(), Ref{Path: "app/db"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "leaked-fixture-secret") {
		t.Fatalf("public error leaked body: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("want status in error, got %v", err)
	}
}

func TestValidateRequiresHTTPS(t *testing.T) {
	p := ProviderConfig{Kind: "vault", Address: "http://vault.example:8200", Token: "s.x"}
	if err := validateProvider("v", p); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http without allow_insecure_http: %v", err)
	}
	p.AllowInsecureHTTP = boolPtr(true)
	if err := validateProvider("v", p); err != nil {
		t.Fatal(err)
	}
	p.Address = "https://vault.example:8200"
	p.AllowInsecureHTTP = nil
	if err := validateProvider("v", p); err != nil {
		t.Fatal(err)
	}
	p.Address = "https://vault.example:8200/v1"
	if err := validateProvider("v", p); err == nil {
		t.Fatal("address with API path should fail")
	}
}

func TestValidateMountCharset(t *testing.T) {
	p := ProviderConfig{Kind: "vault", Address: "https://vault.example:8200", Token: "s.x", KVMount: "secret/../sys"}
	if err := validateProvider("v", p); err == nil || !strings.Contains(err.Error(), "kv_mount") {
		t.Fatalf("bad kv_mount: %v", err)
	}
	p.KVMount = "secret"
	p.K8sRole = "app"
	p.K8sMount = "k8s/../auth"
	if err := validateProvider("v", p); err == nil || !strings.Contains(err.Error(), "k8s_mount") {
		t.Fatalf("bad k8s_mount: %v", err)
	}
}

func TestInsecureTLSScreams(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	c := New(WithConfig(SecretsConfig{
		Providers: map[string]ProviderConfig{
			"bao": {
				Kind:                  "openbao",
				Address:               srv.URL,
				Token:                 "s.test",
				AllowInsecureHTTP:     boolPtr(true),
				TLSInsecureSkipVerify: boolPtr(true),
			},
		},
	}), WithLogger(log))
	if err := c.Init(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })
	out := buf.String()
	if !strings.Contains(out, "tls_insecure_skip_verify is on") {
		t.Fatalf("expected skip-verify scream, got:\n%s", out)
	}
	if !strings.Contains(out, "allow_insecure_http is on") {
		t.Fatalf("expected http scream, got:\n%s", out)
	}
	if got := metricNamed(t, c.Metrics(), "cf_secrets_tls_insecure_skip_verify"); got != 1 {
		t.Fatalf("skip-verify gauge = %v, want 1", got)
	}
	if got := metricNamed(t, c.Metrics(), "cf_secrets_allow_insecure_http"); got != 1 {
		t.Fatalf("insecure http gauge = %v, want 1", got)
	}
}

func boolPtr(b bool) *bool { return &b }

func metricNamed(t *testing.T, ms []cf_observability.Metric, name string) float64 {
	t.Helper()
	for _, m := range ms {
		if m.Name == name {
			return m.Value
		}
	}
	t.Fatalf("metric %s missing in %+v", name, ms)
	return 0
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
