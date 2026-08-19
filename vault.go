package cf_secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type vaultAuth struct {
	role    string
	mount   string
	jwtPath string
}

type vaultDriver struct {
	kindName  string
	address   string
	namespace string
	mount     string
	token     string
	auth      vaultAuth
	http      *http.Client
}

func newVaultDriver(kind string, p ProviderConfig) (*vaultDriver, error) {
	timeout := time.Duration(timeoutOrDefault(p.TimeoutSec) * float64(time.Second))
	tlsCfg, err := vaultTLS(p)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	d := &vaultDriver{
		kindName:  kind,
		address:   strings.TrimRight(strings.TrimSpace(p.Address), "/"),
		namespace: strings.TrimSpace(p.Namespace),
		mount:     strings.TrimSpace(p.KVMount),
		http:      &http.Client{Timeout: timeout, Transport: tr},
	}
	if d.mount == "" {
		d.mount = defaultKVMount
	}
	if role := strings.TrimSpace(p.K8sRole); role != "" {
		d.auth = vaultAuth{
			role:    role,
			mount:   strings.TrimSpace(p.K8sMount),
			jwtPath: strings.TrimSpace(p.K8sJWTPath),
		}
		if d.auth.mount == "" {
			d.auth.mount = defaultK8sMount
		}
		if d.auth.jwtPath == "" {
			d.auth.jwtPath = defaultK8sJWT
		}
		return d, nil
	}
	token, err := readVaultToken(p)
	if err != nil {
		return nil, err
	}
	d.token = token
	return d, nil
}

func vaultTLS(p ProviderConfig) (*tls.Config, error) {
	insecure := p.TLSInsecureSkipVerify != nil && *p.TLSInsecureSkipVerify
	if p.TLSCAFile == "" && !insecure {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	if p.TLSCAFile != "" {
		pem, err := os.ReadFile(p.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file %s contains no certificates", p.TLSCAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func readVaultToken(p ProviderConfig) (string, error) {
	if t := strings.TrimSpace(p.Token); t != "" {
		return t, nil
	}
	path := strings.TrimSpace(p.TokenPath)
	if path == "" {
		return "", fmt.Errorf("token, token_path, or k8s_role is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token_path: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (d *vaultDriver) kind() string { return d.kindName }

func (d *vaultDriver) close() error { return nil }

func (d *vaultDriver) setNamespace(req *http.Request) {
	if d.namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.namespace)
	}
}

func (d *vaultDriver) k8sLogin(ctx context.Context) error {
	jwt, err := os.ReadFile(d.auth.jwtPath)
	if err != nil {
		return fmt.Errorf("read k8s jwt: %w", err)
	}
	body, err := json.Marshal(map[string]string{
		"role": d.auth.role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.address+"/v1/auth/"+d.auth.mount+"/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	d.setNamespace(req)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("k8s login: %s: %s", resp.Status, bytes.TrimSpace(raw))
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("k8s login decode: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return fmt.Errorf("k8s login: empty client_token")
	}
	d.token = out.Auth.ClientToken
	return nil
}

func (d *vaultDriver) ensureToken(ctx context.Context) error {
	if d.token != "" {
		return nil
	}
	if d.auth.role == "" {
		return fmt.Errorf("no vault token")
	}
	return d.k8sLogin(ctx)
}

func (d *vaultDriver) ping(ctx context.Context) error {
	if err := d.ensureToken(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.address+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	d.setNamespace(req)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	// 200 initialized+unsealed; 429 standby; 473 DR secondary — all "up".
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 473 {
		return nil
	}
	return fmt.Errorf("sys/health: %s", resp.Status)
}

func (d *vaultDriver) get(ctx context.Context, ref Ref) ([]byte, error) {
	if err := d.ensureToken(ctx); err != nil {
		return nil, err
	}
	path := strings.Trim(ref.Path, "/")
	u := d.address + "/v1/" + d.mount + "/data/" + path
	if v := strings.TrimSpace(ref.Version); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			u += "?version=" + v
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", d.token)
	d.setNamespace(req)
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret %q not found", ref.Path)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("read %s: %s: %s", path, resp.Status, bytes.TrimSpace(raw))
	}
	var wrap struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, fmt.Errorf("decode kv: %w", err)
	}
	if wrap.Data.Data == nil {
		return nil, fmt.Errorf("secret %q has empty data", ref.Path)
	}
	if ref.Key == "" {
		return json.Marshal(wrap.Data.Data)
	}
	v, ok := wrap.Data.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %q", ref.Key, ref.Path)
	}
	switch t := v.(type) {
	case string:
		return []byte(t), nil
	case nil:
		return nil, fmt.Errorf("key %q is null", ref.Key)
	default:
		return json.Marshal(t)
	}
}
