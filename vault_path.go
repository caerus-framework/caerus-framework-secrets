package cf_secrets

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// sanitizeKVSecretPath is the CLI-style KV path under kv_mount.
// The driver always inserts the KV v2 HTTP prefix /data/. Callers must not.
func sanitizeKVSecretPath(raw string) (string, error) {
	p := strings.Trim(strings.TrimSpace(raw), "/")
	if p == "" {
		return "", fmt.Errorf("empty vault/openbao secret path")
	}
	if strings.Contains(p, "\\") {
		return "", fmt.Errorf("invalid vault/openbao secret path %q", raw)
	}
	if p == "data" || strings.HasPrefix(p, "data/") {
		return "", fmt.Errorf("vault/openbao Ref.Path %q must not start with data/ — that is the KV v2 HTTP prefix; the driver adds it (same as vault kv get <mount>/<path>)", raw)
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", fmt.Errorf("invalid vault/openbao secret path %q", raw)
		}
	}
	return p, nil
}

func kvReadURL(address, mount, secretPath, version string) (string, error) {
	clean, err := sanitizeKVSecretPath(secretPath)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("address: %w", err)
	}
	u = u.JoinPath("v1", mount, "data")
	for _, seg := range strings.Split(clean, "/") {
		u = u.JoinPath(seg)
	}
	if v := strings.TrimSpace(version); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			q := u.Query()
			q.Set("version", v)
			u.RawQuery = q.Encode()
		}
	}
	return u.String(), nil
}

func vaultJoin(address string, segs ...string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	return u.JoinPath(segs...).String(), nil
}
