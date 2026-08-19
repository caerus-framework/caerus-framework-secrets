package cf_secrets

import "fmt"

// Ref names one secret inside a provider. Callers always pass a provider
// name plus a Ref; they never choose the API (vault vs aws) themselves.
//
// Path meanings by kind:
//
//   - vault / openbao: KV path under kv_mount (e.g. "caerus-framework/release-train-gh-app")
//   - aws: Secrets Manager name or ARN
//   - gcp: secret id (short name, or full "projects/…/secrets/…" resource)
//   - file: path relative to the provider root
//
// Key, when set, selects a field: Vault/OpenBao KV property, or a JSON object
// key for AWS/GCP string payloads. Empty Key returns the whole payload.
//
// Version is optional (GCP version id, AWS version id/stage, Vault KV version).
// Empty means the provider default (usually latest).
type Ref struct {
	Path    string
	Key     string
	Version string
}

func (r Ref) validate() error {
	if r.Path == "" {
		return fmt.Errorf("secret ref path is required")
	}
	return nil
}
