package cf_secrets

import (
	"fmt"
	"strings"
)

// SecretsConfig is the file/env-drivable configuration for the secrets
// chassis. Load it through the configuration component and pass it via
// WithConfigSource. The file is the canonical place to declare providers
// (Kubernetes: a mounted ConfigMap/Secret). Env overlay of the providers map
// is not the rotation plane.
type SecretsConfig struct {
	// Providers is the named set of backends. The map key is the provider
	// name callers pass to Get (e.g. "openbao", "aws-prod"). It is not the
	// kind.
	Providers map[string]ProviderConfig `json:"providers" yaml:"providers"`
	// DegradedMode — when true, a failed Init ping of a provider does not
	// abort the process. Get still fails until that backend is reachable.
	// Default off (hard Init). Pointer so omitted ≠ explicit false.
	DegradedMode *bool `json:"degraded_mode,omitempty" yaml:"degraded_mode,omitempty" env:"DEGRADED_MODE"`
	// HealthWhenDegraded: "not_ready" (default) or "ready". Controls Health()
	// (and thus /readyz) while a configured provider cannot ping.
	HealthWhenDegraded string `json:"health_when_degraded,omitempty" yaml:"health_when_degraded,omitempty" env:"HEALTH_WHEN_DEGRADED"`
}

// ProviderConfig is one named backend. Kind selects the API; the rest of the
// fields are interpreted by that kind. Unused fields for another kind are
// ignored (so one struct can hold vault, aws, gcp, and file settings).
//
// Credential fields will grow (AppRole, IRSA-specific, GCP SA JSON path).
// v1: token/token_path or Kubernetes JWT for vault/openbao; AWS default
// credential chain; GCP Application Default Credentials.
type ProviderConfig struct {
	// Kind is the driver: vault, openbao, aws, gcp, file.
	Kind string `json:"kind" yaml:"kind"`

	// Address is the Vault/OpenBao API base URL (https://host:8200).
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
	// Namespace is a Vault Enterprise namespace. Unused for OpenBao.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// KVMount is the KV secrets engine mount (default "secret").
	KVMount string `json:"kv_mount,omitempty" yaml:"kv_mount,omitempty"`
	// Token is a Vault/OpenBao token (dev/break-glass). Prefer TokenPath.
	Token string `json:"token,omitempty" yaml:"token,omitempty" secret:"redact"`
	// TokenPath is a file whose contents are the Vault/OpenBao token
	// (Kubernetes-rotated file).
	TokenPath string `json:"token_path,omitempty" yaml:"token_path,omitempty"`
	// K8sRole is the Vault/OpenBao Kubernetes auth role. When set, Init
	// logs in with the JWT at K8sJWTPath instead of Token/TokenPath.
	K8sRole string `json:"k8s_role,omitempty" yaml:"k8s_role,omitempty"`
	// K8sMount is the Kubernetes auth mount (default "kubernetes").
	K8sMount string `json:"k8s_mount,omitempty" yaml:"k8s_mount,omitempty"`
	// K8sJWTPath is the service-account token file (default
	// /var/run/secrets/kubernetes.io/serviceaccount/token).
	K8sJWTPath string `json:"k8s_jwt_path,omitempty" yaml:"k8s_jwt_path,omitempty"`
	// TLSCAFile is an optional PEM CA for Vault/OpenBao HTTPS.
	TLSCAFile string `json:"tls_ca_file,omitempty" yaml:"tls_ca_file,omitempty"`
	// TLSInsecureSkipVerify skips TLS verify (lab only).
	TLSInsecureSkipVerify *bool `json:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`

	// Region is the AWS region (required for kind aws).
	Region string `json:"region,omitempty" yaml:"region,omitempty"`
	// Endpoint overrides the AWS Secrets Manager endpoint (LocalStack / tests).
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`

	// Project is the GCP project id (required for kind gcp).
	Project string `json:"project,omitempty" yaml:"project,omitempty"`
	// CredentialsFile is an optional Google service-account JSON path.
	// Empty uses Application Default Credentials.
	CredentialsFile string `json:"credentials_file,omitempty" yaml:"credentials_file,omitempty"`

	// Root is the directory for kind file (local / tests).
	Root string `json:"root,omitempty" yaml:"root,omitempty"`

	// TimeoutSec bounds each provider HTTP/SDK call (default 10s).
	TimeoutSec float64 `json:"timeout_sec,omitempty" yaml:"timeout_sec,omitempty"`
}

const (
	kindVault   = "vault"
	kindOpenBao = "openbao"
	kindAWS     = "aws"
	kindGCP     = "gcp"
	kindFile    = "file"

	defaultKVMount  = "secret"
	defaultK8sMount = "kubernetes"
	defaultK8sJWT   = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultTimeout  = 10.0
)

func normalizeKind(kind string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case kindVault, kindOpenBao, kindAWS, kindGCP, kindFile:
		return k, nil
	case "":
		return "", fmt.Errorf("provider kind is required (vault, openbao, aws, gcp, file)")
	default:
		return "", fmt.Errorf("unknown provider kind %q (vault, openbao, aws, gcp, file)", kind)
	}
}

func validateProvider(name string, p ProviderConfig) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("provider name must not be empty")
	}
	kind, err := normalizeKind(p.Kind)
	if err != nil {
		return fmt.Errorf("provider %q: %w", name, err)
	}
	switch kind {
	case kindVault, kindOpenBao:
		if strings.TrimSpace(p.Address) == "" {
			return fmt.Errorf("provider %q: address is required for kind %s", name, kind)
		}
		hasToken := strings.TrimSpace(p.Token) != "" || strings.TrimSpace(p.TokenPath) != ""
		hasK8s := strings.TrimSpace(p.K8sRole) != ""
		if !hasToken && !hasK8s {
			return fmt.Errorf("provider %q: set token, token_path, or k8s_role for kind %s", name, kind)
		}
	case kindAWS:
		if strings.TrimSpace(p.Region) == "" {
			return fmt.Errorf("provider %q: region is required for kind aws", name)
		}
	case kindGCP:
		if strings.TrimSpace(p.Project) == "" {
			return fmt.Errorf("provider %q: project is required for kind gcp", name)
		}
	case kindFile:
		if strings.TrimSpace(p.Root) == "" {
			return fmt.Errorf("provider %q: root is required for kind file", name)
		}
	}
	return nil
}

func (c SecretsConfig) validate() error {
	for name, p := range c.Providers {
		if err := validateProvider(name, p); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.HealthWhenDegraded)) {
	case "", "not_ready", "ready":
	default:
		return fmt.Errorf("health_when_degraded must be ready or not_ready, got %q", c.HealthWhenDegraded)
	}
	return nil
}

func timeoutOrDefault(sec float64) float64 {
	if sec > 0 {
		return sec
	}
	return defaultTimeout
}
