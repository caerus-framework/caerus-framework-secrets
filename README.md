# caerus-framework-secrets

[![CI](https://github.com/caerus-framework/caerus-framework-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/caerus-framework/caerus-framework-secrets/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/caerus-framework/caerus-framework-secrets/graph/badge.svg)](https://codecov.io/gh/caerus-framework/caerus-framework-secrets)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Caerus Framework **secrets chassis**. One component holds several **named
providers**. Callers ask for a secret by **provider name** plus a path/key;
they do **not** switch on Vault vs AWS vs GCP themselves.

This module is declared in `main` like postgres/valkey. It is **not**
auto-registered with logs/configuration/observability. It initializes in the
bootstrap **`secrets`** stage (after configuration, before data) so data
clients can read credentials during their own `Init` if they hold this
component pointer.

## Design (why named providers)

Wrong vs right:

```text
Wrong: GetSecret("db_password") and the chassis guesses the backend
Right: Get(ctx, "openbao", Ref{Path: "app/db", Key: "password"})

Wrong: app code `switch cfg.Kind { case "aws": … case "vault": … }`
Right: app code always calls Get; kind is only in secrets.json
```

**Provider name** (map key, `Get`’s first argument) and **kind** (which API)
are two different strings. Prefer matching them when you have one backend
(`"openbao"` + `kind: "openbao"`). They may differ (`"prod-kv"` +
`kind: "vault"`).

**OpenBao vs Vault** are two **kinds** that share the same KV v2 HTTP client.
They are not two SDKs. Use `kind: openbao` or `kind: vault` so metrics and
docs say which product you pointed `address` at. Kubernetes auth (`k8s_role`)
and token file (`token_path`) are the same for both.

**This is not External Secrets Operator.** ESO copies Bao/Vault into a
Kubernetes Secret for the pod. This chassis is for **in-process** fetches
(apps that call Get at Init or per use). You can use both: ESO for the
GitHub App PEM, this module for app-level secrets later.

Credentials for talking *to* the backends (Bao token, AWS chain, GCP ADC)
are still a bootstrap problem: they live in this component’s config file or
the cloud default chain. We will grow AppRole / extra AWS/GCP settings when
the file shape below is wrong for a real deploy.

## Wiring

Two wiring shapes. Prefer the **app-owned** shape.

### App-owned consumer (golden — demoapp pattern)

`main` declares secrets as chassis. The app stores `*CFSecrets` and calls
`Get` / `GetString` per use (do not snapshot the bytes at Init if the owner
must see rotations — call Get again, or reload via config).

```go
fw := cf.New(&cf.FrameworkOptions{
	Logs:          &cf.LogsSettings{Format: "json", Level: "info", ConfigSource: "logs"},
	Observability: &cf.ObservabilitySettings{Bind: ":9090", ConfigSource: "observability"},
	Components: []cf.CaerusComponent{
		cf_secrets.New(cf_secrets.WithConfigSource("secrets", "config/secrets.json")),
		cf_postgres.New(cf_postgres.WithConfigSource("postgresql", "config/postgresql.json")),
		app.New(),
	},
})
```

```go
type App struct {
	secrets *cf_secrets.CFSecrets
}

func (a *App) GetDependencies() []string {
	return []string{cf_secrets.ComponentName} // "secrets", not the source nickname
}

func (a *App) Init(ctx context.Context, fw *cf.CaerusFramework) error {
	sec, ok := cf.Get[*cf_secrets.CFSecrets](fw)
	if !ok {
		return errors.New("app: secrets component missing")
	}
	a.secrets = sec
	return nil
}

func (a *App) webhookHMAC(ctx context.Context) (string, error) {
	return a.secrets.GetString(ctx, "openbao", cf_secrets.Ref{
		Path: "caerus-framework/release-train-gh-app",
		Key:  "webhook-secret",
	})
}
```

### Simple `main`-level wiring

```go
fw := cf.New()
fw.AddComponent(cf_logs.New(cf_logs.WithWriter(os.Stdout)))
fw.AddComponent(cf_secrets.New(cf_secrets.WithConfigSource("secrets", "config/secrets.json")))
```

Then `cf.MustGet[*cf_secrets.CFSecrets](fw)`. Same `Get` API.

## Configuration

File is canonical. Example `config/secrets.json`:

```json
{
  "degraded_mode": false,
  "health_when_degraded": "not_ready",
  "providers": {
    "openbao": {
      "kind": "openbao",
      "address": "https://openbao.example.com:8200",
      "kv_mount": "secret",
      "token_path": "/var/run/secrets/openbao/token"
    },
    "vault": {
      "kind": "vault",
      "address": "https://vault.example.com:8200",
      "kv_mount": "secret",
      "k8s_role": "release-train",
      "k8s_mount": "kubernetes"
    },
    "aws": {
      "kind": "aws",
      "region": "eu-central-1"
    },
    "gcp": {
      "kind": "gcp",
      "project": "my-gcp-project"
    }
  }
}
```

You only list the providers this process uses. An unused kind is omitted.

| Kind | `Get` Path | `Get` Key | Auth in v1 |
|---|---|---|---|
| `openbao` / `vault` | KV path under `kv_mount` | property in the KV data map | `token` / `token_path`, or `k8s_role` (+ JWT file) |
| `aws` | Secrets Manager name or ARN | JSON object key if the secret string is JSON | AWS default credential chain (`region` required) |
| `gcp` | secret id, or full `projects/…/secrets/…` | JSON object key if payload is JSON | Application Default Credentials (`project` required) |
| `file` | path under `root` | JSON object key if the file is JSON | local / tests only |

`kind: file` is for laptop tests. It is not a production secret store.

### Auth paths for Vault/OpenBao (pick one per provider)

**Path Token-file (typical in Kubernetes):** `token_path` points at a mounted
file; the process reads it at Init (and again if you later add reload-from-file).

**Path Kubernetes auth:** set `k8s_role`; the driver POSTs the service-account
JWT (`k8s_jwt_path`, default the in-cluster token path) to
`/v1/auth/<k8s_mount>/login`.

**Path Inline token (dev / break-glass):** `token` in the config file. Do not
use this in production files that are not a Secret.

## Lifecycle

- **Init** builds clients and **pings** each provider (Vault/OpenBao
  `sys/health`, AWS `ListSecrets`, GCP list, file `stat` of `root`). Hard
  failure by default.
- **DegradedMode** lets Init finish when a ping fails; logs and metrics
  scream; `/readyz` stays red unless `health_when_degraded: ready`.
- **Get** always hits the live driver (no snapshot of secret bytes on the
  chassis).
- **OnConfigReload** rebuilds drivers; last-good stays if rebuild/ping fails
  (unless DegradedMode already allowed a partial set).

```mermaid
flowchart TD
  A[Caller Get provider+Ref] --> B{Provider name in map?}
  B -->|no| C[error unknown provider]
  B -->|yes| D[kind from that provider's config]
  D -->|vault / openbao| E[KV v2 HTTP]
  D -->|aws| F[Secrets Manager]
  D -->|gcp| G[Secret Manager]
  D -->|file| H[read root/path]
```

## Health and metrics

`Health` re-pings every provider. Metrics (`cf_secrets_*`) include provider
count, Get totals, ping failures, DegradedMode.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
