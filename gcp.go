package cf_secrets

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type gcpSecretsAPI interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) gcpSecretIter
	Close() error
}

type gcpSecretIter interface {
	Next() (*secretmanagerpb.Secret, error)
}

type gcpClientAdapter struct {
	c *secretmanager.Client
}

func (a gcpClientAdapter) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return a.c.AccessSecretVersion(ctx, req)
}

func (a gcpClientAdapter) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) gcpSecretIter {
	return a.c.ListSecrets(ctx, req)
}

func (a gcpClientAdapter) Close() error { return a.c.Close() }

type gcpDriver struct {
	project string
	client  gcpSecretsAPI
}

func newGCPDriver(ctx context.Context, p ProviderConfig) (*gcpDriver, error) {
	var opts []option.ClientOption
	if f := strings.TrimSpace(p.CredentialsFile); f != "" {
		opts = append(opts, option.WithCredentialsFile(f))
	}
	c, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp secretmanager client: %w", err)
	}
	return &gcpDriver{
		project: strings.TrimSpace(p.Project),
		client:  gcpClientAdapter{c: c},
	}, nil
}

func (d *gcpDriver) kind() string { return kindGCP }

func (d *gcpDriver) close() error {
	if d.client != nil {
		return d.client.Close()
	}
	return nil
}

func (d *gcpDriver) ping(ctx context.Context) error {
	it := d.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent:   "projects/" + d.project,
		PageSize: 1,
	})
	_, err := it.Next()
	if err == iterator.Done {
		return nil
	}
	return err
}

func (d *gcpDriver) get(ctx context.Context, ref Ref) ([]byte, error) {
	name := gcpVersionName(d.project, ref)
	out, err := d.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil {
		return nil, err
	}
	if out.Payload == nil {
		return nil, fmt.Errorf("gcp secret %q has empty payload", ref.Path)
	}
	return extractJSONKey(out.Payload.Data, ref.Key)
}

func gcpVersionName(project string, ref Ref) string {
	path := strings.TrimSpace(ref.Path)
	ver := strings.TrimSpace(ref.Version)
	if ver == "" {
		ver = "latest"
	}
	if strings.HasPrefix(path, "projects/") {
		if strings.Contains(path, "/versions/") {
			return path
		}
		return path + "/versions/" + ver
	}
	return "projects/" + project + "/secrets/" + path + "/versions/" + ver
}
