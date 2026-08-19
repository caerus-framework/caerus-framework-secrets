package cf_secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type awsSecretsAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

type awsDriver struct {
	region string
	client awsSecretsAPI
}

func newAWSDriver(ctx context.Context, p ProviderConfig) (*awsDriver, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(strings.TrimSpace(p.Region)),
	}
	if ep := strings.TrimSpace(p.Endpoint); ep != "" {
		opts = append(opts, awsconfig.WithBaseEndpoint(ep))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return &awsDriver{
		region: p.Region,
		client: secretsmanager.NewFromConfig(cfg),
	}, nil
}

func (d *awsDriver) kind() string { return kindAWS }

func (d *awsDriver) close() error { return nil }

func (d *awsDriver) ping(ctx context.Context) error {
	_, err := d.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	})
	return err
}

func (d *awsDriver) get(ctx context.Context, ref Ref) ([]byte, error) {
	in := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(ref.Path),
	}
	if v := strings.TrimSpace(ref.Version); v != "" {
		if strings.HasPrefix(v, "AWSCURRENT") || strings.HasPrefix(v, "AWSPENDING") || strings.HasPrefix(v, "AWSPREVIOUS") {
			in.VersionStage = aws.String(v)
		} else {
			in.VersionId = aws.String(v)
		}
	}
	out, err := d.client.GetSecretValue(ctx, in)
	if err != nil {
		return nil, err
	}
	var payload []byte
	switch {
	case out.SecretString != nil:
		payload = []byte(*out.SecretString)
	case len(out.SecretBinary) > 0:
		payload = out.SecretBinary
	default:
		return nil, fmt.Errorf("aws secret %q has empty payload", ref.Path)
	}
	return extractJSONKey(payload, ref.Key)
}
