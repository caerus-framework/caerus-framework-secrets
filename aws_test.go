package cf_secrets

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeAWS struct {
	val string
	err error
}

func (f fakeAWS) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(f.val)}, nil
}

func (f fakeAWS) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{}, f.err
}

func TestAWSDriverJSONKey(t *testing.T) {
	d := &awsDriver{region: "eu-central-1", client: fakeAWS{val: `{"webhook-secret":"hex"}`}}
	ctx := context.Background()
	if err := d.ping(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := d.get(ctx, Ref{Path: "rtgh", Key: "webhook-secret"})
	if err != nil || string(got) != "hex" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestGCPVersionName(t *testing.T) {
	got := gcpVersionName("proj", Ref{Path: "db-pass"})
	want := "projects/proj/secrets/db-pass/versions/latest"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	full := gcpVersionName("proj", Ref{Path: "projects/proj/secrets/x", Version: "5"})
	if full != "projects/proj/secrets/x/versions/5" {
		t.Fatalf("got %s", full)
	}
}
