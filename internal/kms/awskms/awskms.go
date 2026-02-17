package awskms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

type KMSClient interface {
	Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Options struct {
	KeyArn string
	Region string
}

type Provider struct {
	keyArn string
	region string
	client KMSClient
}

func NewProvider(opts Options) (*Provider, error) {
	if opts.KeyArn == "" {
		return nil, errors.New("key ARN is required")
	}

	region := opts.Region
	if region == "" {
		region = extractRegionFromArn(opts.KeyArn)
	}

	return &Provider{
		keyArn: opts.KeyArn,
		region: region,
		client: nil,
	}, nil
}

func NewProviderWithClient(opts Options, client KMSClient) (*Provider, error) {
	p, err := NewProvider(opts)
	if err != nil {
		return nil, err
	}
	p.client = client
	return p, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(p.region))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	p.client = kms.NewFromConfig(cfg)
	return nil
}

func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderAWSKMS
}

func (p *Provider) Region() string {
	return p.region
}

func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	output, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(p.keyArn),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt failed: %w", err)
	}

	return output.CiphertextBlob, nil
}

func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.keyArn),
		CiphertextBlob: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt failed: %w", err)
	}

	return output.Plaintext, nil
}

func extractRegionFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}
