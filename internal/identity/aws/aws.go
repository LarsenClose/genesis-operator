// Package aws provides AWS IRSA identity verification
package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// stsAPI defines the interface for STS operations needed by the verifier
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Claims represents the identity information from AWS STS GetCallerIdentity
type Claims struct {
	// Account is the AWS account ID
	Account string `json:"account"`

	// UserID is the unique identifier for the caller
	UserID string `json:"userId"`

	// Arn is the AWS ARN of the caller
	Arn string `json:"arn"`

	// RoleArn is the assumed role ARN (extracted from Arn if it's a role)
	RoleArn string `json:"roleArn,omitempty"`
}

// Policy defines what role ARN is required for authentication
type Policy struct {
	// RoleArn is the expected IAM role ARN
	RoleArn string `json:"roleArn"`
}

// Verifier verifies AWS IRSA identity
type Verifier struct {
	stsClient stsAPI
}

// VerifierOption configures a Verifier
type VerifierOption func(*Verifier)

// WithSTSClient sets a custom STS client (for testing)
func WithSTSClient(client stsAPI) VerifierOption {
	return func(v *Verifier) {
		v.stsClient = client
	}
}

// NewVerifier creates a new AWS IRSA identity verifier
func NewVerifier(ctx context.Context, opts ...VerifierOption) (*Verifier, error) {
	v := &Verifier{}

	for _, opt := range opts {
		opt(v)
	}

	// Create STS client if not provided
	if v.stsClient == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		v.stsClient = sts.NewFromConfig(cfg)
	}

	return v, nil
}

// Verify verifies the AWS IRSA identity and returns the claims
func (v *Verifier) Verify(ctx context.Context, policy *Policy) (*Claims, error) {
	// Call GetCallerIdentity to get the current identity
	result, err := v.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil || result.UserId == nil || result.Arn == nil {
		return nil, fmt.Errorf("incomplete caller identity response")
	}

	claims := &Claims{
		Account: *result.Account,
		UserID:  *result.UserId,
		Arn:     *result.Arn,
	}

	// Extract role ARN if this is an assumed role
	// Format: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
	if strings.Contains(claims.Arn, ":assumed-role/") {
		claims.RoleArn = extractRoleArn(claims.Arn)
	}

	// Verify policy
	if policy != nil {
		if err := v.verifyPolicy(claims, policy); err != nil {
			return nil, fmt.Errorf("policy verification failed: %w", err)
		}
	}

	return claims, nil
}

func (v *Verifier) verifyPolicy(claims *Claims, policy *Policy) error {
	if policy == nil {
		return nil
	}

	// Check role ARN
	if policy.RoleArn != "" {
		if claims.RoleArn == "" {
			return fmt.Errorf("expected role ARN %s, but caller is not using an assumed role", policy.RoleArn)
		}
		if claims.RoleArn != policy.RoleArn {
			return fmt.Errorf("role ARN mismatch: expected %s, got %s", policy.RoleArn, claims.RoleArn)
		}
	}

	return nil
}

// extractRoleArn extracts the role ARN from an assumed-role ARN
// Input: arn:aws:sts::123456789012:assumed-role/MyRole/session-name
// Output: arn:aws:iam::123456789012:role/MyRole
func extractRoleArn(assumedRoleArn string) string {
	// Parse the ARN components
	parts := strings.Split(assumedRoleArn, ":")
	if len(parts) < 6 {
		return ""
	}

	// Extract account ID (parts[4] is account)
	account := parts[4]

	// Extract role name from the resource part
	// Format: assumed-role/ROLE_NAME/SESSION_NAME
	resourceParts := strings.Split(parts[5], "/")
	if len(resourceParts) < 2 {
		return ""
	}

	roleName := resourceParts[1]

	// Construct the IAM role ARN
	// arn:aws:iam::ACCOUNT:role/ROLE_NAME
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
}
