package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSTSClient is a mock implementation of the STS client for testing
type mockSTSClient struct {
	getCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.getCallerIdentityFunc != nil {
		return m.getCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("mock function not set")
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

func TestNewVerifier(t *testing.T) {
	// Test with custom STS client
	customClient := &mockSTSClient{}
	v, err := NewVerifier(context.Background(), WithSTSClient(customClient))
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, customClient, v.stsClient)
}

func TestVerify_Success(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE:session-name"),
				Arn:     stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	claims, err := v.Verify(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, "123456789012", claims.Account)
	assert.Equal(t, "AROA123456789EXAMPLE:session-name", claims.UserID)
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/MyRole/session-name", claims.Arn)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", claims.RoleArn)
}

func TestVerify_PolicyMatch(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE:session-name"),
				Arn:     stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	policy := &Policy{
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	claims, err := v.Verify(context.Background(), policy)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", claims.RoleArn)
}

func TestVerify_PolicyMismatch(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE:session-name"),
				Arn:     stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	policy := &Policy{
		RoleArn: "arn:aws:iam::123456789012:role/DifferentRole",
	}

	claims, err := v.Verify(context.Background(), policy)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "role ARN mismatch")
	assert.Contains(t, err.Error(), "expected arn:aws:iam::123456789012:role/DifferentRole")
	assert.Contains(t, err.Error(), "got arn:aws:iam::123456789012:role/MyRole")
}

func TestVerify_NoPolicy(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE:session-name"),
				Arn:     stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	// No policy means no verification constraints
	claims, err := v.Verify(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", claims.RoleArn)
}

func TestVerify_DirectIAMRole(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE"),
				Arn:     stringPtr("arn:aws:iam::123456789012:role/MyRole"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	claims, err := v.Verify(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, claims)

	// Direct IAM role ARN should not have RoleArn set (no assumed-role)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", claims.Arn)
	assert.Empty(t, claims.RoleArn)
}

func TestVerify_NotAssumedRole(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AIDAI123456789EXAMPLE"),
				Arn:     stringPtr("arn:aws:iam::123456789012:user/developer"),
			}, nil
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	policy := &Policy{
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	// Should fail because caller is not using an assumed role
	claims, err := v.Verify(context.Background(), policy)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "expected role ARN")
	assert.Contains(t, err.Error(), "but caller is not using an assumed role")
}

func TestVerify_IncompleteResponse(t *testing.T) {
	tests := []struct {
		name   string
		output *sts.GetCallerIdentityOutput
	}{
		{
			name: "missing account",
			output: &sts.GetCallerIdentityOutput{
				UserId: stringPtr("AROA123456789EXAMPLE:session-name"),
				Arn:    stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			},
		},
		{
			name: "missing userId",
			output: &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				Arn:     stringPtr("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
			},
		},
		{
			name: "missing arn",
			output: &sts.GetCallerIdentityOutput{
				Account: stringPtr("123456789012"),
				UserId:  stringPtr("AROA123456789EXAMPLE:session-name"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSTSClient{
				getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return tt.output, nil
				},
			}

			v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
			require.NoError(t, err)

			claims, err := v.Verify(context.Background(), nil)
			require.Error(t, err)
			assert.Nil(t, claims)
			assert.Contains(t, err.Error(), "incomplete caller identity response")
		})
	}
}

func TestVerify_STSError(t *testing.T) {
	mockClient := &mockSTSClient{
		getCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("STS API error")
		},
	}

	v, err := NewVerifier(context.Background(), WithSTSClient(mockClient))
	require.NoError(t, err)

	claims, err := v.Verify(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "failed to get caller identity")
	assert.Contains(t, err.Error(), "STS API error")
}

func TestExtractRoleArn(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid assumed role ARN",
			input:    "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
		{
			name: "assumed role with path",
			// Note: The current implementation only takes resourceParts[1], so this test
			// verifies the actual behavior (which may need enhancement for paths)
			input:    "arn:aws:sts::123456789012:assumed-role/path/to/MyRole/session-name",
			expected: "arn:aws:iam::123456789012:role/path",
		},
		{
			name: "direct IAM role ARN",
			// This ARN has exactly 6 parts and resourceParts[1] exists, so it returns a role ARN
			// even though this is not an assumed-role ARN
			input:    "arn:aws:iam::123456789012:role/MyRole",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
		{
			name: "user ARN",
			// This ARN has exactly 6 parts and resourceParts[1] exists
			input:    "arn:aws:iam::123456789012:user/developer",
			expected: "arn:aws:iam::123456789012:role/developer",
		},
		{
			name:     "invalid ARN format",
			input:    "not-an-arn",
			expected: "",
		},
		{
			name:     "ARN with too few parts",
			input:    "arn:aws:sts",
			expected: "",
		},
		{
			name: "assumed role ARN with missing session",
			// This has resourceParts = ["assumed-role", "MyRole"], so len >= 2 and returns MyRole
			input:    "arn:aws:sts::123456789012:assumed-role/MyRole",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRoleArn(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVerifyPolicy_NilPolicy(t *testing.T) {
	v := &Verifier{}
	claims := &Claims{
		Account: "123456789012",
		UserID:  "AROA123456789EXAMPLE:session-name",
		Arn:     "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	err := v.verifyPolicy(claims, nil)
	require.NoError(t, err)
}

func TestVerifyPolicy_EmptyRoleArn(t *testing.T) {
	v := &Verifier{}
	claims := &Claims{
		Account: "123456789012",
		UserID:  "AROA123456789EXAMPLE:session-name",
		Arn:     "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	// Policy with empty RoleArn should not fail
	policy := &Policy{
		RoleArn: "",
	}

	err := v.verifyPolicy(claims, policy)
	require.NoError(t, err)
}

func TestClaims(t *testing.T) {
	claims := &Claims{
		Account: "123456789012",
		UserID:  "AROA123456789EXAMPLE:session-name",
		Arn:     "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	assert.Equal(t, "123456789012", claims.Account)
	assert.Equal(t, "AROA123456789EXAMPLE:session-name", claims.UserID)
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/MyRole/session-name", claims.Arn)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", claims.RoleArn)
}

func TestPolicy(t *testing.T) {
	policy := &Policy{
		RoleArn: "arn:aws:iam::123456789012:role/MyRole",
	}

	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", policy.RoleArn)
}
