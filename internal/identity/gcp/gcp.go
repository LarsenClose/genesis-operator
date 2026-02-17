// Package gcp provides GCP Workload Identity verification
package gcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// MetadataServerURL is the GCP metadata server endpoint
	MetadataServerURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

	// MetadataServerProjectURL is the endpoint for project ID
	MetadataServerProjectURL = "http://metadata.google.internal/computeMetadata/v1/project/project-id"

	// MetadataFlavor is the required header value for GCP metadata server requests
	MetadataFlavor = "Google"
)

// Claims represents the identity information from GCP metadata server
type Claims struct {
	// ServiceAccount is the GCP service account email
	ServiceAccount string `json:"serviceAccount"`

	// ProjectID is the GCP project ID
	ProjectID string `json:"projectId,omitempty"`
}

// Policy defines what service account is required for authentication
type Policy struct {
	// ServiceAccount is the expected GCP service account email
	ServiceAccount string `json:"serviceAccount"`
}

// Verifier verifies GCP Workload Identity
type Verifier struct {
	httpClient *http.Client
}

// VerifierOption configures a Verifier
type VerifierOption func(*Verifier)

// WithHTTPClient sets a custom HTTP client (for testing)
func WithHTTPClient(client *http.Client) VerifierOption {
	return func(v *Verifier) {
		v.httpClient = client
	}
}

// NewVerifier creates a new GCP Workload Identity verifier
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		httpClient: &http.Client{},
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

// Verify verifies the GCP Workload Identity and returns the claims
func (v *Verifier) Verify(ctx context.Context, policy *Policy) (*Claims, error) {
	// Get service account from metadata server
	serviceAccount, err := v.getMetadata(ctx, MetadataServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get service account from metadata server: %w", err)
	}

	claims := &Claims{
		ServiceAccount: serviceAccount,
	}

	// Try to get project ID (non-critical, continue if it fails)
	projectID, err := v.getMetadata(ctx, MetadataServerProjectURL)
	if err == nil {
		claims.ProjectID = projectID
	}

	// Verify policy
	if policy != nil {
		if err := v.verifyPolicy(claims, policy); err != nil {
			return nil, fmt.Errorf("policy verification failed: %w", err)
		}
	}

	return claims, nil
}

func (v *Verifier) getMetadata(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}

	// GCP metadata server requires this header
	req.Header.Set("Metadata-Flavor", MetadataFlavor)

	resp, err := v.httpClient.Do(req) // #nosec G704 -- URL is constructed from trusted GCP metadata server endpoint
	if err != nil {
		return "", fmt.Errorf("failed to query metadata server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata response: %w", err)
	}

	value := strings.TrimSpace(string(body))
	if value == "" {
		return "", fmt.Errorf("metadata server returned empty value")
	}

	return value, nil
}

func (v *Verifier) verifyPolicy(claims *Claims, policy *Policy) error {
	if policy == nil {
		return nil
	}

	// Check service account
	if policy.ServiceAccount != "" && claims.ServiceAccount != policy.ServiceAccount {
		return fmt.Errorf("service account mismatch: expected %s, got %s",
			policy.ServiceAccount, claims.ServiceAccount)
	}

	return nil
}
