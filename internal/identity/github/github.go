// Package github provides GitHub Actions OIDC identity verification
package github

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// GitHubOIDCIssuer is the issuer URL for GitHub Actions OIDC tokens
	GitHubOIDCIssuer = "https://token.actions.githubusercontent.com"

	// DefaultAudience is the default audience for GitHub Actions OIDC tokens
	DefaultAudience = "https://github.com/genesis-operator"

	// JWKSCacheDuration is how long to cache the JWKS
	JWKSCacheDuration = 1 * time.Hour
)

// Claims represents the claims in a GitHub Actions OIDC token
type Claims struct {
	// Standard OIDC claims
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	NotBefore  int64  `json:"nbf"`
	JTI        string `json:"jti"`

	// GitHub-specific claims
	Repository        string `json:"repository"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	RepositoryID      string `json:"repository_id"`
	Actor             string `json:"actor"`
	ActorID           string `json:"actor_id"`
	Workflow          string `json:"workflow"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSHA       string `json:"workflow_sha"`
	EventName         string `json:"event_name"`
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type"`
	HeadRef           string `json:"head_ref"`
	BaseRef           string `json:"base_ref"`
	SHA               string `json:"sha"`
	RunID             string `json:"run_id"`
	RunNumber         string `json:"run_number"`
	RunAttempt        string `json:"run_attempt"`
	Environment       string `json:"environment"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	RunnerEnvironment string `json:"runner_environment"`
}

// Policy defines what claims are required for authentication
type Policy struct {
	// Audience is the expected audience claim
	Audience string `json:"audience,omitempty"`

	// Repository is the exact repository to match (e.g., "owner/repo")
	Repository string `json:"repository,omitempty"`

	// RepositoryOwner restricts to repositories owned by this user/org
	RepositoryOwner string `json:"repositoryOwner,omitempty"`

	// Workflow restricts to a specific workflow file
	Workflow string `json:"workflow,omitempty"`

	// Environment restricts to a specific GitHub environment
	Environment string `json:"environment,omitempty"`

	// Ref restricts to a specific ref (e.g., "refs/heads/main")
	Ref string `json:"ref,omitempty"`

	// RefPatterns is a list of ref patterns to allow (glob-style)
	RefPatterns []string `json:"refPatterns,omitempty"`

	// AllowedActors restricts which actors can authenticate
	AllowedActors []string `json:"allowedActors,omitempty"`

	// RequireEnvironment requires the environment claim to be present
	RequireEnvironment bool `json:"requireEnvironment,omitempty"`
}

// Verifier verifies GitHub Actions OIDC tokens
type Verifier struct {
	httpClient   *http.Client
	jwksCache    *jwksCache
	customIssuer string
}

// VerifierOption configures a Verifier
type VerifierOption func(*Verifier)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) VerifierOption {
	return func(v *Verifier) {
		v.httpClient = client
	}
}

// WithIssuer sets a custom OIDC issuer (for testing)
func WithIssuer(issuer string) VerifierOption {
	return func(v *Verifier) {
		v.customIssuer = issuer
	}
}

// NewVerifier creates a new GitHub OIDC token verifier
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(v)
	}

	v.jwksCache = newJWKSCache(v.httpClient, v.getIssuer())

	return v
}

func (v *Verifier) getIssuer() string {
	if v.customIssuer != "" {
		return v.customIssuer
	}
	return GitHubOIDCIssuer
}

// VerifyToken verifies a GitHub Actions OIDC token and returns the claims
func (v *Verifier) VerifyToken(ctx context.Context, token string, policy *Policy) (*Claims, error) {
	// Parse the JWT
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Verify issuer
	if claims.Issuer != v.getIssuer() {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.getIssuer(), claims.Issuer)
	}

	// Verify audience
	expectedAudience := DefaultAudience
	if policy != nil && policy.Audience != "" {
		expectedAudience = policy.Audience
	}
	if claims.Audience != expectedAudience {
		return nil, fmt.Errorf("invalid audience: expected %s, got %s", expectedAudience, claims.Audience)
	}

	// Verify expiration
	now := time.Now().Unix()
	if claims.Expiration < now {
		return nil, errors.New("token has expired")
	}

	// Verify not before
	if claims.NotBefore > now {
		return nil, errors.New("token is not yet valid")
	}

	// Verify signature
	if err := v.verifySignature(ctx, token, header.Kid); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Verify policy
	if policy != nil {
		if err := v.verifyPolicy(&claims, policy); err != nil {
			return nil, fmt.Errorf("policy verification failed: %w", err)
		}
	}

	return &claims, nil
}

func (v *Verifier) verifySignature(ctx context.Context, token string, kid string) error {
	// Get the public key from JWKS
	key, err := v.jwksCache.getKey(ctx, kid)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse JWT parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT format")
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature using RSA-SHA256
	message := parts[0] + "." + parts[1]
	if err := verifyRSASignature(key, []byte(message), signature); err != nil {
		return err
	}

	return nil
}

func (v *Verifier) verifyPolicy(claims *Claims, policy *Policy) error {
	if policy == nil {
		return nil
	}

	// Check repository
	if policy.Repository != "" && claims.Repository != policy.Repository {
		return fmt.Errorf("repository mismatch: expected %s, got %s", policy.Repository, claims.Repository)
	}

	// Check repository owner
	if policy.RepositoryOwner != "" && claims.RepositoryOwner != policy.RepositoryOwner {
		return fmt.Errorf("repository owner mismatch: expected %s, got %s", policy.RepositoryOwner, claims.RepositoryOwner)
	}

	// Check workflow
	if policy.Workflow != "" && claims.Workflow != policy.Workflow {
		return fmt.Errorf("workflow mismatch: expected %s, got %s", policy.Workflow, claims.Workflow)
	}

	// Check environment
	if policy.Environment != "" && claims.Environment != policy.Environment {
		return fmt.Errorf("environment mismatch: expected %s, got %s", policy.Environment, claims.Environment)
	}

	// Check if environment is required
	if policy.RequireEnvironment && claims.Environment == "" {
		return errors.New("environment claim is required but not present")
	}

	// Check ref
	if policy.Ref != "" && claims.Ref != policy.Ref {
		return fmt.Errorf("ref mismatch: expected %s, got %s", policy.Ref, claims.Ref)
	}

	// Check ref patterns
	if len(policy.RefPatterns) > 0 {
		matched := false
		for _, pattern := range policy.RefPatterns {
			if matchPattern(pattern, claims.Ref) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("ref %s does not match any allowed patterns", claims.Ref)
		}
	}

	// Check allowed actors
	if len(policy.AllowedActors) > 0 {
		allowed := false
		for _, actor := range policy.AllowedActors {
			if actor == claims.Actor {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("actor %s is not in the allowed list", claims.Actor)
		}
	}

	return nil
}

// matchPattern performs simple glob-style matching
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}

	return pattern == value
}

// jwtHeader represents a JWT header
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwksCache caches JWKS keys
type jwksCache struct {
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	expiration time.Time
	httpClient *http.Client
	issuer     string
}

func newJWKSCache(client *http.Client, issuer string) *jwksCache {
	return &jwksCache{
		keys:       make(map[string]*rsa.PublicKey),
		httpClient: client,
		issuer:     issuer,
	}
}

func (c *jwksCache) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if time.Now().Before(c.expiration) {
		if key, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Refresh cache
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}

	return key, nil
}

func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(c.expiration) {
		return nil
	}

	// Fetch OIDC configuration
	configURL := c.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create config request: %w", err)
	}

	resp, err := c.httpClient.Do(req) // #nosec G704 -- URL is constructed from trusted OIDC issuer configuration
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC config returned status %d", resp.StatusCode)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	// Fetch JWKS
	jwksReq, err := http.NewRequestWithContext(ctx, http.MethodGet, config.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	jwksResp, err := c.httpClient.Do(jwksReq) // #nosec G704 -- URL is from OIDC discovery document of trusted issuer
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer jwksResp.Body.Close()

	if jwksResp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned status %d", jwksResp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Parse keys
	newKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}

		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		// Convert exponent bytes to int
		var exp int
		for _, b := range e {
			exp = exp<<8 + int(b)
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: exp,
		}

		newKeys[key.Kid] = pubKey
	}

	c.keys = newKeys
	c.expiration = time.Now().Add(JWKSCacheDuration)

	return nil
}

// verifyRSASignature verifies an RSA-SHA256 signature
func verifyRSASignature(key *rsa.PublicKey, message, signature []byte) error {
	hash := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
}
