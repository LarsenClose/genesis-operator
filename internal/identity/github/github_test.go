package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	require.NotNil(t, v)
	assert.Equal(t, GitHubOIDCIssuer, v.getIssuer())
}

func TestNewVerifierWithCustomIssuer(t *testing.T) {
	customIssuer := "https://custom.issuer.example.com"
	v := NewVerifier(WithIssuer(customIssuer))
	require.NotNil(t, v)
	assert.Equal(t, customIssuer, v.getIssuer())
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "refs/heads/main",
			value:    "refs/heads/main",
			expected: true,
		},
		{
			name:     "exact no match",
			pattern:  "refs/heads/main",
			value:    "refs/heads/develop",
			expected: false,
		},
		{
			name:     "wildcard all",
			pattern:  "*",
			value:    "anything",
			expected: true,
		},
		{
			name:     "prefix wildcard",
			pattern:  "refs/heads/*",
			value:    "refs/heads/feature-branch",
			expected: true,
		},
		{
			name:     "prefix wildcard no match",
			pattern:  "refs/heads/*",
			value:    "refs/tags/v1.0.0",
			expected: false,
		},
		{
			name:     "suffix wildcard",
			pattern:  "*-release",
			value:    "v1.0.0-release",
			expected: true,
		},
		{
			name:     "suffix wildcard no match",
			pattern:  "*-release",
			value:    "v1.0.0-beta",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchPattern(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVerifyPolicy(t *testing.T) {
	verifier := NewVerifier()

	tests := []struct {
		name    string
		claims  *Claims
		policy  *Policy
		wantErr bool
		errMsg  string
	}{
		{
			name: "no policy",
			claims: &Claims{
				Repository:      "owner/repo",
				RepositoryOwner: "owner",
				Ref:             "refs/heads/main",
			},
			policy:  nil,
			wantErr: false,
		},
		{
			name: "matching repository",
			claims: &Claims{
				Repository: "owner/repo",
			},
			policy: &Policy{
				Repository: "owner/repo",
			},
			wantErr: false,
		},
		{
			name: "mismatched repository",
			claims: &Claims{
				Repository: "owner/other-repo",
			},
			policy: &Policy{
				Repository: "owner/repo",
			},
			wantErr: true,
			errMsg:  "repository mismatch",
		},
		{
			name: "matching repository owner",
			claims: &Claims{
				RepositoryOwner: "myorg",
			},
			policy: &Policy{
				RepositoryOwner: "myorg",
			},
			wantErr: false,
		},
		{
			name: "mismatched repository owner",
			claims: &Claims{
				RepositoryOwner: "otherorg",
			},
			policy: &Policy{
				RepositoryOwner: "myorg",
			},
			wantErr: true,
			errMsg:  "repository owner mismatch",
		},
		{
			name: "matching workflow",
			claims: &Claims{
				Workflow: ".github/workflows/deploy.yml",
			},
			policy: &Policy{
				Workflow: ".github/workflows/deploy.yml",
			},
			wantErr: false,
		},
		{
			name: "matching environment",
			claims: &Claims{
				Environment: "production",
			},
			policy: &Policy{
				Environment: "production",
			},
			wantErr: false,
		},
		{
			name: "required environment present",
			claims: &Claims{
				Environment: "staging",
			},
			policy: &Policy{
				RequireEnvironment: true,
			},
			wantErr: false,
		},
		{
			name: "required environment missing",
			claims: &Claims{
				Environment: "",
			},
			policy: &Policy{
				RequireEnvironment: true,
			},
			wantErr: true,
			errMsg:  "environment claim is required",
		},
		{
			name: "matching ref",
			claims: &Claims{
				Ref: "refs/heads/main",
			},
			policy: &Policy{
				Ref: "refs/heads/main",
			},
			wantErr: false,
		},
		{
			name: "ref pattern match",
			claims: &Claims{
				Ref: "refs/heads/feature-123",
			},
			policy: &Policy{
				RefPatterns: []string{"refs/heads/*"},
			},
			wantErr: false,
		},
		{
			name: "ref pattern no match",
			claims: &Claims{
				Ref: "refs/tags/v1.0.0",
			},
			policy: &Policy{
				RefPatterns: []string{"refs/heads/*"},
			},
			wantErr: true,
			errMsg:  "does not match any allowed patterns",
		},
		{
			name: "allowed actor",
			claims: &Claims{
				Actor: "trusted-user",
			},
			policy: &Policy{
				AllowedActors: []string{"trusted-user", "another-user"},
			},
			wantErr: false,
		},
		{
			name: "disallowed actor",
			claims: &Claims{
				Actor: "untrusted-user",
			},
			policy: &Policy{
				AllowedActors: []string{"trusted-user"},
			},
			wantErr: true,
			errMsg:  "not in the allowed list",
		},
		{
			name: "multiple policy checks pass",
			claims: &Claims{
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Environment:     "production",
				Actor:           "deploy-bot",
			},
			policy: &Policy{
				Repository:         "myorg/myrepo",
				RepositoryOwner:    "myorg",
				RefPatterns:        []string{"refs/heads/main", "refs/heads/release-*"},
				RequireEnvironment: true,
				AllowedActors:      []string{"deploy-bot"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.verifyPolicy(tt.claims, tt.policy)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClaims(t *testing.T) {
	claims := &Claims{
		Issuer:            GitHubOIDCIssuer,
		Subject:           "repo:owner/repo:ref:refs/heads/main",
		Audience:          DefaultAudience,
		Repository:        "owner/repo",
		RepositoryOwner:   "owner",
		RepositoryID:      "123456",
		Actor:             "developer",
		ActorID:           "789",
		Workflow:          ".github/workflows/ci.yml",
		EventName:         "push",
		Ref:               "refs/heads/main",
		RefType:           "branch",
		SHA:               "abc123def456",
		RunID:             "1234567890",
		RunNumber:         "42",
		Environment:       "production",
		RunnerEnvironment: "github-hosted",
	}

	assert.Equal(t, GitHubOIDCIssuer, claims.Issuer)
	assert.Equal(t, "owner/repo", claims.Repository)
	assert.Equal(t, "owner", claims.RepositoryOwner)
	assert.Equal(t, "developer", claims.Actor)
	assert.Equal(t, "production", claims.Environment)
	assert.Equal(t, "refs/heads/main", claims.Ref)
}

func TestPolicy(t *testing.T) {
	policy := &Policy{
		Audience:           "https://custom.audience",
		Repository:         "owner/repo",
		RepositoryOwner:    "owner",
		Workflow:           ".github/workflows/deploy.yml",
		Environment:        "production",
		Ref:                "refs/heads/main",
		RefPatterns:        []string{"refs/heads/*", "refs/tags/v*"},
		AllowedActors:      []string{"deploy-bot", "admin"},
		RequireEnvironment: true,
	}

	assert.Equal(t, "https://custom.audience", policy.Audience)
	assert.Equal(t, "owner/repo", policy.Repository)
	assert.Len(t, policy.RefPatterns, 2)
	assert.Len(t, policy.AllowedActors, 2)
	assert.True(t, policy.RequireEnvironment)
}

// Test fixtures and helpers

type testServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ts := &testServer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        "test-key-id",
	}

	mux := http.NewServeMux()

	// OIDC configuration endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":   ts.server.URL,
			"jwks_uri": ts.server.URL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		// Convert public key to JWK format
		n := base64.RawURLEncoding.EncodeToString(ts.publicKey.N.Bytes())
		e := make([]byte, 4)
		e[0] = byte(ts.publicKey.E >> 24)
		e[1] = byte(ts.publicKey.E >> 16)
		e[2] = byte(ts.publicKey.E >> 8)
		e[3] = byte(ts.publicKey.E)
		// Trim leading zeros
		for len(e) > 1 && e[0] == 0 {
			e = e[1:]
		}
		eEncoded := base64.RawURLEncoding.EncodeToString(e)

		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kid": ts.kid,
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   eEncoded,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	ts.server = httptest.NewServer(mux)
	return ts
}

func (ts *testServer) Close() {
	ts.server.Close()
}

func (ts *testServer) createToken(claims *Claims) (string, error) {
	// Create header
	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: ts.kid,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create payload
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Sign
	message := headerEncoded + "." + payloadEncoded
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, ts.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureEncoded, nil
}

func (ts *testServer) createInvalidToken(header interface{}, payload interface{}, signature string) string {
	headerBytes, _ := json.Marshal(header)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	if signature == "" {
		signature = "invalidsignature"
	}

	return headerEncoded + "." + payloadEncoded + "." + signature
}

// Token Verification Tests

func TestVerifyToken_InvalidJWTFormat(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	tests := []struct {
		name  string
		token string
	}{
		{name: "no dots", token: "invalidtoken"},
		{name: "one dot", token: "header.payload"},
		{name: "too many dots", token: "header.payload.signature.extra"},
		{name: "empty string", token: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.VerifyToken(context.Background(), tt.token, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid JWT format")
		})
	}
}

func TestVerifyToken_InvalidHeaderBase64(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	token := "not-valid-base64!@#$.payload.signature"
	_, err := verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWT header")
}

func TestVerifyToken_InvalidHeaderJSON(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	// Valid base64 but invalid JSON
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	token := invalidJSON + ".payload.signature"
	_, err := verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWT header")
}

func TestVerifyToken_UnsupportedAlgorithm(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	tests := []struct {
		name string
		alg  string
	}{
		{name: "HS256", alg: "HS256"},
		{name: "ES256", alg: "ES256"},
		{name: "none", alg: "none"},
		{name: "PS256", alg: "PS256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := map[string]string{"alg": tt.alg, "typ": "JWT", "kid": "test"}
			payload := map[string]string{"test": "data"}
			token := ts.createInvalidToken(header, payload, "")

			_, err := verifier.VerifyToken(context.Background(), token, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported algorithm")
		})
	}
}

func TestVerifyToken_InvalidPayloadBase64(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: "test"}
	headerBytes, _ := json.Marshal(header)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	token := headerEncoded + ".not-valid-base64!@#$.signature"
	_, err := verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWT payload")
}

func TestVerifyToken_InvalidPayloadJSON(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: "test"}
	headerBytes, _ := json.Marshal(header)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Valid base64 but invalid JSON
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	token := headerEncoded + "." + invalidJSON + ".signature"
	_, err := verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWT claims")
}

func TestVerifyToken_InvalidIssuer(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     "https://wrong.issuer.com",
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issuer")
}

func TestVerifyToken_InvalidAudience(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   "https://wrong.audience.com",
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid audience")
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(-1 * time.Hour).Unix(), // Expired
		NotBefore:  now.Add(-2 * time.Hour).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token has expired")
}

func TestVerifyToken_TokenNotYetValid(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(2 * time.Hour).Unix(),
		NotBefore:  now.Add(1 * time.Hour).Unix(), // Not yet valid
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is not yet valid")
}

func TestVerifyToken_ValidToken(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:          ts.server.URL,
		Audience:        DefaultAudience,
		Expiration:      now.Add(1 * time.Hour).Unix(),
		NotBefore:       now.Add(-1 * time.Minute).Unix(),
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		Actor:           "test-user",
		Ref:             "refs/heads/main",
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	verifiedClaims, err := verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)
	assert.Equal(t, claims.Repository, verifiedClaims.Repository)
	assert.Equal(t, claims.Actor, verifiedClaims.Actor)
}

func TestVerifyToken_ValidTokenWithPolicy(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:          ts.server.URL,
		Audience:        DefaultAudience,
		Expiration:      now.Add(1 * time.Hour).Unix(),
		NotBefore:       now.Add(-1 * time.Minute).Unix(),
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		Actor:           "deploy-bot",
		Ref:             "refs/heads/main",
		Environment:     "production",
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	policy := &Policy{
		Repository:      "owner/repo",
		RepositoryOwner: "owner",
		AllowedActors:   []string{"deploy-bot"},
		RefPatterns:     []string{"refs/heads/*"},
	}

	verifiedClaims, err := verifier.VerifyToken(context.Background(), token, policy)
	require.NoError(t, err)
	assert.Equal(t, claims.Repository, verifiedClaims.Repository)
}

func TestVerifyToken_CustomAudience(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	customAudience := "https://custom.audience.com"
	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   customAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	policy := &Policy{
		Audience: customAudience,
	}

	_, err = verifier.VerifyToken(context.Background(), token, policy)
	require.NoError(t, err)
}

// JWKS Cache Tests

func TestJWKSCache_CacheHit(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	// First call should populate cache
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)

	// Second call should use cached key
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)
}

func TestJWKSCache_RefreshFailure(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Create verifier with unreachable server
	verifier := NewVerifier(
		WithIssuer("http://unreachable.local:9999"),
		WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     "http://unreachable.local:9999",
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	// Create a token signed by test server (won't matter since we can't fetch JWKS)
	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get public key")
}

func TestJWKSCache_InvalidOIDCConfig(t *testing.T) {
	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}
	}))
	defer invalidServer.Close()

	verifier := NewVerifier(
		WithIssuer(invalidServer.URL),
		WithHTTPClient(invalidServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     invalidServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OIDC config")
}

func TestJWKSCache_InvalidJWKS(t *testing.T) {
	var invalidServer *httptest.Server
	invalidServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   invalidServer.URL,
				"jwks_uri": invalidServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}
	}))
	defer invalidServer.Close()

	verifier := NewVerifier(
		WithIssuer(invalidServer.URL),
		WithHTTPClient(invalidServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     invalidServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

func TestJWKSCache_KeyNotFound(t *testing.T) {
	var emptyServer *httptest.Server
	emptyServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   emptyServer.URL,
				"jwks_uri": emptyServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			// Return empty keys
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		}
	}))
	defer emptyServer.Close()

	verifier := NewVerifier(
		WithIssuer(emptyServer.URL),
		WithHTTPClient(emptyServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     emptyServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestJWKSCache_OIDCConfigHTTPError(t *testing.T) {
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer errorServer.Close()

	verifier := NewVerifier(
		WithIssuer(errorServer.URL),
		WithHTTPClient(errorServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     errorServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC config returned status")
}

func TestJWKSCache_JWKSHTTPError(t *testing.T) {
	var jwksErrorServer *httptest.Server
	jwksErrorServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   jwksErrorServer.URL,
				"jwks_uri": jwksErrorServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer jwksErrorServer.Close()

	verifier := NewVerifier(
		WithIssuer(jwksErrorServer.URL),
		WithHTTPClient(jwksErrorServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     jwksErrorServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS returned status")
}

// Signature Verification Tests

func TestVerifySignature_ValidSignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	// Tamper with signature
	parts := splitToken(token)
	tamperedSignature := base64.RawURLEncoding.EncodeToString([]byte("tampered"))
	tamperedToken := parts[0] + "." + parts[1] + "." + tamperedSignature

	_, err = verifier.VerifyToken(context.Background(), tamperedToken, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifySignature_WrongKey(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Create a different key pair
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	// Create header
	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: ts.kid,
	}
	headerBytes, _ := json.Marshal(header)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create payload
	payloadBytes, _ := json.Marshal(claims)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Sign with wrong key
	message := headerEncoded + "." + payloadEncoded
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, wrongKey, crypto.SHA256, hash[:])
	require.NoError(t, err)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	token := message + "." + signatureEncoded

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifySignature_InvalidSignatureBase64(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	parts := splitToken(token)
	invalidToken := parts[0] + "." + parts[1] + ".not-valid-base64!@#$"

	_, err = verifier.VerifyToken(context.Background(), invalidToken, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

// Additional edge cases

func TestVerifyToken_PolicyFailureAfterValidSignature(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:          ts.server.URL,
		Audience:        DefaultAudience,
		Expiration:      now.Add(1 * time.Hour).Unix(),
		NotBefore:       now.Add(-1 * time.Minute).Unix(),
		Repository:      "wrong/repo",
		RepositoryOwner: "wrong",
		Actor:           "wrong-user",
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	policy := &Policy{
		Repository:      "expected/repo",
		RepositoryOwner: "expected",
		AllowedActors:   []string{"allowed-user"},
	}

	_, err = verifier.VerifyToken(context.Background(), token, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy verification failed")
}

func TestWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	verifier := NewVerifier(WithHTTPClient(customClient))
	require.NotNil(t, verifier)
	assert.Equal(t, customClient, verifier.httpClient)
}

func TestJWKSCache_CacheExpiration(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	// First call populates cache
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)

	// Expire the cache
	verifier.jwksCache.mu.Lock()
	verifier.jwksCache.expiration = time.Now().Add(-1 * time.Hour)
	verifier.jwksCache.mu.Unlock()

	// Second call should refresh cache
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)
}

func TestVerifyPolicy_WorkflowMismatch(t *testing.T) {
	verifier := NewVerifier()

	claims := &Claims{
		Workflow: ".github/workflows/wrong.yml",
	}

	policy := &Policy{
		Workflow: ".github/workflows/deploy.yml",
	}

	err := verifier.verifyPolicy(claims, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow mismatch")
}

func TestVerifyPolicy_EnvironmentMismatch(t *testing.T) {
	verifier := NewVerifier()

	claims := &Claims{
		Environment: "staging",
	}

	policy := &Policy{
		Environment: "production",
	}

	err := verifier.verifyPolicy(claims, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment mismatch")
}

func TestVerifyPolicy_RefMismatch(t *testing.T) {
	verifier := NewVerifier()

	claims := &Claims{
		Ref: "refs/heads/develop",
	}

	policy := &Policy{
		Ref: "refs/heads/main",
	}

	err := verifier.verifyPolicy(claims, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ref mismatch")
}

func TestJWKSCache_DoubleCheckAfterLock(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	verifier := NewVerifier(
		WithIssuer(ts.server.URL),
		WithHTTPClient(ts.server.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     ts.server.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	// First call populates cache
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)

	// Manually expire the cache but set it to expire soon
	verifier.jwksCache.mu.Lock()
	verifier.jwksCache.expiration = time.Now().Add(100 * time.Millisecond)
	verifier.jwksCache.mu.Unlock()

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// This should trigger a refresh
	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.NoError(t, err)
}

func TestJWKSCache_NonRSAKey(t *testing.T) {
	var nonRSAServer *httptest.Server
	nonRSAServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   nonRSAServer.URL,
				"jwks_uri": nonRSAServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			// Return EC key instead of RSA
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kid": "ec-key",
						"kty": "EC",
						"alg": "ES256",
						"use": "sig",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		}
	}))
	defer nonRSAServer.Close()

	verifier := NewVerifier(
		WithIssuer(nonRSAServer.URL),
		WithHTTPClient(nonRSAServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     nonRSAServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestJWKSCache_NonSigUseKey(t *testing.T) {
	var nonSigServer *httptest.Server
	nonSigServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   nonSigServer.URL,
				"jwks_uri": nonSigServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			// Return key with wrong use
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kid": "enc-key",
						"kty": "RSA",
						"alg": "RS256",
						"use": "enc",
						"n":   "test",
						"e":   "AQAB",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		}
	}))
	defer nonSigServer.Close()

	verifier := NewVerifier(
		WithIssuer(nonSigServer.URL),
		WithHTTPClient(nonSigServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     nonSigServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestJWKSCache_InvalidModulusBase64(t *testing.T) {
	var invalidModServer *httptest.Server
	invalidModServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   invalidModServer.URL,
				"jwks_uri": invalidModServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			// Return key with invalid base64 modulus
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kid": "bad-mod",
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"n":   "not-valid-base64!@#$",
						"e":   "AQAB",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		}
	}))
	defer invalidModServer.Close()

	verifier := NewVerifier(
		WithIssuer(invalidModServer.URL),
		WithHTTPClient(invalidModServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     invalidModServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

func TestJWKSCache_InvalidExponentBase64(t *testing.T) {
	var invalidExpServer *httptest.Server
	invalidExpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]interface{}{
				"issuer":   invalidExpServer.URL,
				"jwks_uri": invalidExpServer.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			// Valid modulus but invalid exponent
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kid": "bad-exp",
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"n":   "test",
						"e":   "not-valid-base64!@#$",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)
		}
	}))
	defer invalidExpServer.Close()

	verifier := NewVerifier(
		WithIssuer(invalidExpServer.URL),
		WithHTTPClient(invalidExpServer.Client()),
	)

	now := time.Now()
	claims := &Claims{
		Issuer:     invalidExpServer.URL,
		Audience:   DefaultAudience,
		Expiration: now.Add(1 * time.Hour).Unix(),
		NotBefore:  now.Add(-1 * time.Minute).Unix(),
	}

	ts := newTestServer(t)
	defer ts.Close()

	token, err := ts.createToken(claims)
	require.NoError(t, err)

	_, err = verifier.VerifyToken(context.Background(), token, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in JWKS")
}

// Helper function
func splitToken(token string) []string {
	parts := make([]string, 3)
	idx1 := 0
	idx2 := 0

	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if idx1 == 0 {
				parts[0] = token[:i]
				idx1 = i
			} else {
				parts[1] = token[idx1+1 : i]
				idx2 = i
				break
			}
		}
	}
	parts[2] = token[idx2+1:]
	return parts
}
