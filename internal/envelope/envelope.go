package envelope

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/larsenclose/genesis/internal/kms"
	"gopkg.in/yaml.v3"
)

type Envelope struct {
	Provider      kms.ProviderName `yaml:"provider"`
	PublicKey     string           `yaml:"publicKey"`
	Ciphertext    []byte           `yaml:"-"`
	CiphertextB64 string           `yaml:"ciphertext"`
}

func Create(ctx context.Context, provider kms.Provider, agePrivateKey string) (*Envelope, error) {
	kp, err := crypto.ParseAgeKeypair(agePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid age private key: %w", err)
	}

	ciphertext, err := provider.Encrypt(ctx, []byte(agePrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt age key: %w", err)
	}

	return &Envelope{
		Provider:      provider.Name(),
		PublicKey:     kp.PublicKey,
		Ciphertext:    ciphertext,
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func Open(ctx context.Context, provider kms.Provider, env *Envelope) (string, error) {
	ciphertext := env.Ciphertext
	if len(ciphertext) == 0 && env.CiphertextB64 != "" {
		var err error
		ciphertext, err = base64.StdEncoding.DecodeString(env.CiphertextB64)
		if err != nil {
			return "", fmt.Errorf("failed to decode ciphertext: %w", err)
		}
	}

	plaintext, err := provider.Decrypt(ctx, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	privateKey := string(plaintext)
	if !crypto.IsValidAgePrivateKey(privateKey) {
		return "", fmt.Errorf("decrypted content is not a valid age private key")
	}

	return privateKey, nil
}

func (e *Envelope) MarshalYAML() ([]byte, error) {
	e.CiphertextB64 = base64.StdEncoding.EncodeToString(e.Ciphertext)
	return yaml.Marshal(e)
}

func (e *Envelope) UnmarshalYAML(data []byte) error {
	type envAlias Envelope
	var aux envAlias
	if err := yaml.Unmarshal(data, &aux); err != nil {
		return err
	}

	*e = Envelope(aux)
	if e.CiphertextB64 != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(e.CiphertextB64)
		if err != nil {
			return fmt.Errorf("failed to decode ciphertext: %w", err)
		}
		e.Ciphertext = ciphertext
	}
	return nil
}
