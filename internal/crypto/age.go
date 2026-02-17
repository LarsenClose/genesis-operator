package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

type AgeKeypair struct {
	PrivateKey string
	PublicKey  string
}

func GenerateAgeKeypair() (*AgeKeypair, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age keypair: %w", err)
	}

	return &AgeKeypair{
		PrivateKey: identity.String(),
		PublicKey:  identity.Recipient().String(),
	}, nil
}

func ParseAgeKeypair(privateKey string) (*AgeKeypair, error) {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age private key: %w", err)
	}

	return &AgeKeypair{
		PrivateKey: identity.String(),
		PublicKey:  identity.Recipient().String(),
	}, nil
}

func AgeEncrypt(plaintext []byte, publicKey string) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age public key: %w", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create age encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close age encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

func AgeDecrypt(ciphertext []byte, privateKey string) ([]byte, error) {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age private key: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return plaintext, nil
}

func IsValidAgePrivateKey(key string) bool {
	if key == "" || !strings.HasPrefix(key, "AGE-SECRET-KEY-1") {
		return false
	}
	_, err := age.ParseX25519Identity(key)
	return err == nil
}

func IsValidAgePublicKey(key string) bool {
	if key == "" || !strings.HasPrefix(key, "age1") {
		return false
	}
	_, err := age.ParseX25519Recipient(key)
	return err == nil
}
