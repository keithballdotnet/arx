package kms

import (
	"golang.org/x/net/context"
)

// CryptoProvider provides an interface for crypto provider solutions
type CryptoProvider interface {
	CreateKey(ctx context.Context, description string, keyType string) (KeyMetadata, error)
	ListKeys(ctx context.Context) ([]KeyMetadata, error)
	GetKey(ctx context.Context, KeyID string) (Key, error)
	EnableKey(ctx context.Context, KeyID string) (KeyMetadata, error)
	DisableKey(ctx context.Context, KeyID string) (KeyMetadata, error)
	RotateKey(ctx context.Context, KeyID string) error
	Encrypt(ctx context.Context, data []byte, KeyID string) ([]byte, error)
	Decrypt(ctx context.Context, data []byte) ([]byte, string, error)
	ReEncrypt(ctx context.Context, data []byte, KeyID string) ([]byte, string, error)
	Sign(ctx context.Context, data []byte, KeyID string) ([]byte, error)
	Verify(data []byte, sig []byte) (bool, error)
	GetSecret(ctx context.Context, secretID string) (Secret, error)
	SetSecret(ctx context.Context, secretID string, data []byte, overwrite bool) error
	ListSecrets(ctx context.Context) ([]string, error)
}

// MasterKeyProvider provides a mechanism to load a master key
type MasterKeyProvider interface {
	GetKey(ctx context.Context) ([]byte, error)
}

// StorageProvider is an interface to storage providers
type StorageProvider interface {
	SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error
	GetKey(ctx context.Context, keyID string) ([]byte, error)
	ListCustomerKeyIDs(ctx context.Context) ([]string, error)
	SaveSecret(ctx context.Context, secretID string, data []byte, overwrite bool) error
	GetSecret(ctx context.Context, secretID string) ([]byte, error)
	ListSecrets(ctx context.Context) ([]string, error)
}
