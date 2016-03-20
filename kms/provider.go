// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	arxpb "github.com/keithballdotnet/arx/proto"
	"golang.org/x/net/context"
)

// Type of key
var (
	CustomerAESKeyType = "aes"
	MasterKeyType      = "masterkey"
)

// CryptoProvider provides an interface for crypto provider solutions
type CryptoProvider interface {
	CreateKey(ctx context.Context, description string) (*arxpb.KeyMetadata, error)
	ListKeys(ctx context.Context) ([]*arxpb.KeyMetadata, error)
	GetKey(ctx context.Context, KeyID string) (*arxpb.Key, error)
	EnableKey(ctx context.Context, KeyID string) (*arxpb.KeyMetadata, error)
	DisableKey(ctx context.Context, KeyID string) (*arxpb.KeyMetadata, error)
	RotateKey(ctx context.Context, KeyID string) error
	Encrypt(ctx context.Context, data []byte, KeyID string) ([]byte, error)
	Decrypt(ctx context.Context, data []byte) ([]byte, string, error)
	ReEncrypt(ctx context.Context, data []byte, KeyID string) ([]byte, string, error)
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
	Close()
}
