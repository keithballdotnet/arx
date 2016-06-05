// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"errors"

	"golang.org/x/net/context"
)

// FailingStorageProvider ...
type FailingStorageProvider struct {
}

// NewFailingStorageProvider ...
func NewFailingStorageProvider() (*FailingStorageProvider, error) {
	return &FailingStorageProvider{}, nil
}

// SaveKey - Persist a key
func (sp FailingStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {
	return errors.New("Error saving key")
}

// GetKey - Read a key from disk
func (sp FailingStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	return nil, errors.New("Error getting key")
}

// ListCustomerKeyIDs - List available keys
func (sp FailingStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {
	var keyIDs []string
	return keyIDs, errors.New("Error getting keys")
}

// Close will do nothing
func (sp FailingStorageProvider) Close() {
}
