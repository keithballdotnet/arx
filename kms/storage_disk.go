// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/golang/glog"

	"golang.org/x/net/context"
)

// DiskStorageProvider is an implementation of aquiring a MASTER key using a derived key
type DiskStorageProvider struct {
	path string
}

// NewDiskStorageProvider ...
func NewDiskStorageProvider() (DiskStorageProvider, error) {

	path := os.Getenv("ARX_PATH")

	log.Infof("Using DiskStorageProvider - Disk Path: %v", path)

	return DiskStorageProvider{path: path}, nil
}

// SaveKey - Persist a key to disk
func (sp DiskStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	keyPath := filepath.Join(sp.path, keyID+".key")

	log.Infof("SaveKey: %v", keyPath)

	_, err := os.Stat(keyPath)
	if err == nil && !overwrite {
		return errors.New("Already exists")
	}

	return ioutil.WriteFile(keyPath, data, 0600)
}

// GetKey - Read a key from disk
func (sp DiskStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {

	keyPath := filepath.Join(sp.path, keyID+".key")

	log.Infof("GetKey: %v", keyPath)

	return ioutil.ReadFile(keyPath)
}

// ListCustomerKeyIDs - List available keys
func (sp DiskStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {

	// List the key ids
	keyIDs := []string{}

	files, _ := ioutil.ReadDir(sp.path)
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".key") && !strings.HasPrefix(f.Name(), "kms") {
			keyIDs = append(keyIDs, strings.TrimSuffix(f.Name(), ".key"))
		}
	}

	return keyIDs, nil
}

// Close will do nothing
func (sp DiskStorageProvider) Close() {
}
