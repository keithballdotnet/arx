package kms

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/context"
)

// DiskStorageProvider is an implementation of aquiring a MASTER key using a derived key
type DiskStorageProvider struct {
	path string
}

// NewDiskStorageProvider ...
func NewDiskStorageProvider() (DiskStorageProvider, error) {

	path := os.Getenv("GOKMS_PATH")

	log.Printf("Using DiskStorageProvider - Disk Path: %v", path)

	return DiskStorageProvider{path: path}, nil
}

// SaveKey - Persist a key to disk
func (sp DiskStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	keyPath := filepath.Join(sp.path, keyID+".key")

	log.Printf("SaveKey: %v", keyPath)

	_, err := os.Stat(keyPath)
	if err == nil && !overwrite {
		return errors.New("Already exists")
	}

	return ioutil.WriteFile(keyPath, data, 0600)
}

// GetKey - Read a key from disk
func (sp DiskStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {

	keyPath := filepath.Join(sp.path, keyID+".key")

	log.Printf("GetKey: %v", keyPath)

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

// GetSecret - Get a secret
func (sp DiskStorageProvider) GetSecret(ctx context.Context, secretID string) ([]byte, error) {
	keyPath := filepath.Join(sp.path, secretID+".secret")

	log.Printf("GetSecret: %v", keyPath)

	return ioutil.ReadFile(keyPath)
}

// SaveSecret - set a secret
func (sp DiskStorageProvider) SaveSecret(ctx context.Context, secretID string, data []byte, overwrite bool) error {
	secretPath := filepath.Join(sp.path, secretID+".secret")

	log.Printf("SaveSecret: %v", secretPath)

	_, err := os.Stat(secretPath)
	if err == nil && !overwrite {
		return errors.New("Already exists")
	}

	return ioutil.WriteFile(secretPath, data, 0600)
}

// ListSecrets List available secrets
func (sp DiskStorageProvider) ListSecrets(ctx context.Context) ([]string, error) {
	// List the key ids
	secretIDs := []string{}

	files, _ := ioutil.ReadDir(sp.path)
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".secret") && !strings.HasPrefix(f.Name(), "kms") {
			secretIDs = append(secretIDs, strings.TrimSuffix(f.Name(), ".secret"))
		}
	}

	return secretIDs, nil
}
