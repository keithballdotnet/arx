// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/golang/glog"

	"golang.org/x/net/context"

	"github.com/boltdb/bolt"
)

var bucketName = "keys"

// BoltStorageProvider ...
type BoltStorageProvider struct {
	db *bolt.DB
}

// NewBoltStorageProvider ...
func NewBoltStorageProvider() (*BoltStorageProvider, error) {

	boltdb := os.Getenv("ARX_BOLTDB")
	if boltdb == "" {
		boltdb = "arx.db"
	}

	db, err := bolt.Open(boltdb, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Errorf("Error getting bucket:  %v", err)
		return nil, err
	}

	// Create keys bucks
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltStorageProvider{db: db}, nil
}

// SaveKey - Persist a key
func (sp BoltStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	log.Infof("SaveKey: %v", keyID)

	err := sp.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))

		if !overwrite {
			existing := b.Get([]byte(keyID))
			if existing != nil {
				return errors.New("Already exists")
			}
		}

		return b.Put([]byte(keyID), data)
	})
	if err != nil {
		return err
	}
	return nil
}

// GetKey - Read a key from disk
func (sp BoltStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {

	log.Infof("GetKey: %v", keyID)

	var key []byte
	err := sp.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		key = b.Get([]byte(keyID))
		if key == nil {
			return errors.New("Not found")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// ListCustomerKeyIDs - List available keys
func (sp BoltStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {

	var keyIDs []string
	sp.db.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte(bucketName))

		b.ForEach(func(k, v []byte) error {

			keyID := string(k)
			log.Infof("key=%s\n", keyID)
			// Do not add salts to list of stored keys
			if strings.HasSuffix(keyID, ".salt") || strings.HasSuffix(keyID, ".master") {
				return nil
			}

			keyIDs = append(keyIDs, keyID)

			return nil
		})
		return nil
	})

	return keyIDs, nil
}

// Close will do nothing
func (sp BoltStorageProvider) Close() {
	sp.db.Close()
}
