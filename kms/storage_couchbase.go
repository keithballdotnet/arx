// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/couchbase/gocb"
)

// CouchbaseStorageProvider ...
type CouchbaseStorageProvider struct {
	bucket *gocb.Bucket
}

// NewCouchbaseStorageProvider ...
func NewCouchbaseStorageProvider() (CouchbaseStorageProvider, error) {

	cbhost := os.Getenv("ARX_CBHOST")
	if cbhost == "" {
		cbhost = "http://localhost:8091"
	}
	cbbuket := os.Getenv("ARX_CBBUCKET")
	if cbbuket == "" {
		cbbuket = "kms"
	}

	cluster, err := gocb.Connect(cbhost)
	if err != nil {
		log.Errorf("Error getting bucket:  %v", err)
		return CouchbaseStorageProvider{}, err
	}

	bucket, err := cluster.OpenBucket(cbbuket, "")
	if err != nil {
		log.Errorf("Error getting bucket:  %v", err)
		return CouchbaseStorageProvider{}, err
	}

	bucket.SetOperationTimeout(30 * time.Second)

	return CouchbaseStorageProvider{bucket: bucket}, nil
}

// KeyIDList - A list of key IDs
type KeyIDList struct {
	KeyIDs []string
}

// SaveKey - Persist a key to disk
func (sp CouchbaseStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	keyPath := "arx:key:" + keyID

	log.Infof("SaveKey: %v", keyPath)

	if sp.bucket == nil {
		return errors.New("No couchbase bucket!")
	}

	cbdata := RawData{Data: data}

	if !overwrite {
		_, err := sp.bucket.Insert(keyPath, cbdata, 0)
		if err != nil {
			return err
		}
	} else {
		_, err := sp.bucket.Upsert(keyPath, cbdata, 0)
		if err != nil {
			return err
		}
	}

	// Do not add salts to list of stored keys
	if strings.HasSuffix(keyID, ".salt") || strings.HasSuffix(keyID, ".master") {
		return nil
	}

	var keyList KeyIDList
	// Get key list
	_, err := sp.bucket.Get("arx:keylist", &keyList)

	log.Infof("Add key got keylist: %v", keyList)

	if err != nil {
		log.Infof("Error getting key list: %v", err)
		// We got an error.  If not found that is ok.
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			log.Println("Not found error... creating empty list")
			keyList = KeyIDList{KeyIDs: []string{}}
		} else {
			return err
		}
	}

	// Add the key id it not already there
	if !contains(keyList.KeyIDs, keyID) {
		log.Infof("Adding key %v to key list", keyID)
		keyList.KeyIDs = append(keyList.KeyIDs, keyID)
	}

	log.Infof("Setting keylist: %v", keyList)

	// Preseve the key list
	_, err = sp.bucket.Upsert("arx:keylist", keyList, 0)
	if err != nil {
		log.Infof("Error setting key list: %v", err)
	}

	return err
}

// Check if a slice contains a string
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// GetKey - Read a key from disk
func (sp CouchbaseStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {

	if sp.bucket == nil {
		return nil, errors.New("No couchbase bucket!")
	}

	keyPath := "arx:key:" + keyID

	log.Infof("GetKey: %v", keyPath)

	var data RawData
	_, err := sp.bucket.Get(keyPath, &data)

	// Get data...
	return data.Data, err
}

// ListCustomerKeyIDs - List available keys
func (sp CouchbaseStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {
	var keyList KeyIDList
	// Get key list
	_, err := sp.bucket.Get("arx:keylist", &keyList)
	if err != nil {
		return nil, err
	}

	log.Infof("ListKeys keylist: %v", keyList)

	return keyList.KeyIDs, nil
}

// RawData type for json marshalling
type RawData struct {
	Data []byte
}

// Close will close the connection
func (sp CouchbaseStorageProvider) Close() {
	sp.bucket.Close()
}
