package kms

import (
	"errors"
	"fmt"
	"log"
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

	cbhost := os.Getenv("GOKMS_CBHOST")
	if cbhost == "" {
		cbhost = "http://localhost:8091"
	}
	cbbuket := os.Getenv("GOKMS_CBBUCKET")
	if cbbuket == "" {
		cbbuket = "kms"
	}

	cluster, err := gocb.Connect(cbhost)
	if err != nil {
		log.Println(fmt.Sprintf("Error getting bucket:  %v", err))
		return CouchbaseStorageProvider{}, err
	}

	bucket, err := cluster.OpenBucket(cbbuket, "")
	if err != nil {
		log.Println(fmt.Sprintf("Error getting bucket:  %v", err))
		return CouchbaseStorageProvider{}, err
	}

	bucket.SetOperationTimeout(30 * time.Second)

	return CouchbaseStorageProvider{bucket: bucket}, nil
}

// KeyIDList - A list of key IDs
type KeyIDList struct {
	KeyIDs []string
}

// SecretIDList - A list of secret IDs
type SecretIDList struct {
	SecretIDs []string
}

// SaveKey - Persist a key to disk
func (sp CouchbaseStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	keyPath := "gokms:key:" + keyID

	log.Printf("SaveKey: %v", keyPath)

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
	_, err := sp.bucket.Get("gokms:keylist", &keyList)

	log.Printf("Add key got keylist: %v", keyList)

	if err != nil {
		log.Printf("Error getting key list: %v", err)
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
		log.Printf("Adding key %v to key list", keyID)
		keyList.KeyIDs = append(keyList.KeyIDs, keyID)
	}

	log.Printf("Setting keylist: %v", keyList)

	// Preseve the key list
	_, err = sp.bucket.Upsert("gokms:keylist", keyList, 0)
	if err != nil {
		log.Printf("Error setting key list: %v", err)
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

	keyPath := "gokms:key:" + keyID

	log.Printf("GetKey: %v", keyPath)

	var data RawData
	_, err := sp.bucket.Get(keyPath, &data)

	// Get data...
	return data.Data, err
}

// ListCustomerKeyIDs - List available keys
func (sp CouchbaseStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {
	var keyList KeyIDList
	// Get key list
	_, err := sp.bucket.Get("gokms:keylist", &keyList)
	if err != nil {
		return nil, err
	}

	log.Printf("ListKeys keylist: %v", keyList)

	return keyList.KeyIDs, nil
}

// SaveSecret - Save a secret
func (sp CouchbaseStorageProvider) SaveSecret(ctx context.Context, secretID string, data []byte, overwrite bool) error {
	keyPath := "gokms:secret:" + secretID

	log.Printf("SaveSecret: %v", keyPath)

	if sp.bucket == nil {
		return errors.New("No couchbase bucket!")
	}

	cbdata := RawData{Data: data}

	if !overwrite {
		_, err := sp.bucket.Insert(keyPath, cbdata, 0)
		if err != nil {
			if err == gocb.ErrKeyExists {
				return errors.New("Already exists")
			}

			return err
		}
	} else {
		_, err := sp.bucket.Upsert(keyPath, cbdata, 0)
		if err != nil {
			return err
		}
	}

	var secretList SecretIDList
	// Get key list
	_, err := sp.bucket.Get("gokms:secretlist", &secretList)

	log.Printf("Add secret got secretlist: %v", secretList)

	if err != nil {
		log.Printf("Error getting secret list: %v", err)
		// We got an error.  If not found that is ok.
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			log.Println("Not found error... creating empty list")
			secretList = SecretIDList{SecretIDs: []string{}}
		} else {
			return err
		}
	}

	// Add the key id it not already there
	if !contains(secretList.SecretIDs, secretID) {
		log.Printf("Adding key %v to key list", secretID)
		secretList.SecretIDs = append(secretList.SecretIDs, secretID)
	}

	log.Printf("Setting keylist: %v", secretList)

	// Preseve the secret list
	_, err = sp.bucket.Upsert("gokms:secretlist", secretList, 0)
	if err != nil {
		log.Printf("Error setting secret list: %v", err)
	}

	return err
}

// GetSecret - Get a secret
func (sp CouchbaseStorageProvider) GetSecret(ctx context.Context, secretID string) ([]byte, error) {
	if sp.bucket == nil {
		return nil, errors.New("No couchbase bucket!")
	}

	secretPath := "gokms:secret:" + secretID

	log.Printf("GetSecret: %v", secretPath)

	var data RawData
	_, err := sp.bucket.Get(secretPath, &data)
	// Get data...
	return data.Data, err
}

// ListSecrets - list secrets
func (sp CouchbaseStorageProvider) ListSecrets(ctx context.Context) ([]string, error) {
	var secretList SecretIDList
	// Get key list
	_, err := sp.bucket.Get("gokms:secretlist", &secretList)
	if err != nil {
		return nil, err
	}

	log.Printf("ListSecrets secretlist: %v", secretList)

	return secretList.SecretIDs, nil
}

// RawData type for json marshalling
type RawData struct {
	Data []byte
}
