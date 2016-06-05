// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"errors"
	"strings"

	"golang.org/x/net/context"

	"github.com/gocql/gocql"
)

/* Before you execute the program, Launch `cqlsh` and execute:
create keyspace arx with replication = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
create table arx.keys(id text, data blob, PRIMARY KEY(id));
create index on arx.keys(id);
*/

var keyspace = "arx"

// CassandraStorageProvider ...
type CassandraStorageProvider struct {
	session *gocql.Session
}

// NewCassandraStorageProvider ...
func NewCassandraStorageProvider(cassandradb string) (*CassandraStorageProvider, error) {

	if cassandradb == "" {
		cassandradb = "127.0.0.1"
	}

	cluster := gocql.NewCluster(cassandradb)
	cluster.Keyspace = keyspace
	cluster.ProtoVersion = 3
	session, err := cluster.CreateSession()

	if err != nil {
		log.Errorf("Error getting cassandra session:  %v", err)
		return nil, err
	}

	return &CassandraStorageProvider{session: session}, nil
}

// SaveKey - Persist a key
func (sp CassandraStorageProvider) SaveKey(ctx context.Context, keyID string, data []byte, overwrite bool) error {

	log.Infof("SaveKey: %v", keyID)

	// first check if key exists.  If so then bail...
	var id string

	exists := false
	if err := sp.session.Query(`SELECT id FROM keys WHERE id = ? LIMIT 1`,
		keyID).Consistency(gocql.One).Scan(&id); err != nil {
		if err.Error() != "not found" {
			return err
		}
	}
	if id != "" {
		exists = true
	}

	if exists && !overwrite {
		return errors.New("Already exists")
	}

	// Cassandra treats INSERT like an UPSERT, so lets just do an insert

	if err := sp.session.Query(`INSERT INTO keys (id, data) VALUES (?, ?)`,
		keyID, data).Exec(); err != nil {
		return err
	}

	return nil
}

// GetKey - Read a key from disk
func (sp CassandraStorageProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {

	log.Infof("GetKey: %v", keyID)

	var key []byte

	if err := sp.session.Query(`SELECT data FROM keys WHERE id = ? LIMIT 1`,
		keyID).Consistency(gocql.One).Scan(&key); err != nil {
		return nil, errors.New("Not found")
	}

	return key, nil
}

// ListCustomerKeyIDs - List available keys
func (sp CassandraStorageProvider) ListCustomerKeyIDs(ctx context.Context) ([]string, error) {

	log.Info("ListCustomerKeyIDs")

	var keyIDs []string
	var keyID string
	// list all ids
	iter := sp.session.Query(`SELECT id FROM keys`).Iter()
	for iter.Scan(&keyID) {
		log.Infof("key=%s\n", keyID)
		// Do not add salts to list of stored keys
		if strings.HasSuffix(keyID, ".salt") || strings.HasSuffix(keyID, ".master") {
			continue
		}

		keyIDs = append(keyIDs, keyID)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}

	return keyIDs, nil
}

// Close will do nothing
func (sp CassandraStorageProvider) Close() {
	sp.session.Close()
}
