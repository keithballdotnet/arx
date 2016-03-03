package kms

import (
	"sort"
	"time"
)

// Type of key
var (
	CustomerAESKeyType   = "aes"
	MasterKeyType        = "masterkey"
	CustomerECDSAKeyType = "ecdsa"
)

// Key is a represention of a key
type Key struct {
	Metadata KeyMetadata
	Versions []KeyVersion
}

// KeyMetadata is the associated meta data of any key
type KeyMetadata struct {
	KeyID        string
	CreationDate time.Time
	Description  string
	Enabled      bool
	KeyType      string
}

// KeyVersion is a version of a key
type KeyVersion struct {
	Version int
	Key     []byte
}

// Secret is a representation of a secret
type Secret struct {
	SecretID string
	Secret   []byte
}

// GetLatest will return the latest available key
func (key *Key) GetLatest() []byte {
	sort.Sort(KeyByVersion(key.Versions))

	return key.Versions[len(key.Versions)-1].Key
}

// GetLatestVersion will return the latest version number
func (key *Key) GetLatestVersion() int {
	sort.Sort(KeyByVersion(key.Versions))

	return key.Versions[len(key.Versions)-1].Version
}

// GetVersion will return a specific versioned key
func (key *Key) GetVersion(version int) []byte {
	return key.Versions[version-1].Key
}

// KeyByVersion - Will sort the Keys by Version (highest version at top i.e. Version 5 will be 4 in index, v3 index 2)
type KeyByVersion []KeyVersion

func (a KeyByVersion) Len() int      { return len(a) }
func (a KeyByVersion) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a KeyByVersion) Less(i, j int) bool {
	return a[i].Version < a[j].Version
}
