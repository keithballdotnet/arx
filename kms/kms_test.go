// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"bytes"
	"io/ioutil"
	"testing"

	"path/filepath"

	"github.com/stretchr/testify/require"
)

func SetUpCouchbaseProvider(t *testing.T) {

	var err error
	Storage, err = NewCouchbaseStorageProvider("", "")
	require.NoError(t, err)
	MasterKeyStore, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)
	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)
}

func TestCouchbaseProvider(t *testing.T) {

	SetUpCouchbaseProvider(t)
	defer Storage.Close()

	DoKMSTest(t)
}

func SetUpDiskProvider(t *testing.T) {

	temp, err := ioutil.TempDir("", "kms_test")
	require.NoError(t, err)

	Storage, err = NewDiskStorageProvider(temp)
	require.NoError(t, err)
	MasterKeyStore, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)
	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)
}

func TestDiskProvider(t *testing.T) {

	SetUpDiskProvider(t)
	defer Storage.Close()

	DoKMSTest(t)
}

func SetUpBoltDBProvider(t *testing.T) {
	temp, err := ioutil.TempDir("", "kms_test")

	Storage, err = NewBoltStorageProvider(filepath.Join(temp, "arx.db"))
	require.NoError(t, err)
	MasterKeyStore, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)
	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)
}

func TestBoltProvider(t *testing.T) {

	SetUpBoltDBProvider(t)
	defer Storage.Close()

	DoKMSTest(t)
}

func SetUpCassandraDBProvider(t *testing.T) {
	var err error
	Storage, err = NewCassandraStorageProvider("")
	require.NoError(t, err)
	MasterKeyStore, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)
	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)
}

func TestCassandraProvider(t *testing.T) {

	t.Skip("Not atm")
	SetUpCassandraDBProvider(t)
	defer Storage.Close()

	DoKMSTest(t)
}

func DoKMSTest(t *testing.T) {

	desc := "A new key description!"

	keyMetadata, err := KmsCrypto.CreateKey(nil, desc)
	require.NoError(t, err)

	t.Logf("KeyMetadata: %v", keyMetadata)

	require.True(t, desc == keyMetadata.Description)
	require.True(t, keyMetadata.Enabled)
	require.True(t, keyMetadata.KeyID != "")

	key, err := KmsCrypto.GetKey(nil, keyMetadata.KeyID)
	require.NoError(t, err)

	t.Logf("key: %v", key)

	// Ensure key is 32 bytes
	require.True(t, len(key.GetLatest()) == 32)

	require.True(t, key.Metadata.Description == desc)

	require.True(t, key.Metadata.Enabled)

	keyList, err := KmsCrypto.ListKeys(nil)
	require.NoError(t, err)

	keyFoundInList := false

	t.Logf("Looking for key %v", keyMetadata.KeyID)

	for _, k := range keyList {
		if k.KeyID == keyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}
	t.Logf("Keys: %v", keyList)

	require.True(t, keyFoundInList)

	err = KmsCrypto.RotateKey(nil, keyMetadata.KeyID)
	require.NoError(t, err)

	err = KmsCrypto.RotateKey(nil, keyMetadata.KeyID)
	require.NoError(t, err)

	key, err = KmsCrypto.GetKey(nil, keyMetadata.KeyID)
	require.NoError(t, err)

	require.True(t, len(key.Versions) == 3)

	keyOne := key.GetVersion(1)
	keyTwo := key.GetVersion(2)
	keyThree := key.GetVersion(3)

	require.False(t, bytes.Equal(keyOne, keyTwo))
	require.False(t, bytes.Equal(keyTwo, keyThree))
	require.False(t, bytes.Equal(keyOne, keyThree))

	latestVersion := key.GetLatestVersion()
	require.True(t, latestVersion == 3)

	latestKey := key.GetLatest()

	require.True(t, bytes.Equal(latestKey, keyThree))

	// Encrypt & Decrypt

	quote := "Every moment think steadily as a Roman and a man to do what thou hast in hand with perfect and simple dignity, and feeling of affection, and freedom, and justice; and to give thyself relief from all other thoughts."
	plainText := []byte(quote)

	ciphertextBlob, err := KmsCrypto.Encrypt(nil, plainText, keyMetadata.KeyID)
	require.NoError(t, err)
	require.NotEqual(t, plainText, ciphertextBlob)

	plainTextUnEnc, keyID, err := KmsCrypto.Decrypt(nil, ciphertextBlob)
	require.NoError(t, err)
	require.Equal(t, plainText, plainTextUnEnc)
	require.Equal(t, keyMetadata.KeyID, keyID)

	// No key
	_, err = KmsCrypto.Encrypt(nil, plainText, "non-existing key")
	require.Error(t, err)

	keyMetadata2, err := KmsCrypto.CreateKey(nil, "key 2")
	require.True(t, err == nil)

	quote2 := "Since it is possible that thou mayest depart from life this very moment, regulate every act and thought accordingly."
	plainText2 := []byte(quote2)

	ciphertextBlob2, err := KmsCrypto.Encrypt(nil, plainText2, keyMetadata.KeyID)
	require.NoError(t, err)
	require.NotEqual(t, plainText2, ciphertextBlob2)
	require.NotEqual(t, plainText2, ciphertextBlob)
	// Different text, same key
	require.NotEqual(t, ciphertextBlob, ciphertextBlob2)

	ciphertextBlob3, err := KmsCrypto.Encrypt(nil, plainText, keyMetadata2.KeyID)
	require.NoError(t, err)
	require.NotEqual(t, plainText, ciphertextBlob)
	// Same text, different key..
	require.NotEqual(t, ciphertextBlob, ciphertextBlob3)

	ciphertextBlob4, sourceKeyID, err := KmsCrypto.ReEncrypt(nil, ciphertextBlob, keyMetadata2.KeyID)
	require.NoError(t, err)
	require.Equal(t, keyMetadata.KeyID, sourceKeyID)
	require.NotEqual(t, ciphertextBlob, ciphertextBlob4)

	plainTextUnEnc2, _, err := KmsCrypto.Decrypt(nil, ciphertextBlob4)
	require.NoError(t, err)
	require.Equal(t, plainText, plainTextUnEnc2)

	disKey2, err := KmsCrypto.DisableKey(nil, keyMetadata2.KeyID)
	require.NoError(t, err)
	require.False(t, disKey2.Enabled)

	// Disabled key
	_, err = KmsCrypto.Encrypt(nil, plainText, keyMetadata2.KeyID)
	require.Error(t, err)

	_, _, err = KmsCrypto.Decrypt(nil, ciphertextBlob4)
	require.Error(t, err)

	disKey3, err := KmsCrypto.EnableKey(nil, keyMetadata2.KeyID)
	require.NoError(t, err)
	require.True(t, disKey3.Enabled)

	// Re-enabled key
	_, err = KmsCrypto.Encrypt(nil, plainText, keyMetadata2.KeyID)
	require.NoError(t, err)

	_, _, err = KmsCrypto.Decrypt(nil, ciphertextBlob4)
	require.NoError(t, err)
}

func TestFailingProviderMasterKey(t *testing.T) {
	var err error
	Storage, err = NewFailingStorageProvider()
	require.NoError(t, err)

	_, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)

	KmsCrypto, err = NewDefaultCryptoProvider()
	require.Error(t, err)
}

func SetUpFailingProvider(t *testing.T) {
	temp, err := ioutil.TempDir("", "kms_test")
	require.NoError(t, err)

	Storage, err = NewDiskStorageProvider(temp)
	require.NoError(t, err)

	MasterKeyStore, err = NewArxMasterKeyProvider("A long passphrase that will be used to generate the master key")
	require.NoError(t, err)

	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)

	Storage, err = NewFailingStorageProvider()
	require.NoError(t, err)
}

func TestFailingProvider(t *testing.T) {

	SetUpFailingProvider(t)
	defer Storage.Close()

	DoFailingKMSTest(t)
}

func DoFailingKMSTest(t *testing.T) {

	_, err := KmsCrypto.CreateKey(nil, "bleh")
	require.Error(t, err)

	_, err = KmsCrypto.GetKey(nil, "some key")
	require.Error(t, err)

	_, err = KmsCrypto.ListKeys(nil)
	require.Error(t, err)

	err = KmsCrypto.RotateKey(nil, "some key")
	require.Error(t, err)

	quote := "Every moment think steadily as a Roman and a man to do what thou hast in hand with perfect and simple dignity, and feeling of affection, and freedom, and justice; and to give thyself relief from all other thoughts."
	plainText := []byte(quote)
	ciphertextBlob := []byte("Do wrong to thyself, do wrong to thyself, my soul; but thou wilt no longer have the opportunity of honouring thyself.")

	_, err = KmsCrypto.Encrypt(nil, plainText, "some key")
	require.Error(t, err)

	_, _, err = KmsCrypto.Decrypt(nil, ciphertextBlob)
	require.Error(t, err)

	_, _, err = KmsCrypto.ReEncrypt(nil, ciphertextBlob, "some key")
	require.Error(t, err)

	_, _, err = KmsCrypto.Decrypt(nil, ciphertextBlob)
	require.Error(t, err)

	_, err = KmsCrypto.DisableKey(nil, "some key")
	require.Error(t, err)
}
