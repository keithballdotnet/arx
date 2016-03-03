package kms

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/keithballdotnet/arx/crypto"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"
)

// encryptedKeyLength is the length of key id encrypted using AES256-GCM
var encryptedKeyLength = 70

// DefaultCryptoProvider is an implementation of encryption using a local storage
// GOLINT will complain about this here, but DefaultCryptoProvider is correct as
// it differenciates between KMS and HSM crypto
type DefaultCryptoProvider struct {
	MasterKey []byte
}

// NewDefaultCryptoProvider ...
func NewDefaultCryptoProvider() (DefaultCryptoProvider, error) {
	log.Println("Using KMS crypto provider...")

	key, err := MasterKeyStore.GetKey(nil)
	if err != nil {
		return DefaultCryptoProvider{}, errors.New("unable to get master key")
	}

	return DefaultCryptoProvider{MasterKey: key}, nil
}

// EnableKey - will mark a key as enabled
func (cp DefaultCryptoProvider) EnableKey(ctx context.Context, KeyID string) (KeyMetadata, error) {
	key, err := cp.GetKey(ctx, KeyID)
	if err != nil {
		return KeyMetadata{}, err
	}

	key.Metadata.Enabled = true

	err = cp.SaveKey(ctx, key, true)

	if err != nil {
		return KeyMetadata{}, err
	}

	return key.Metadata, nil
}

// DisableKey - will mark a key as disabled
func (cp DefaultCryptoProvider) DisableKey(ctx context.Context, KeyID string) (KeyMetadata, error) {
	key, err := cp.GetKey(ctx, KeyID)
	if err != nil {
		return KeyMetadata{}, err
	}

	key.Metadata.Enabled = false

	err = cp.SaveKey(ctx, key, true)

	if err != nil {
		return KeyMetadata{}, err
	}

	return key.Metadata, nil
}

// ListKeys will list the available keys
func (cp DefaultCryptoProvider) ListKeys(ctx context.Context) ([]KeyMetadata, error) {

	// Create slice of metadata to return
	var metadata []KeyMetadata

	keyLists, err := Storage.ListCustomerKeyIDs(ctx)
	if err != nil {
		return metadata, nil
	}

	for _, keyID := range keyLists {
		key, err := cp.GetKey(ctx, keyID)
		if err != nil {
			log.Printf("ListKeys() got problem getting key %s: %v\n", keyID, err)
		} else {
			metadata = append(metadata, key.Metadata)
		}
	}

	return metadata, nil
}

// CreateKey will create a new key
func (cp DefaultCryptoProvider) CreateKey(ctx context.Context, description string, keyType string) (KeyMetadata, error) {

	// Create a new key id
	keyID := uuid.NewV4().String()

	newKeyType := "aes"
	if keyType != "" {
		newKeyType = keyType
	}

	// Create metadata
	keyMetadata := KeyMetadata{
		KeyID:        keyID,
		Description:  description,
		CreationDate: time.Now().UTC(),
		Enabled:      true,
		KeyType:      newKeyType,
	}

	encKey := []byte{}

	// Create a new secret key
	if newKeyType == CustomerAESKeyType {
		encKey = crypto.GenerateAesKey()
	} else if newKeyType == CustomerECDSAKeyType {
		priv, _ := crypto.GenerateECDSAKey()
		encPriv, _ := crypto.ECDSAEncodePrivateKey(priv)
		encKey = encPriv
	} else {
		return KeyMetadata{}, errors.New("Unknown key type: " + keyType)
	}

	// Create new key object
	key := Key{Metadata: keyMetadata, Versions: []KeyVersion{{Version: 1, Key: encKey}}}

	// Persist the key to disk
	err := cp.SaveKey(ctx, key, false)
	if err != nil {
		return KeyMetadata{}, err
	}

	return keyMetadata, nil
}

// RotateKey will create a new version of a key while preserving the old key
func (cp DefaultCryptoProvider) RotateKey(ctx context.Context, KeyID string) error {

	key, err := cp.GetKey(ctx, KeyID)
	if err != nil {
		return err
	}

	// Only AES keys can be rotated
	if key.Metadata.KeyType != CustomerAESKeyType {
		return errors.New("Only AES key rotation is supported")
	}

	// Support per key a maximum of 99999 rotations...
	// Why?  To place the version into the key id, and maintain the envelope
	// I pad the version with 5 leading 0s.
	if key.GetLatestVersion() >= 99999 {
		return errors.New("Reached AES key rotation limit")
	}

	// Create new key version
	newKeyVersion := KeyVersion{Version: key.GetLatestVersion() + 1, Key: crypto.GenerateAesKey()}

	key.Versions = append(key.Versions, newKeyVersion)

	return cp.SaveKey(ctx, key, true)
}

// SaveKey will persist a key to disk
func (cp DefaultCryptoProvider) SaveKey(ctx context.Context, key Key, add bool) error {
	// JSON -> byte
	keyData, err := json.Marshal(key)
	if err != nil {
		return err
	}

	// Encrypt the key data with the user key and perist to disk..
	encryptedKey, err := crypto.AesGCMEncrypt(keyData, cp.MasterKey)
	if err != nil {
		return err
	}

	// Persist key to storage
	err = Storage.SaveKey(ctx, key.Metadata.KeyID, encryptedKey, add)
	if err != nil {
		return err
	}

	return nil
}

// GetKey from the the store
func (cp DefaultCryptoProvider) GetKey(ctx context.Context, KeyID string) (Key, error) {

	var err error
	encryptedKey := []byte{}

	// Read encrypted key from disk
	encryptedKey, err = Storage.GetKey(ctx, KeyID)
	if err != nil {
		log.Printf("GetKey() failed %s\n", err)
		return Key{}, err
	}

	// decrypt the data on disk with the users derived key
	decryptedData, err := crypto.AesGCMDecrypt(encryptedKey, cp.MasterKey)
	if err != nil {
		log.Printf("GetKey() failed %s\n", err)
		return Key{}, err
	}

	var key Key
	err = json.Unmarshal(decryptedData, &key)
	if err != nil {
		log.Printf("GetKey() failed %s\n", err)
		return Key{}, err
	}

	return key, nil
}

// Sign will sign data and return a signiture
func (cp DefaultCryptoProvider) Sign(ctx context.Context, data []byte, KeyID string) ([]byte, error) {

	key, err := cp.GetKey(ctx, KeyID)
	if err != nil {
		return nil, err
	}

	// Check to see if key is enabled
	if !key.Metadata.Enabled {
		return nil, errors.New("Key is not enabled!")
	}

	// Check if correct key type
	if key.Metadata.KeyType != CustomerECDSAKeyType {
		return nil, errors.New("Key can not be used for signing!")
	}

	// Decode key
	priv, err := crypto.ECDSADecodePrivateKey(key.GetLatest())
	if err != nil {
		return nil, err
	}

	// Sign the data
	return crypto.ECDSASign(priv, data)
}

// Verify will unpack a signiture and verify it
func (cp DefaultCryptoProvider) Verify(data []byte, sig []byte) (bool, error) {
	return crypto.ECDSAVerify(data, sig), nil
}

// ReEncrypt will decrypt with the current key, and rencrypt with the new key id
func (cp DefaultCryptoProvider) ReEncrypt(ctx context.Context, data []byte, KeyID string) ([]byte, string, error) {

	// Decrypt the data
	plaintext, sourceKeyID, err := cp.Decrypt(ctx, data)
	if err != nil {
		return nil, "", err
	}

	// Encrypt with the new key
	ciphertext, err := cp.Encrypt(ctx, plaintext, KeyID)
	if err != nil {
		return nil, "", err
	}

	// return encrypted data
	return ciphertext, sourceKeyID, nil
}

// Encrypt will encrypt the data using the HSM
func (cp DefaultCryptoProvider) Encrypt(ctx context.Context, data []byte, KeyID string) ([]byte, error) {

	key, err := cp.GetKey(ctx, KeyID)
	if err != nil {
		return nil, err
	}

	// Check to see if key is enabled
	if !key.Metadata.Enabled {
		return nil, errors.New("Key is not enabled!")
	}

	// Check if correct key type
	if key.Metadata.KeyType == CustomerECDSAKeyType {
		return nil, errors.New("Key can not be used for encryption!")
	}

	encryptedData, err := crypto.AesGCMEncrypt(data, key.GetLatest())
	if err != nil {
		return nil, err
	}

	keyID := fmt.Sprintf("%s#%05d", key.Metadata.KeyID, key.GetLatestVersion())

	// Encrypt the key ID and version used with the master key, so we can ID it later on
	encryptedKey, err := crypto.AesGCMEncrypt([]byte(keyID), cp.MasterKey)
	if err != nil {
		return nil, err
	}

	// Envelope the encrypted key with the encrypted data
	return append(encryptedKey, encryptedData...), nil
}

// Decrypt will decrypt the data using the HSM
func (cp DefaultCryptoProvider) Decrypt(ctx context.Context, data []byte) ([]byte, string, error) {

	// Find the encrypted key ID
	encryptedKey := data[:encryptedKeyLength]
	encryptedData := data[encryptedKeyLength:]

	// Decrypt the key ID used in the encryption
	keyID, err := crypto.AesGCMDecrypt(encryptedKey, cp.MasterKey)
	if err != nil {
		return nil, "", err
	}

	// Split KeyID and Key Version from package
	keyIDParts := strings.Split(string(keyID), "#")

	// Get the key
	key, err := cp.GetKey(ctx, keyIDParts[0])
	if err != nil {
		return nil, "", err
	}

	// Check to see if key is enabled
	if !key.Metadata.Enabled {
		return nil, "", errors.New("Key is not enabled!")
	}

	// Check if correct key type
	if key.Metadata.KeyType == CustomerECDSAKeyType {
		return nil, "", errors.New("Key can not be used for encryption!")
	}

	// Extract key version from id.
	keyVersion, _ := strconv.Atoi(keyIDParts[1])

	// Let's decrypt the data
	decryptedData, err := crypto.AesGCMDecrypt(encryptedData, key.GetVersion(keyVersion))
	if err != nil {
		log.Printf("Decrypt() failed %s\n", err)
		return nil, "", err
	}

	return decryptedData, key.Metadata.KeyID, nil
}

// GetSecret by name
func (cp DefaultCryptoProvider) GetSecret(ctx context.Context, secretID string) (Secret, error) {
	var err error

	// Read encrypted secret from disk
	encryptedSecret, err := Storage.GetSecret(ctx, secretID)
	if err != nil {
		log.Printf("GetSecret() failed %s\n", err)
		return Secret{}, err
	}

	// decrypt the data on disk with the master key
	decryptedData, err := crypto.AesGCMDecrypt(encryptedSecret, cp.MasterKey)
	if err != nil {
		log.Printf("GetSecret() failed %s\n", err)
		return Secret{}, err
	}

	var secret Secret
	err = json.Unmarshal(decryptedData, &secret)
	if err != nil {
		log.Printf("GetSecret() failed %s\n", err)
		return Secret{}, err
	}

	return secret, nil
}

// SetSecret by name
func (cp DefaultCryptoProvider) SetSecret(ctx context.Context, secretID string, data []byte, overwrite bool) error {

	if strings.TrimSpace(secretID) == "" {
		return errors.New("Empty secret ID")
	}

	// Create secret struct
	secret := Secret{SecretID: secretID, Secret: data}

	// JSON -> byte
	secretData, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	// Encrypt the secret data with the user key and perist to disk..
	encryptedSecret, err := crypto.AesGCMEncrypt(secretData, cp.MasterKey)
	if err != nil {
		return err
	}

	// Persist key to storage
	err = Storage.SaveSecret(ctx, secretID, encryptedSecret, overwrite)
	if err != nil {
		return err
	}

	return nil
}

// ListSecrets will list all available secrets
func (cp DefaultCryptoProvider) ListSecrets(ctx context.Context) ([]string, error) {
	return Storage.ListSecrets(ctx)
}
