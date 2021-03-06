// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"fmt"

	"github.com/keithballdotnet/arx/crypto"
	"golang.org/x/net/context"
)

// ArxMasterKeyProvider is an implementation of acquiring a MASTER key using a derived key
type ArxMasterKeyProvider struct {
	passphrase string
}

// NewArxMasterKeyProvider ...
func NewArxMasterKeyProvider(passphrase string) (*ArxMasterKeyProvider, error) {

	log.Infof("Using ArxMasterKeyProvider...")

	return &ArxMasterKeyProvider{passphrase: passphrase}, nil
}

// Passphrase sets the provider pass phrase
func (mkp *ArxMasterKeyProvider) Passphrase(passphrase string) {
	mkp.passphrase = passphrase
}

// GetKey will return the master key
func (mkp *ArxMasterKeyProvider) GetKey(ctx context.Context) ([]byte, error) {

	// Derive key from pass phrase
	if len([]rune(mkp.passphrase)) < 30 {
		return nil, fmt.Errorf("The passphrase must be at least 30 characters long is only %v characters. Set using -p.", len([]rune(mkp.passphrase)))
	}

	// The salt used for KDF
	var salt []byte

	salt, err := Storage.GetKey(ctx, "kms.salt")

	if err != nil {
		// Random 64 byte salt is recommended according to spec
		salt = crypto.GenerateSalt(64)

		err = Storage.SaveKey(ctx, "kms.salt", salt, false)
		if err != nil {
			return nil, fmt.Errorf("SaveKey() failed %s\n", err)
		}
	}

	// Get the derived key
	kdfKey := crypto.GetScryptAesKey(mkp.passphrase, salt)

	// Get the encrypted key
	encryptedKey, err := Storage.GetKey(ctx, "kms.master")

	if err == nil {
		decryptedData, err := crypto.AesGCMDecrypt(encryptedKey, kdfKey)
		if err != nil {
			return nil, fmt.Errorf("AesGCMDecrypt() failed %s\n", err)
		}

		return decryptedData, nil
	}

	// Create new aes key
	masterAesKey := crypto.GenerateAesKey()

	// Encrypt the master key and preserve it
	encryptedKey, err = crypto.AesGCMEncrypt(masterAesKey, kdfKey)
	if err != nil {
		return nil, fmt.Errorf("AesGCMEncrypt() failed %s\n", err)
	}

	err = Storage.SaveKey(ctx, "kms.master", encryptedKey, false)
	if err != nil {
		return nil, fmt.Errorf("SaveKey() failed %s\n", err)
	}

	return masterAesKey, nil
}
