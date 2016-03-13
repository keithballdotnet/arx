// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"fmt"
	"os"

	log "github.com/golang/glog"

	"github.com/keithballdotnet/arx/crypto"
	"golang.org/x/net/context"
)

// ArxMasterKeyProvider is an implementation of aquiring a MASTER key using a derived key
type ArxMasterKeyProvider struct {
	passphrase string
}

// NewArxMasterKeyProvider ...
func NewArxMasterKeyProvider() (*ArxMasterKeyProvider, error) {

	log.Infoln("Using ArxMasterKeyProvider...")

	passphrase := os.Getenv("ARX_PASSPHRASE")

	return &ArxMasterKeyProvider{passphrase: passphrase}, nil
}

// GetKey will return the master key
func (mkp ArxMasterKeyProvider) GetKey(ctx context.Context) ([]byte, error) {

	// Derive key from pass phrase
	if len([]rune(mkp.passphrase)) < 30 {
		return nil, fmt.Errorf("The pass phrase must be at least 30 characters long is only %v characters", len([]rune(mkp.passphrase)))
	}

	// The salt used for KDF
	var salt []byte

	salt, err := Storage.GetKey(ctx, "kms.salt")

	if err != nil {
		// Random 64 byte salt is recommended according to spec
		salt = crypto.GenerateSalt(64)

		err = Storage.SaveKey(ctx, "kms.salt", salt, false)
		if err != nil {
			return nil, fmt.Errorf("WriteFile() failed %s\n", err)
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
