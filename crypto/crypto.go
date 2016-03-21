// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"io"

	"github.com/coreos/pkg/capnslog"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var log = capnslog.NewPackageLogger("github.com/keithballdotnet/arx", "crypto")

// AesGCMEncrypt Encrypt data using AES with the GCM cipher mode (Gives Confidentiality and Authenticity)
func AesGCMEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

// AesGCMDecrypt Decrypt data using AES with the GCM cipher mode (Gives Confidentiality and Authenticity)
func AesGCMDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("Data to decrypt is too small")
	}

	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GetPBKFS2AesKey will generate a AES key from a passphrase using PBKFS2
func GetPBKFS2AesKey(passphrase string, salt []byte) []byte {
	// Create key
	return pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha1.New)
}

// GetScryptAesKey will generate a AES key from a passphrase using Scrypt
func GetScryptAesKey(passphrase string, salt []byte) []byte {
	// Create key
	// 16384 -- The 2009 recommended value
	// 262144 -- The most common value used in 2015 for bitcoin wallets. ;) (Takes about 1 second on my MacBook Pro)
	key, _ := scrypt.Key([]byte(passphrase), salt, 262144, 8, 1, 32)
	return key
}

// GenerateSalt will generate and return a random salt
func GenerateSalt(length int) []byte {
	salt := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Errorf("Error reading random bytes: %v", err)
	}
	return salt
}

// GenerateAesKey will generate a new 32 byte key (Uses OS random source)
func GenerateAesKey() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Errorf("Error reading random bytes: %v", err)
	}

	return key
}
