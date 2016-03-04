// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

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
		log.Printf("Error reading random bytes: %v", err)
	}
	return salt
}

// GenerateAesKey will generate a new 32 byte key (Uses OS random source)
func GenerateAesKey() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Printf("Error reading random bytes: %v", err)
	}

	return key
}

// Which curve should be used?  P521 is considered a SafeCurve...
//  http://safecurves.cr.yp.to/
//  http://infosecurity.ch/20100926/not-every-elliptic-curve-is-the-same-trough-on-ecc-security/
//  http://www.hyperelliptic.org/tanja/vortraege/20130531.pdf

// GenerateECDSAKey will create a new ECDSA key that can be used for signing and verifying data
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

// ECDSASign will sign a block of data.  This should be a hash from data
func ECDSASign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, priv, data)
	if err != nil {
		return nil, err
	}

	encodedPub, err := ECDSAEncodePublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Create signature
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	// Pack into sig, the public key and the sig values
	if err := enc.Encode([][]byte{encodedPub, r.Bytes(), s.Bytes()}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ECDSAVerify will verify a block of data with the passed values
func ECDSAVerify(data []byte, sig []byte) bool {

	// Unpack sig
	var unpackedSig [][]byte
	dec := json.NewDecoder(bytes.NewBuffer(sig))
	if err := dec.Decode(&unpackedSig); err != nil {
		log.Printf("Error decoding signature: %v", err)
	}

	// Extract public key from sig
	publicKey, err := ECDSADecodePublicKey(unpackedSig[0])
	if err != nil {
		return false
	}

	// Get S & R
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(unpackedSig[1])
	s.SetBytes(unpackedSig[2])

	// Now verify values
	return ecdsa.Verify(publicKey, data, r, s)
}

// ECDSAEncodePrivateKey will encode a private key to bytes
func ECDSAEncodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	err := enc.Encode([]big.Int{*key.X, *key.Y, *key.D})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ECDSADecodePrivateKey will decode a private key from bytes
func ECDSADecodePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	var p []big.Int
	buf := bytes.NewBuffer(b)
	dec := json.NewDecoder(buf)
	err := dec.Decode(&p)
	if err != nil {
		return nil, err
	}
	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = elliptic.P521()
	privateKey.PublicKey.X = &p[0]
	privateKey.PublicKey.Y = &p[1]
	privateKey.D = &p[2]
	return privateKey, nil
}

// ECDSAEncodePublicKey will encode a public key to bytes
func ECDSAEncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	err := enc.Encode([]big.Int{*key.X, *key.Y})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ECDSADecodePublicKey will decode a public key from bytes
func ECDSADecodePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	var p []big.Int
	buf := bytes.NewBuffer(b)
	dec := json.NewDecoder(buf)
	err := dec.Decode(&p)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P521(), X: &p[0], Y: &p[1]}, nil
}
