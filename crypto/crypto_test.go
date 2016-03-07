// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var input = []byte("it just works")
var md5Reference = []byte("qp\xbdZ\x9dSH\xe81\x10\x0fk\x81\xff\xda\xdc")

func TestHash(t *testing.T) {
	ourMd5 := ComputeMd5Checksum(input)
	require.Equal(t, md5Reference, ourMd5)

	require.True(t, ValidateMd5Checksum(input, md5Reference))
	require.True(t, ValidateMd5Checksum(input, ourMd5))

	// Fails...
	require.False(t, ValidateMd5Checksum(ourMd5, input))

	// No panic on empty
	require.False(t, ValidateMd5Checksum([]byte(""), []byte("")))

	ourSha256 := ComputeSha256Checksum(input)
	require.True(t, ValidateSha256Checksum(input, ourSha256))

	sha256AsString := GetSha256HashString(input)

	// Make sure not empty string
	require.True(t, sha256AsString != "")

	// Ensure is the same as out previous hash
	firstHashString := hex.EncodeToString(ourSha256)

	//c.Logf("Comparing %s to %s", firstHashString, sha256AsString)

	require.Equal(t, firstHashString, sha256AsString)
}

func TestGetRandomNumber(t *testing.T) {

	// Lets get a 6 digit number
	random := GetRandomInt(100000, 999999)

	require.True(t, random > 100000 && random < 999999)

}

func TestRandomSecret(t *testing.T) {

	secret := GetRandomString(0, "")

	require.True(t, secret != "")

}

var keyPassphrase = "It was the best of times, it was the worst of times."

func TestGenerateKeyFromPassphraseUsingPBKDF2(t *testing.T) {

	// Get a salt of 64 bytes
	salt := GenerateSalt(64)

	start := time.Now()
	aesKey := GetPBKFS2AesKey(keyPassphrase, salt)
	end := time.Now()

	fmt.Printf("GetPBKFS2AesKey took: %v\n", end.Sub(start))

	require.True(t, len(aesKey) == 32)

	fmt.Println("Aes Key from passphrase: " + string(aesKey))

	aesKey2 := GetPBKFS2AesKey(keyPassphrase, salt)

	fmt.Println("Aes Key 2 from passphrase: " + string(aesKey2))

	require.True(t, bytes.Equal(aesKey, aesKey2))

}

func TestGenerateKeyFromPassphraseUsingScrypt(t *testing.T) {

	salt := GenerateSalt(64)

	start := time.Now()
	aesKey := GetScryptAesKey(keyPassphrase, salt)
	end := time.Now()

	fmt.Printf("GetScryptAesKey took: %v Key: %v", end.Sub(start), string(aesKey))

	require.True(t, len(aesKey) == 32)
}

func TestAesGCMCrypto(t *testing.T) {

	encryptString := "I once had a girl, or should I say, she once had me."

	bytesToEncrypt := []byte(encryptString)

	fmt.Println("GCM bytes to encrypt: " + string(bytesToEncrypt))

	aesKey := GenerateAesKey()

	encryptedBytes, err := AesGCMEncrypt(bytesToEncrypt, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	require.True(t, err == nil)

	fmt.Println("GCM encrypted bytes: " + string(encryptedBytes))

	unencryptedBytes, err := AesGCMDecrypt(encryptedBytes, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	require.True(t, err == nil)

	fmt.Println("GCM Unencrypted bytes: " + string(unencryptedBytes))

	require.True(t, bytes.Equal(bytesToEncrypt, unencryptedBytes))
}

func TestHMACKey(t *testing.T) {

	expectedHmac := "RvPtP0QB7iIun1ehwheD4YUo7+fYfw7/ywl+HsC5Ddk="

	// The secret key
	secretKey := "e7yflbeeid26rredmwtbiyzxijzak6altcnrsi4yol2f5sexbgdwevlpgosfoeyy"
	method := "COPY"
	//date := time.Now().UTC().Format(time.RFC1123) // UTC time
	//fmt.Printf("Now: %s", date)
	date := "Wed, 28 Jan 2015 10:42:13 UTC"
	resource := "/api/v1/blocker/6f90d707-3b6a-4321-b32c-3c1d37915c1b"

	// Create auth request key
	authRequestKey := fmt.Sprintf("%s\n%s\n%s", method, date, resource)

	hmac := GetHmac256(authRequestKey, secretKey)

	// Test positive.
	require.True(t, expectedHmac == hmac)

	// Test negative.  (Resource and Data in wrong order)
	authRequestKey = fmt.Sprintf("%s\n%s\n%s", method, resource, date)

	hmac = GetHmac256(authRequestKey, secretKey)

	// Test positive.
	require.True(t, expectedHmac != hmac)
}
