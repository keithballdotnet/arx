// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/keithballdotnet/arx/crypto"

	"github.com/stretchr/testify/require"
)

func SetUpSuite(t *testing.T) {

	err := os.Setenv("GOKMS_HSM_SLOT_PASSWORD", "1234")
	require.NoError(t, err)

	err = os.Setenv("GOKMS_PASSPHRASE", "A long passphrase that will be used to generate the master key")
	require.NoError(t, err)
	temp, err := ioutil.TempDir("", "kms_test")
	err = os.Setenv("GOKMS_PATH", temp)
	require.NoError(t, err)

	// Need to be set to pass test
	err = os.Setenv("GOKMS_SSL_CERT", "../files/auth.key")
	require.NoError(t, err)
	err = os.Setenv("GOKMS_SSL_KEY", "../files/auth.key")
	require.NoError(t, err)

	//os.Setenv("GOKMS_STORAGE_PROVIDER", "disk")
	err = os.Setenv("GOKMS_STORAGE_PROVIDER", "disk")
	require.NoError(t, err)

	err = os.Setenv("GOKMS_AUTH_KEY", "e7yflbeeid26rredmwtbiyzxijzak6altcnrsi4yol2f5sexbgdwevlpgosfoeyy")
	require.NoError(t, err)

	Storage, err = NewDiskStorageProvider()
	require.NoError(t, err)
	MasterKeyStore, err = NewGoKMSMasterKeyProvider()
	require.NoError(t, err)
	KmsCrypto, err = NewDefaultCryptoProvider()
	require.NoError(t, err)
}

/*func TestHSMMasterKeyProvider(t *testing.T) {

	c.Skip("HSM must be set up for this test to work")

	os.Setenv("GOKMS_HSM_LIB", "/opt/nfast/toolkits/pkcs11/libcknfast.so")
	os.Setenv("GOKMS_HSM_SLOT", "0")
	os.Setenv("GOKMS_HSM_AES_KEYID", "My New AES Key")
	os.Setenv("GOKMS_KSMC_PATH", "/home/keithball/Documents/tokens")
	Config["GOKMS_KSMC_PATH"] = "/home/keithball/Documents/tokens"
	// Ensure we actually match the interface
	var mkp MasterKeyProvider
	mkp, err := NewHSMMasterKeyProvider()

	// Get key
	key, err := mkp.GetKey()

	// No error
	require.True(t, err == nil)

	// Ensure key is 32 bytes
	require.True(t, len(key) == 32)

	fmt.Printf("Key is: %v %v", key, string(key))
}*/

func TestCreateECDSAKeyThenGetKeyListKeysAndCheckKeyIsThere(t *testing.T) {

	SetUpSuite(t)

	desc := "A new key description!"

	keyType := "ecdsa"

	keyMetadata, err := KmsCrypto.CreateKey(nil, desc, keyType)

	// No error
	require.True(t, err == nil)

	require.True(t, desc == keyMetadata.Description)
	require.True(t, keyMetadata.Enabled)
	require.True(t, keyMetadata.KeyID != "")

	key, err := KmsCrypto.GetKey(nil, keyMetadata.KeyID)

	// No error
	require.True(t, err == nil)

	// Ensure key can be decoded
	_, err = crypto.ECDSADecodePrivateKey(key.GetLatest())
	require.True(t, err == nil)

	require.True(t, key.Metadata.Description == desc)

	require.True(t, key.Metadata.Enabled)

	require.True(t, key.Metadata.KeyType == keyType)

	keyList, err := KmsCrypto.ListKeys(nil)

	// No error
	require.True(t, err == nil)

	keyFoundInList := false

	for _, k := range keyList {
		if k.KeyID == keyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}

	require.True(t, keyFoundInList)
}

func TestCreateAESKeyThenGetKeyListKeysAndCheckKeyIsThere(t *testing.T) {

	SetUpSuite(t)

	desc := "A new key description!"

	keyType := "aes"

	keyMetadata, err := KmsCrypto.CreateKey(nil, desc, keyType)

	// No error
	require.True(t, err == nil)

	require.True(t, desc == keyMetadata.Description)
	require.True(t, keyMetadata.Enabled)
	require.True(t, keyMetadata.KeyID != "")

	key, err := KmsCrypto.GetKey(nil, keyMetadata.KeyID)

	// No error
	require.True(t, err == nil)

	// Ensure key is 32 bytes
	require.True(t, len(key.GetLatest()) == 32)

	require.True(t, key.Metadata.Description == desc)

	require.True(t, key.Metadata.Enabled)

	require.True(t, key.Metadata.KeyType == keyType)

	keyList, err := KmsCrypto.ListKeys(nil)

	// No error
	require.True(t, err == nil)

	keyFoundInList := false

	for _, k := range keyList {
		if k.KeyID == keyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}

	require.True(t, keyFoundInList)

	err = KmsCrypto.RotateKey(nil, keyMetadata.KeyID)

	// No error
	require.True(t, err == nil)

	err = KmsCrypto.RotateKey(nil, keyMetadata.KeyID)

	// No error
	require.True(t, err == nil)

	key, err = KmsCrypto.GetKey(nil, keyMetadata.KeyID)

	// No error
	require.True(t, err == nil)

	require.True(t, len(key.Versions) == 3)

	keyOne := key.GetVersion(1)
	keyTwo := key.GetVersion(2)
	keyThree := key.GetVersion(3)

	require.False(t, bytes.Equal(keyOne, keyTwo))
	require.False(t, bytes.Equal(keyTwo, keyThree))
	require.False(t, bytes.Equal(keyOne, keyThree))

	latestVersion := key.GetLatestVersion()
	// No error
	require.True(t, latestVersion == 3)

	latestKey := key.GetLatest()

	require.True(t, bytes.Equal(latestKey, keyThree))
}

/*func TestRESTSecretInterfaceFunctions(t *testing.T) {

	SetUpSuite(t)

	//context := AuthContext{UserAgent: "KMS Test Agent"}

	secretID := "ThisIsASuperSecret"
	secretValue := []byte("There is no mistake; there has been no mistake; and there shall be no mistake.")

	setSecretRequest := SetSecretRequest{Value: secretValue}

	u := url.URL{Path: fmt.Sprintf("/api/v1/go-kms/secret/%v", secretID)}
	ur := u.Query()
	ur.Set("SecretID", secretID)
	u.RawQuery = ur.Encode()
	r := http.Request{Header: http.Header{"accept": {"application/json"}}}
	request := SetAuth(&r, "POST", u.Path)

	status, _, setSecretReponse, err := setSecretHandler(&u, request.Header, &setSecretRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	require.True(t, setSecretReponse.SecretID == secretID)

	require.True(t, bytes.Equal(setSecretReponse.Value, secretValue))

	u = url.URL{Path: fmt.Sprintf("/api/v1/go-kms/secret/%v", secretID)}
	ur = u.Query()
	ur.Set("SecretID", secretID)
	u.RawQuery = ur.Encode()
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "GET", u.Path)

	status, _, getSecretReponse, err := getSecretHandler(&u, request.Header, nil, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	require.True(t, getSecretReponse.SecretID == secretID)

	require.True(t, bytes.Equal(getSecretReponse.Value, secretValue))

	u = url.URL{Path: "/api/v1/go-kms/secrets"}
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "GET", u.Path)

	status, _, listSecretsReponse, err := listSecretsHandler(&u, request.Header, nil, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	keyFoundInList := false

	for _, sid := range listSecretsReponse.SecretIDs {
		if sid == secretID {
			keyFoundInList = true
			break
		}
	}

	require.True(t, keyFoundInList)

	/* Trying to add the same secret again should fail * /

	u = url.URL{Path: fmt.Sprintf("/api/v1/go-kms/secret/%v", secretID)}
	ur = u.Query()
	ur.Set("SecretID", secretID)
	u.RawQuery = ur.Encode()
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "POST", u.Path)

	status, _, setSecretReponse, err = setSecretHandler(&u, request.Header, &setSecretRequest, &context)
	require.NoError(t, err)

	// Status
	require.True(t, status == http.StatusConflict)

}

func TestRESTKeyInterfaceFunctions(t *testing.T) {

	SetUpSuite(t)

	// Create temporary store for keys during test
	Config["GOKMS_KSMC_PATH"] = test.MkDir()

	context := AuthContext{UserAgent: "KMS Test Agent"}

	request := GetRequest("/api/v1/go-kms/createkey", "POST")

	u := url.URL{Path: "/api/v1/go-kms/"}

	description := "Test Encryption Key"

	createKeyRequest := rest.CreateKeyRequest{Description: description}

	status, _, createKeyResponse, err := createKeyHandler(&u, request.Header, &createKeyRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Ensure the key is enabled
	require.True(t, createKeyResponse.KeyMetadata.Enabled)

	// Check the description is correct
	require.True(t, createKeyResponse.KeyMetadata.Description == description)

	request = GetRequest("/api/v1/go-kms/listkeys", "POST")

	listKeysRequest := rest.ListKeysRequest{}

	status, _, listKeysResponse, err := listKeysHandler(&u, request.Header, &listKeysRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Assert the key is listed
	keyFoundInList := false

	for _, k := range listKeysResponse.KeyMetadata {
		if k.KeyID == createKeyResponse.KeyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}

	require.True(t, keyFoundInList)

	request = GetRequest("/api/v1/go-kms/generatedatakey", "POST")

	dataKeyRequest := rest.GenerateDataKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, dataKeyResponse, err := generateDataKeyHandler(&u, request.Header, &dataKeyRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Want a 32 byte AES Key
	require.True(t, len(dataKeyResponse.Plaintext) == 32)

	aesKey := dataKeyResponse.Plaintext

	// Ensure the data is different
	require.False(t, bytes.Equal(dataKeyResponse.Plaintext, dataKeyResponse.CiphertextBlob))

	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest := rest.DecryptRequest{CiphertextBlob: dataKeyResponse.CiphertextBlob}

	status, _, decryptResponse, err := decryptHandler(&u, request.Header, &decryptRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Want a 32 byte AES Key
	require.True(t, len(decryptResponse.Plaintext) == 32)

	// Ensure decrypted key is the same as the key we go via plain text
	require.True(t, bytes.Equal(decryptResponse.Plaintext, aesKey))

	request = GetRequest("/api/v1/go-kms/encrypt", "POST")

	somePlaintext := []byte("Kaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahn!")

	encryptRequest := rest.EncryptRequest{KeyID: createKeyResponse.KeyMetadata.KeyID, Plaintext: somePlaintext}

	status, _, encryptResponse, err := encryptHandler(&u, request.Header, &encryptRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Ensure we have some data
	require.True(t, len(encryptResponse.CiphertextBlob) > 0)

	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest = rest.DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure decrypted key is the same as the key we go via plain text
	require.True(t, bytes.Equal(decryptResponse.Plaintext, somePlaintext))

	// Disable the key and try to decrypt again
	request = GetRequest("/api/v1/go-kms/disablekey", "POST")

	disableKeyRequest := rest.DisableKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, disableKeyResponse, err := disableKeyHandler(&u, request.Header, &disableKeyRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	require.False(t, disableKeyResponse.KeyMetadata.Enabled)

	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest = rest.DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	require.False(t, status == http.StatusOK)

	request = GetRequest("/api/v1/go-kms/enablekey", "POST")

	enableKeyRequest := rest.EnableKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, enableKeyResponse, err := enableKeyHandler(&u, request.Header, &enableKeyRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	require.True(t, enableKeyResponse.KeyMetadata.Enabled)

	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest = rest.DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure decrypted key is the same as the key we go via plain text
	require.True(t, bytes.Equal(decryptResponse.Plaintext, somePlaintext))

	request = GetRequest("/api/v1/go-kms/createkey", "POST")

	description2 := "II Test Encryption Key"

	createKeyRequest2 := rest.CreateKeyRequest{Description: description2}

	status, _, createKeyResponse2, err := createKeyHandler(&u, request.Header, &createKeyRequest2, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure the key is enabled
	require.True(t, createKeyResponse2.KeyMetadata.Enabled)

	// Check the description is correct
	require.True(t, createKeyResponse2.KeyMetadata.Description == description2)

	request = GetRequest("/api/v1/go-kms/reencrypt", "POST")

	reEncryptRequest := rest.ReEncryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob, DestinationKeyID: createKeyResponse2.KeyMetadata.KeyID}

	status, _, reEncryptResponse, err := reEncryptHandler(&u, request.Header, &reEncryptRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure the key was encrypted with the original key
	require.True(t, reEncryptResponse.SourceKeyID == createKeyResponse.KeyMetadata.KeyID)

	// Ensure data is now encrypted with the new key
	require.True(t, reEncryptResponse.KeyID == createKeyResponse2.KeyMetadata.KeyID)

	// Ensure that the encrypted data has changed
	require.False(t, bytes.Equal(reEncryptResponse.CiphertextBlob, encryptResponse.CiphertextBlob))

	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest = rest.DecryptRequest{CiphertextBlob: reEncryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure decrypted key is the same as the key we go via plain text
	require.True(t, bytes.Equal(decryptResponse.Plaintext, somePlaintext))

	// Rotate the key....
	request = GetRequest("/api/v1/go-kms/rotatekey", "POST")

	rotateKeyRequest := rest.RotateKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, rotateKeyResponse, err := rotateKeyHandler(&u, request.Header, &rotateKeyRequest, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)
	require.True(t, rotateKeyResponse.Success)

	// Now lets do the encrytion again...
	request = GetRequest("/api/v1/go-kms/encrypt", "POST")

	encryptRequest2 := rest.EncryptRequest{KeyID: createKeyResponse.KeyMetadata.KeyID, Plaintext: somePlaintext}

	status, _, encryptResponse2, err := encryptHandler(&u, request.Header, &encryptRequest2, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Ensure we have some data
	require.True(t, len(encryptResponse2.CiphertextBlob) > 0)

	// Encrypt with the same key but thanks to rotation we should get new bytes
	require.False(t, bytes.Equal(encryptResponse2.CiphertextBlob, encryptResponse.CiphertextBlob))

	// Decrypt of the data with the old key should still work...
	request = GetRequest("/api/v1/go-kms/decrypt", "POST")

	decryptRequest2 := rest.DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse2, err := decryptHandler(&u, request.Header, &decryptRequest2, &context)

	require.True(t, err == nil)
	require.True(t, status == http.StatusOK)

	// Ensure decrypted key is the same as the key we go via plain text
	require.True(t, bytes.Equal(decryptResponse2.Plaintext, somePlaintext))

	request = GetRequest("/api/v1/go-kms/createkey", "POST")

	ecdsaDesc := "Signing Key"

	createKeyRequest = rest.CreateKeyRequest{Description: ecdsaDesc, KeyType: CustomerECDSAKeyType}

	status, _, createKeyResponse, err = createKeyHandler(&u, request.Header, &createKeyRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Ensure the key is enabled
	require.True(t, createKeyResponse.KeyMetadata.Enabled)

	// Check the description is correct
	require.True(t, createKeyResponse.KeyMetadata.Description == ecdsaDesc)

	require.True(t, createKeyResponse.KeyMetadata.KeyType == CustomerECDSAKeyType)

	hash := []byte("This is not really a hash")

	request = GetRequest("/api/v1/go-kms/sign", "POST")

	signRequest := rest.SignRequest{KeyID: createKeyResponse.KeyMetadata.KeyID, Hashdata: hash}

	status, _, signResponse, err := signHandler(&u, request.Header, &signRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	// Make sure we go something back
	require.True(t, len(signResponse.Signature) > 0)

	request = GetRequest("/api/v1/go-kms/verify", "POST")

	verifyRequest := rest.VerifyRequest{Hashdata: hash, Signature: signResponse.Signature}

	status, _, verifyResponse, err := verifyHandler(&u, request.Header, &verifyRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	require.True(t, verifyResponse.Verified == true)

	hash2 := []byte("This is the wrong hash")

	verifyRequest = rest.VerifyRequest{Hashdata: hash2, Signature: signResponse.Signature}

	status, _, verifyResponse, err = verifyHandler(&u, request.Header, &verifyRequest, &context)

	// No error
	require.True(t, err == nil)

	// Status
	require.True(t, status == http.StatusOK)

	require.True(t, verifyResponse.Verified == false)

} */

func TestHMSEncryptDecrypt(t *testing.T) {

	t.Skip("No HSM test")

	SetUpSuite(t)

	data := crypto.GenerateAesKey()

	fmt.Printf("Encrypt data: %v len: %v ", string(data), len(data))

	encryptedData, err := KmsCrypto.Encrypt(nil, data, "Blocker_RSA4096_PubKey")

	fmt.Println("HSM encrypted bytes: " + string(encryptedData))

	// No error
	require.True(t, err == nil)

	decryptedData, _, err := KmsCrypto.Decrypt(nil, encryptedData)
	require.NoError(t, err)

	fmt.Println("HSM decrypted bytes: " + string(decryptedData))

	require.True(t, bytes.Equal(data, decryptedData))
}
