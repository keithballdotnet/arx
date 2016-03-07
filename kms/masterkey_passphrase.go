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

// GoKMSMasterKeyProvider is an implementation of aquiring a MASTER key using a derived key
type GoKMSMasterKeyProvider struct {
	passphrase string
}

// NewGoKMSMasterKeyProvider ...
func NewGoKMSMasterKeyProvider() (GoKMSMasterKeyProvider, error) {

	log.Infoln("Using GoKMSMasterKeyProvider...")

	passphrase := os.Getenv("GOKMS_PASSPHRASE")

	return GoKMSMasterKeyProvider{passphrase: passphrase}, nil
}

// GetKey will return the master key
func (mkp GoKMSMasterKeyProvider) GetKey(ctx context.Context) ([]byte, error) {

	// Derive key from pass phrase
	if len(mkp.passphrase) < 30 {
		return nil, fmt.Errorf("The pass phrase must be at least 30 characters long is only %v characters", len(mkp.passphrase))
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

// HSMMasterKeyProvider is an implementation of aquiring a MASTER key using a connection to a Hardware Security Module
/*type HSMMasterKeyProvider struct {
}

// NewHSMMasterKeyProvider
func NewHSMMasterKeyProvider() (HSMMasterKeyProvider, error) {

	diagnostics.Debugln(nil, "Using HSMMasterKeyProvider...")

	envFiles := []string{"GOKMS_HSM_LIB"}

	providerConfig := map[string]string{
		"GOKMS_HSM_LIB":       "",
		"GOKMS_HSM_SLOT":      "0",
		"GOKMS_HSM_AES_KEYID": "",
		// "GOKMS_HSM_SLOT_PASSWORD": "",  // This can be skipped, if the TOKEN does not require a password.
	}

	// Ensure our config is ok...
	InitConfig(providerConfig, envFiles)

	return HSMMasterKeyProvider{}, nil
}

// GetKey will return the decrypted master key
func (mkp HSMMasterKeyProvider) GetKey() ([]byte, error) {

	// Set up pkcs11

	diagnostics.Debugf(ctx, "Using HSM Lib: %v", Config["GOKMS_HSM_LIB"])

	p := pkcs11.New(Config["GOKMS_HSM_LIB"])
	if p == nil {
		Exit("Failed to init lib", 2)
	}

	if err := p.Initialize(); err != nil {
		Exit(fmt.Sprintf("Initialize() failed %s\n", err), 2)
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	diagnostics.Debugf(ctx, "Using %v %v %v.%v", info.ManufacturerID, info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)

	slots, err := p.GetSlotList(true)
	if err != nil {
		Exit(fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	diagnostics.Debugf(ctx, "We have got %v slots", len(slots))
	if len(slots) == 0 {
		Exit("No HSM slots...", 2)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		Exit(fmt.Sprintf("OpenSession() failed %s\n", err), 2)
	}

	// Perhaps the HSM requires no pin
	if Config["GOKMS_HSM_SLOT_PIN"] != "" {
		err = p.Login(session, pkcs11.CKU_USER, Config["GOKMS_HSM_SLOT_PIN"])
		if err != nil {
			Exit(fmt.Sprintf("Login() failed %s\n", err), 2)
		}
		defer p.Logout(session)
	}

	defer p.Destroy()
	defer p.Finalize()
	defer p.CloseSession(session)

	// Locate desired key from the HSM

	diagnostics.Debugf(ctx, "Looking for hsm key: %v", Config["GOKMS_HSM_AES_KEYID"])

	// Create search index
	keySearch := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, Config["GOKMS_HSM_AES_KEYID"])}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		Exit(fmt.Sprintf("FindObjectsInit() failed %s\n", err), 2)
	}

	// Find the object
	obj, b, err := p.FindObjects(session, 1)
	if err != nil {
		Exit(fmt.Sprintf("FindObjects() failed %s %v\n", err, b), 2)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		Exit(fmt.Sprintf("FindObjectsFinal() failed %s\n", err), 2)
	}

	// Get the encrypted key
	encryptedKey, err := Storage.GetKey("kms.master")

	// Can we use the key?
	if err == nil {
		// Extract iv from encrypted key
		iv := encryptedKey[:aes.BlockSize]

		// Get the actual encrypted data
		encryptedData := encryptedKey[aes.BlockSize:]

		err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, obj[0])
		if err != nil {
			Exit(fmt.Sprintf("DecryptInit() failed %s\n", err), 2)
		}

		// Let's decrypt again
		decryptedData, err := p.Decrypt(session, encryptedData)
		if err != nil {
			Exit(fmt.Sprintf("Decrypt() failed %s\n", err), 2)
		}

		return decryptedData, nil
	}

	// Create new aes key
	masterAesKey, err := p.GenerateRandom(session, 32)
	if err != nil {
		Exit(fmt.Sprintf("GenerateRandom() failed %s\n", err), 2)
	}

	// Create iv
	iv, err := p.GenerateRandom(session, 16)
	if err != nil {
		Exit(fmt.Sprintf("GenerateRandom() failed %s\n", err), 2)
	}

	// Set up encryption
	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		Exit(fmt.Sprintf("AES EncryptInit() failed %s\n", err), 2)
	}

	encryptedData, err := p.Encrypt(session, masterAesKey)
	if err != nil {
		Exit(fmt.Sprintf("Encrypt() failed %s\n", err), 2)
	}

	// Create envelope
	encryptedKey = append(iv, encryptedData...)

	// Store key on disk
	err = Storage.SaveKey("kms.master", encryptedKey)
	if err != nil {
		Exit(fmt.Sprintf("WriteFile() failed %s\n", err), 2)
	}

	return masterAesKey, nil
}*/

/*  HSM - PKCS11 - Play ground code
func TestGetInfo(t *testing.T) {
	p := New("/opt/nfast/toolkits/pkcs11/libcknfast.so")
	if p == nil {
		diagnostics.Debugf(ctx, "Failed to init lib", 2)
	}

	if err := p.Initialize(); err != nil {
		diagnostics.Debugf(ctx,fmt.Sprintf("Initialize() failed %s\n", err), 2)
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	diagnostics.Debugf(ctx, "Using %v %v %v.%v", info.ManufacturerID, info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)

	slots, err := p.GetSlotList(true)
	if err != nil {
		diagnostics.Debugf(ctx,fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	diagnostics.Debugf(ctx, "We have got %v slots", len(slots))
	if len(slots) == 0 {
		diagnostics.Debugf(ctx, "No HSM slots...", 2)
	}

	slotInfo, err := p.GetSlotInfo(slots[0])
	if err != nil {
		diagnostics.Debugf(ctx,fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	diagnostics.Debugf(ctx, "Slot 0 Description: %v", slotInfo.SlotDescription)

	/*mechanisms, err := p.GetMechanismList(slots[0])
	if err != nil {
		panic(fmt.Sprintf("GetMechanismList() failed %s\n", err))
	}
	for i, m := range mechanisms {
		diagnostics.Debugf(ctx, "Mechanism %d, ID %d, Param %d", i, m.Mechanism, m.Parameter)
	}* /

	tokenInfo, err := p.GetTokenInfo(slots[0])
	if err != nil {
		panic(fmt.Sprintf("GetTokenInfo() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Token Info.Label: %v ", tokenInfo.Label)
	diagnostics.Debugf(ctx, "Token Info.FirmwareVersion: %v ", tokenInfo.FirmwareVersion)
	diagnostics.Debugf(ctx, "Token Info.ManufacturerID: %v ", tokenInfo.ManufacturerID)
	diagnostics.Debugf(ctx, "Token Info.SerialNumber: %v ", tokenInfo.SerialNumber)
	diagnostics.Debugf(ctx, "Token Info.MaxPinLen: %v ", tokenInfo.MaxPinLen)
	diagnostics.Debugf(ctx, "Token Info.Model: %v ", tokenInfo.Model)
	diagnostics.Debugf(ctx, "Token Info.MinPinLen: %v ", tokenInfo.MinPinLen)
	diagnostics.Debugf(ctx, "Token Info.HardwareVersion: %v ", tokenInfo.HardwareVersion)
	diagnostics.Debugf(ctx, "Token Info.MaxSessionCount: %v ", tokenInfo.MaxSessionCount)

	session, err := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		panic(fmt.Sprintf("OpenSession() failed %s\n", err))
	}

	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()

	/*err = p.Login(session, 0, "")
	if err != nil {
		panic(fmt.Sprintf("Login() failed %s\n", err))
	}* /

	// Create search index
	keySearch := []*Attribute{NewAttribute(CKA_LABEL, "GO-KMS Crypto Key")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("FindObjectsInit() failed %s\n", err))
	}

	// Find the object
	obj, b, err := p.FindObjects(session, 2)
	if err != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if err := p.FindObjectsFinal(session); err != nil {
		panic(fmt.Sprintf("FindObjectsFinal() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Found ojects: %v ", len(obj))

	var pubKey ObjectHandle
	var privKey ObjectHandle

	for i, key := range obj {
		diagnostics.Debugf(ctx, "Looking at item %v:", i)
		search := []*Attribute{
			NewAttribute(CKA_LABEL, nil),
			//NewAttribute(CKA_ENCRYPT, nil),
			//NewAttribute(CKA_VALUE_LEN, nil),
			NewAttribute(CKA_CLASS, nil),
		}
		// ObjectHandle two is the public key
		attr, err := p.GetAttributeValue(session, key, search)
		if err != nil {
			panic(fmt.Sprintf("GetAttributeValue() failed %s\n", err))
		}
		for i, a := range attr {
			// Found public key
			if a.Type == CKA_CLASS && bytes.Equal(a.Value, []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
				pubKey = key
			}

			// Found private key
			if a.Type == CKA_CLASS && bytes.Equal(a.Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}) {
				privKey = key
			}

			if a.Type == CKA_LABEL {
				diagnostics.Debugf(ctx, "Attr %d, type %d, valuelen %d, value %v", i, a.Type, len(a.Value), string(a.Value))
			} else {
				diagnostics.Debugf(ctx, "Attr %d, type %d, value %v", i, a.Type, a.Value)

			}
		}
	}

	diagnostics.Debugf(ctx, "Public Key: %v", pubKey)
	diagnostics.Debugf(ctx, "Priv Key: %v", privKey)

	err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS, nil)}, pubKey)

	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	data := []byte("There is nothing to fear but fear itself....")

	diagnostics.Debugf(ctx, "Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err := p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Result: %v len: %v ", string(encryptedData), len(encryptedData))

	err = p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS, nil)}, privKey)
	if err != nil {
		panic(fmt.Sprintf("DecryptInit() failed %s\n", err))
	}

	// Let's decrypt again
	decryptedData, err := p.Decrypt(session, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Decrypted Data: %v len: %v ", string(decryptedData), len(decryptedData))

	// Create search index
	keySearch = []*Attribute{NewAttribute(CKA_LABEL, "My New AES Key")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("FindObjectsInit() failed %s\n", err))
	}

	// Find the object
	obj, b, err = p.FindObjects(session, 2)
	if err != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(fmt.Sprintf("FindObjectsFinal() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Found ojects: %v ", len(obj))

	iv, err := p.GenerateRandom(session, 16)
	if err != nil {
		panic(fmt.Sprintf("GenerateRandom() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "IV: %v", iv)

	// Set up encryption
	err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		panic(fmt.Sprintf("AES EncryptInit() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Key Inited %v ", obj[0])

	data = []byte("Would the real slim shady please stand up!")

	diagnostics.Debugf(ctx, "Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err = p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "AES Result: %v len: %v ", string(encryptedData), len(encryptedData))

	err = p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		panic(fmt.Sprintf("DecryptInit() failed %s\n", err))
	}

	// Let's decrypt again
	decryptedData, err = p.Decrypt(session, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "AES Decrypted Data: %v len: %v ", string(decryptedData), len(decryptedData))

	/ *publicKeyTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{3}),
		NewAttribute(CKA_MODULUS_BITS, 4096),
		NewAttribute(CKA_LABEL, "Blocker_RSA4096_PubKey"),
	}
	privateKeyTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_LABEL, "Blocker_RSA4096_PrivKey"),
	}

	pub, priv, err := p.GenerateKeyPair(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKeyPair() failed %s\n", err))
	}

	diagnostics.Debugf(ctx, "Public Key: %v", pub)
	diagnostics.Debugf(ctx, "Priv Key: %v", priv)*/

/*iv := []byte("01020304050607081122334455667788")

// Set up encryption
err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC, iv)}, obj[0])
if err != nil {
	panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
}

diagnostics.Debugf(ctx, "Key Inited %v ", obj[0])

data := []byte("this is a string")

diagnostics.Debugf(ctx, "Encrypt data: %v len: %v ", data, len(data))
encryptedData, err := p.Encrypt(session, data)
if err != nil {
	panic(fmt.Sprintf("Encrypt() failed %s\n", err))
}

diagnostics.Debugf(ctx, "Result: %v len: %v ", encryptedData, len(encryptedData))*/

/*aesKeyTemplate := []*Attribute{
	NewAttribute(CKA_LABEL, "Create AES Encryption Key"),
	NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
	NewAttribute(CKA_KEY_TYPE, CKK_AES),
	NewAttribute(CKA_ENCRYPT, true),
	NewAttribute(CKA_TOKEN, true),
	NewAttribute(CKA_VALUE_LEN, 80),
	NewAttribute(CKA_VALUE, 80),
}

aesKey, err := p.CreateObject(session, aesKeyTemplate)
if err != nil {
	panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
}

diagnostics.Debugf(ctx, "Key Created %v ", aesKey)*/

/*err = p.Login(session, CKU_USER, "")
	if err != nil {
		diagnostics.Debugf(ctx,fmt.Sprintf("Login() failed %s\n", err), 2)
	}* /
}
*/
