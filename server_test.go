// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/keithballdotnet/arx/kms"
	arxpb "github.com/keithballdotnet/arx/proto"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
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

	kms.Storage, err = kms.NewDiskStorageProvider()
	require.NoError(t, err)
	kms.MasterKeyStore, err = kms.NewGoKMSMasterKeyProvider()
	require.NoError(t, err)
	kms.KmsCrypto, err = kms.NewDefaultCryptoProvider()
	require.NoError(t, err)
}

func Test_CreateKey_Success(t *testing.T) {
	SetUpSuite(t)

	server := newServer()

	ctx := context.TODO()

	testDescription := "Afternoon Delight"

	ckr := arxpb.CreateKeyRequest{Description: testDescription}

	km, err := server.CreateKey(ctx, &ckr)
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, km.Description, testDescription)
	require.NotEmpty(t, km.KeyID)
	require.True(t, km.Enabled)
	createDate, err := time.Parse(time.RFC3339Nano, km.CreationDate_RFC3339Nano)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), createDate, 5*time.Second)

}

func Test_ListKeys_Success(t *testing.T) {
	SetUpSuite(t)

	server := newServer()

	ctx := context.TODO()

	testDescription := "Stamos"

	ckr := arxpb.CreateKeyRequest{Description: testDescription}

	km, err := server.CreateKey(ctx, &ckr)
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, km.Description, testDescription)
	require.NotEmpty(t, km.KeyID)
	require.True(t, km.Enabled)
	createDate, err := time.Parse(time.RFC3339Nano, km.CreationDate_RFC3339Nano)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), createDate, 5*time.Second)

}
