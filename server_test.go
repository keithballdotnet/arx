// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"

	"github.com/keithballdotnet/arx/kms"
	"github.com/stretchr/testify/require"

	arxpb "github.com/keithballdotnet/arx/proto"
)

func setUp(t *testing.T) {

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

func Test_Success(t *testing.T) {
	setUp(t)

	_, stopServer := startServer(":10000")
	defer stopServer()

	conn := NewClientConn(":10000")

	client := arxpb.NewArxClient(conn)

	ctx := context.TODO()
	testDescription := "Afternoon Delight"

	ckr := arxpb.CreateKeyRequest{Description: testDescription}

	km, err := client.CreateKey(ctx, &ckr)

	t.Logf("CreateKey - KeyMetadata: %v", km)

	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, km.Description, testDescription)
	require.NotEmpty(t, km.KeyID)
	require.True(t, km.Enabled)
	createDate, err := time.Parse(time.RFC3339Nano, km.CreationDate_RFC3339Nano)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), createDate, 5*time.Second)

	var collectedKeys []*arxpb.KeyMetadata
	lkr := arxpb.ListKeysRequest{}
	stream, err := client.ListKeys(ctx, &lkr)
	require.NoError(t, err)
	for {
		km, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			require.NoError(t, err)
		}

		t.Log(km)
		collectedKeys = append(collectedKeys, km)
	}
	require.Len(t, collectedKeys, 1)

	err := conn.Close()
	require.NoError(err)
}

// NewClientConn creates a gRPC client connection to addr.
func NewClientConn(addr string) *grpc.ClientConn {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		grpclog.Fatalf("NewClientConn(%q) failed to create a ClientConn %v", addr, err)
	}
	return conn
}
