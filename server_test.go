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

	temp, err := ioutil.TempDir("", "kms_test")
	err = os.Setenv("ARX_PATH", temp)
	require.NoError(t, err)

	kms.Storage, err = kms.NewDiskStorageProvider()
	require.NoError(t, err)
	arxMKS, err := kms.NewArxMasterKeyProvider()
	require.NoError(t, err)
	arxMKS.Passphrase("A long passphrase that will be used to generate the master key")

	kms.MasterKeyStore = arxMKS

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

	ckr = arxpb.CreateKeyRequest{Description: "2nd Key"}

	km2, err := client.CreateKey(ctx, &ckr)

	quote := "Do not act as if thou wert going to live ten thousand years. Death hangs over thee. While thou livest, while it is in thy power, be good."
	plainText := []byte(quote)

	er := arxpb.EncryptRequest{KeyID: km.KeyID, Plaintext: plainText}
	encResult, err := client.Encrypt(ctx, &er)
	require.NoError(t, err)
	require.NotNil(t, encResult)
	require.NotNil(t, encResult.CiphertextBlob)
	require.NotEqual(t, plainText, encResult.CiphertextBlob)

	dr := arxpb.DecryptRequest{CiphertextBlob: encResult.CiphertextBlob}
	decResult, err := client.Decrypt(ctx, &dr)
	require.NoError(t, err)
	require.NotNil(t, decResult)
	require.Equal(t, plainText, decResult.Plaintext)

	rer := arxpb.ReEncryptRequest{CiphertextBlob: encResult.CiphertextBlob, DestinationKeyID: km2.KeyID}
	reResult, err := client.ReEncrypt(ctx, &rer)
	require.NoError(t, err)
	require.Equal(t, km.KeyID, reResult.SourceKeyID)
	require.Equal(t, km2.KeyID, reResult.KeyID)
	require.NotNil(t, reResult.CiphertextBlob)

	dr2 := arxpb.DecryptRequest{CiphertextBlob: reResult.CiphertextBlob}
	decResult2, err := client.Decrypt(ctx, &dr2)
	require.NoError(t, err)
	require.NotNil(t, decResult2)
	require.Equal(t, plainText, decResult2.Plaintext)

	disr := arxpb.DisableKeyRequest{KeyID: km2.KeyID}
	disResult, err := client.DisableKey(ctx, &disr)
	require.NoError(t, err)
	require.False(t, disResult.Enabled)

	enr := arxpb.EnableKeyRequest{KeyID: km2.KeyID}
	enableResult, err := client.EnableKey(ctx, &enr)
	require.NoError(t, err)
	require.True(t, enableResult.Enabled)

	dkr := arxpb.GenerateDataKeyRequest{KeyID: km.KeyID}
	dataKey, err := client.GenerateDataKey(ctx, &dkr)
	require.NoError(t, err)
	require.NotNil(t, dataKey)
	require.Len(t, dataKey.Plaintext, 32)

	rokr := arxpb.RotateKeyRequest{KeyID: km.KeyID}
	roResult, err := client.RotateKey(ctx, &rokr)
	require.NoError(t, err)
	require.True(t, roResult.Success)

	err = conn.Close()
	require.NoError(t, err)
}

// NewClientConn creates a gRPC client connection to addr.
func NewClientConn(addr string) *grpc.ClientConn {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		grpclog.Fatalf("NewClientConn(%q) failed to create a ClientConn %v", addr, err)
	}
	return conn
}
