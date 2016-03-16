// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codegangsta/cli"
	log "github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/keithballdotnet/arx/crypto"
	"github.com/keithballdotnet/arx/kms"
	arxpb "github.com/keithballdotnet/arx/proto"
)

type arxServer struct {
}

func newServer() *arxServer {
	s := new(arxServer)
	return s
}

func main() {

	app := cli.NewApp()
	app.Author = "Keith Ball"
	app.Copyright = "2016 - Keith Ball"
	app.Name = "Arx"
	app.Version = "1.0"
	app.Usage = "GRPC Key Management Service"

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "tls",
			Usage: "Connection uses TLS if true, else plain TCP",
		},
		cli.StringFlag{
			Name:  "cert_file, c",
			Value: "testdata/ca.pem",
			Usage: "The TLS cert file",
		},
		cli.StringFlag{
			Name:  "key_file, k",
			Value: "testdata/server1.key",
			Usage: "The TLS key file",
		},
		cli.IntFlag{
			Name:  "port, p",
			Value: 10000,
			Usage: "The server port",
		},
		cli.StringFlag{
			Name:  "phrase, ph",
			Value: "",
			Usage: "Master key passphrase",
		},
		cli.StringFlag{
			Name:  "storage, s",
			Value: "disk",
			Usage: "Storage provider (disk|cb - Default is disk)",
		},
	}
	app.Action = func(c *cli.Context) {
		flag.Parse()
		flag.Set("logtostderr", "true")
		var err error
		// Select the storage provider
		switch c.String("storage") {
		case "disk":
			kms.Storage, err = kms.NewDiskStorageProvider()
		case "cb":
			kms.Storage, err = kms.NewCouchbaseStorageProvider()
		default:
			Exit("You must give a storage provider", 2)
		}
		if err != nil {
			Exit(fmt.Sprintf("Problem creating storage provider: %v", err), 2)
		}

		masterKeyStore, err := kms.NewArxMasterKeyProvider()
		if err != nil {
			Exit(fmt.Sprintf("Problem creating master key provider: %v", err), 2)
		}
		masterKeyStore.Passphrase(c.String("phrase"))
		kms.MasterKeyStore = masterKeyStore

		// Create the KMS Crypto Provider
		kms.KmsCrypto, err = kms.NewDefaultCryptoProvider()
		if err != nil {
			Exit(fmt.Sprintf("Problem creating crypto provider: %v", err), 2)
		}

		addr, stopFunc := startServer(fmt.Sprintf(":%d", c.Int("port")), c.Bool("tls"), c.String("cerFile"), c.String("keyFile"))
		log.Infof("Started Arx RPC server: %s", addr)

		// Wait for close
		ch := make(chan os.Signal)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
		log.Infoln(<-ch)
		stopFunc()
	}

	app.Run(os.Args)
}

func startServer(addr string, tls bool, certFile, keyFile string) (string, func()) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if tls {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	s := grpc.NewServer(opts...)
	arxpb.RegisterArxServer(s, newServer())
	go s.Serve(lis)
	return lis.Addr().String(), func() {
		s.Stop()
	}
}

// CreateKey
func (s *arxServer) CreateKey(ctx context.Context, in *arxpb.CreateKeyRequest) (*arxpb.KeyMetadata, error) {
	start := time.Now()
	log.Infof("CreateKey Start: %v", ctx)

	key, err := kms.KmsCrypto.CreateKey(ctx, in.Description)
	if err != nil {
		log.Errorf("CreateKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	log.Infof("CreateKey took: %dms", time.Since(start)/time.Millisecond)

	return km, nil
}

// EnableKey
func (s *arxServer) EnableKey(ctx context.Context, in *arxpb.EnableKeyRequest) (*arxpb.KeyMetadata, error) {
	start := time.Now()
	log.Infof("EnableKey Start: %v", ctx)

	key, err := kms.KmsCrypto.EnableKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("EnableKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	log.Infof("EnableKey took: %dms", time.Since(start)/time.Millisecond)

	return km, nil
}

// DisableKey
func (s *arxServer) DisableKey(ctx context.Context, in *arxpb.DisableKeyRequest) (*arxpb.KeyMetadata, error) {
	start := time.Now()
	log.Infof("DisableKey Start: %v", ctx)

	key, err := kms.KmsCrypto.DisableKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("DisableKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	log.Infof("DisableKey took: %dms", time.Since(start)/time.Millisecond)

	return km, nil
}

// RotateKey
func (s *arxServer) RotateKey(ctx context.Context, in *arxpb.RotateKeyRequest) (*arxpb.RotateKeyResponse, error) {
	start := time.Now()
	log.Infof("RotateKey Start: %v", ctx)

	err := kms.KmsCrypto.RotateKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("RotateKey: %v", err)
		return nil, err
	}

	rkr := arxpb.RotateKeyResponse{Success: true}

	log.Infof("RotateKey took: %dms", time.Since(start)/time.Millisecond)

	return &rkr, nil
}

// GenerateDataKey
func (s *arxServer) GenerateDataKey(ctx context.Context, in *arxpb.GenerateDataKeyRequest) (*arxpb.GenerateDataKeyResponse, error) {
	start := time.Now()
	log.Infof("GenerateDataKey Start: %v", ctx)

	// Create a new key
	aesKey := crypto.GenerateAesKey()

	// Encrypt the key with the master key
	encryptedData, err := kms.KmsCrypto.Encrypt(ctx, aesKey, in.KeyID)
	if err != nil {
		return nil, err
	}

	rkr := arxpb.GenerateDataKeyResponse{Plaintext: aesKey, CiphertextBlob: encryptedData}

	log.Infof("GenerateDataKey took: %dms", time.Since(start)/time.Millisecond)

	return &rkr, nil
}

// Encrypt
func (s *arxServer) Encrypt(ctx context.Context, in *arxpb.EncryptRequest) (*arxpb.EncryptResponse, error) {
	start := time.Now()
	log.Infof("Encrypt Start: %v", ctx)

	// Encrypt the data with the key specified and return the encrypted data
	encryptedData, err := kms.KmsCrypto.Encrypt(ctx, in.Plaintext, in.KeyID)
	if err != nil {
		return nil, err
	}

	rkr := arxpb.EncryptResponse{CiphertextBlob: encryptedData}

	log.Infof("Encrypt took: %dms", time.Since(start)/time.Millisecond)

	return &rkr, nil
}

// Decrypt
func (s *arxServer) Decrypt(ctx context.Context, in *arxpb.DecryptRequest) (*arxpb.DecryptResponse, error) {
	start := time.Now()
	log.Infof("Decrypt Start: %v", ctx)

	// Decrypt
	decryptedData, _, err := kms.KmsCrypto.Decrypt(ctx, in.CiphertextBlob)
	if err != nil {
		return nil, err
	}

	log.Infof("Decrypt took: %dms", time.Since(start)/time.Millisecond)

	return &arxpb.DecryptResponse{Plaintext: decryptedData}, nil
}

// ReEncrypt
func (s *arxServer) ReEncrypt(ctx context.Context, in *arxpb.ReEncryptRequest) (*arxpb.ReEncryptResponse, error) {
	start := time.Now()
	log.Infof("ReEncrypt Start: %v", ctx)

	// Reencrypt the data
	ciphertextBlob, sourceKeyID, err := kms.KmsCrypto.ReEncrypt(ctx, in.CiphertextBlob, in.DestinationKeyID)
	if err != nil {
		return nil, err
	}

	log.Infof("ReEncrypt took: %dms", time.Since(start)/time.Millisecond)

	return &arxpb.ReEncryptResponse{CiphertextBlob: ciphertextBlob, KeyID: in.DestinationKeyID, SourceKeyID: sourceKeyID}, nil
}

// ListKeys
func (s *arxServer) ListKeys(in *arxpb.ListKeysRequest, stream arxpb.Arx_ListKeysServer) error {
	ctx := stream.Context()
	start := time.Now()
	log.Infof("ListKeys Start: %v", ctx)

	keys, err := kms.KmsCrypto.ListKeys(ctx)
	if err != nil {
		log.Errorf("ListKeys: %v", err)
		return err
	}

	for _, key := range keys {
		km := convertKey(&key)
		if err := stream.Send(km); err != nil {
			return err
		}
	}

	log.Infof("ListKeys took: %dms", time.Since(start)/time.Millisecond)

	return nil
}

func convertKey(km *kms.KeyMetadata) *arxpb.KeyMetadata {
	outkm := arxpb.KeyMetadata{KeyID: km.KeyID,
		CreationDate_RFC3339Nano: km.CreationDate.Format(time.RFC3339Nano),
		Enabled:                  km.Enabled,
		Description:              km.Description}
	return &outkm
}

// Exit will return an error code and the reason to the os
func Exit(messages string, errorCode int) {
	// Exit code and messages based on Nagios plugin return codes (https://nagios-plugins.org/doc/guidelines.html#AEN78)
	var prefix = map[int]string{0: "OK", 1: "Warning", 2: "Critical", 3: "Unknown"}

	// Catch all unknown errorCode and convert them to Unknown
	if errorCode < 0 || errorCode > 3 {
		errorCode = 3
	}

	log.Infof("%s %s\n", prefix[errorCode], messages)

	os.Exit(errorCode)
}
