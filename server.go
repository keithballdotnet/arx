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

	log "github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"

	"github.com/keithballdotnet/arx/crypto"
	"github.com/keithballdotnet/arx/kms"
	arxpb "github.com/keithballdotnet/arx/proto"
)

var (
	tls             = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile        = flag.String("cert_file", "testdata/server1.pem", "The TLS cert file")
	keyFile         = flag.String("key_file", "testdata/server1.key", "The TLS key file")
	port            = flag.Int("port", 10000, "The server port")
	passphrase      = flag.String("phrase", "", "Master key passphrase")
	storageProvider = flag.String("sp", "disk", "Storage provider (disk|cb - Default is disk)")
)

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

type arxServer struct {
}

// CreateKey
func (s *arxServer) CreateKey(ctx context.Context, in *arxpb.CreateKeyRequest) (*arxpb.KeyMetadata, error) {

	log.Infof("CreateKey Start: %v", ctx)

	key, err := kms.KmsCrypto.CreateKey(ctx, in.Description)
	if err != nil {
		log.Errorf("CreateKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	return km, nil
}

// EnableKey
func (s *arxServer) EnableKey(ctx context.Context, in *arxpb.EnableKeyRequest) (*arxpb.KeyMetadata, error) {

	log.Infof("EnableKey Start: %v", ctx)

	key, err := kms.KmsCrypto.EnableKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("EnableKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	return km, nil
}

// DisableKey
func (s *arxServer) DisableKey(ctx context.Context, in *arxpb.DisableKeyRequest) (*arxpb.KeyMetadata, error) {

	log.Infof("DisableKey Start: %v", ctx)

	key, err := kms.KmsCrypto.DisableKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("DisableKey: %v", err)
		return nil, err
	}

	km := convertKey(&key)

	return km, nil
}

// RotateKey
func (s *arxServer) RotateKey(ctx context.Context, in *arxpb.RotateKeyRequest) (*arxpb.RotateKeyResponse, error) {

	log.Infof("RotateKey Start: %v", ctx)

	err := kms.KmsCrypto.RotateKey(ctx, in.KeyID)
	if err != nil {
		log.Errorf("RotateKey: %v", err)
		return nil, err
	}

	rkr := arxpb.RotateKeyResponse{Success: true}

	return &rkr, nil
}

// GenerateDataKey
func (s *arxServer) GenerateDataKey(ctx context.Context, in *arxpb.GenerateDataKeyRequest) (*arxpb.GenerateDataKeyResponse, error) {

	log.Infof("GenerateDataKey Start: %v", ctx)

	// Create a new key
	aesKey := crypto.GenerateAesKey()

	// Encrypt the key with the master key
	encryptedData, err := kms.KmsCrypto.Encrypt(ctx, aesKey, in.KeyID)
	if err != nil {
		return nil, err
	}

	rkr := arxpb.GenerateDataKeyResponse{Plaintext: aesKey, CiphertextBlob: encryptedData}

	return &rkr, nil
}

// Encrypt
func (s *arxServer) Encrypt(ctx context.Context, in *arxpb.EncryptRequest) (*arxpb.EncryptResponse, error) {

	log.Infof("Encrypt Start: %v", ctx)

	// Encrypt the data with the key specified and return the encrypted data
	encryptedData, err := kms.KmsCrypto.Encrypt(ctx, in.Plaintext, in.KeyID)
	if err != nil {
		return nil, err
	}

	rkr := arxpb.EncryptResponse{CiphertextBlob: encryptedData}

	return &rkr, nil
}

// Decrypt
func (s *arxServer) Decrypt(ctx context.Context, in *arxpb.DecryptRequest) (*arxpb.DecryptResponse, error) {

	log.Infof("Decrypt Start: %v", ctx)

	// Decrypt
	decryptedData, _, err := kms.KmsCrypto.Decrypt(ctx, in.CiphertextBlob)
	if err != nil {
		return nil, err
	}

	return &arxpb.DecryptResponse{Plaintext: decryptedData}, nil
}

// ReEncrypt
func (s *arxServer) ReEncrypt(ctx context.Context, in *arxpb.ReEncryptRequest) (*arxpb.ReEncryptResponse, error) {

	log.Infof("ReEncrypt Start: %v", ctx)

	// Reencrypt the data
	ciphertextBlob, sourceKeyID, err := kms.KmsCrypto.ReEncrypt(ctx, in.CiphertextBlob, in.DestinationKeyID)
	if err != nil {
		return nil, err
	}

	return &arxpb.ReEncryptResponse{CiphertextBlob: ciphertextBlob, KeyID: in.DestinationKeyID, SourceKeyID: sourceKeyID}, nil
}

// ListKeys
func (s *arxServer) ListKeys(in *arxpb.ListKeysRequest, stream arxpb.Arx_ListKeysServer) error {
	ctx := stream.Context()

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
	return nil
}

func convertKey(km *kms.KeyMetadata) *arxpb.KeyMetadata {
	outkm := arxpb.KeyMetadata{KeyID: km.KeyID,
		CreationDate_RFC3339Nano: km.CreationDate.Format(time.RFC3339Nano),
		Enabled:                  km.Enabled,
		Description:              km.Description}
	return &outkm
}

func newServer() *arxServer {
	s := new(arxServer)
	return s
}

func main() {

	flag.Parse()
	flag.Set("logtostderr", "true")

	var err error
	// Select the storage provider
	switch *storageProvider {
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
	masterKeyStore.Passphrase(*passphrase)
	kms.MasterKeyStore = masterKeyStore

	// Create the KMS Crypto Provider
	kms.KmsCrypto, err = kms.NewDefaultCryptoProvider()
	if err != nil {
		Exit(fmt.Sprintf("Problem creating crypto provider: %v", err), 2)
	}

	addr, stopFunc := startServer(fmt.Sprintf(":%d", *port))
	log.Infof("Started Arx RPC server: %s", addr)

	// Wait for close
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	log.Infoln(<-ch)
	stopFunc()
}

func startServer(addr string) (string, func()) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
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
