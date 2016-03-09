// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	log "github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"

	"github.com/keithballdotnet/arx/kms"
	arxpb "github.com/keithballdotnet/arx/proto"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "testdata/server1.pem", "The TLS cert file")
	keyFile  = flag.String("key_file", "testdata/server1.key", "The TLS key file")
	port     = flag.Int("port", 10000, "The server port")
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

// CreateGroup
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

	var err error
	// Select the storage provider
	/*switch Config["GOKMS_STORAGE_PROVIDER"] {
	case "disk":
		kms.Storage, err = kms.NewDiskStorageProvider()
	case "cb":
		kms.Storage, err = kms.NewCouchbaseStorageProvider()
	default:
		kms.Storage, err = kms.NewDiskStorageProvider()
	}*/

	kms.Storage, err = kms.NewDiskStorageProvider()
	if err != nil {
		Exit(fmt.Sprintf("Problem creating storage provider: %v", err), 2)
	}

	// Which master key provider should we use?
	/*switch Config["GOKMS_MASTERKEY_PROVIDER"] {
	case "gokms":
		kms.MasterKeyStore, err = kms.NewGoKMSMasterKeyProvider()
	case "hsm":
		// Create crypto provider
		//MasterKeyStore, err = NewHSMMasterKeyProvider()
	default:
		kms.MasterKeyStore, err = kms.NewGoKMSMasterKeyProvider()
	}*/

	kms.MasterKeyStore, err = kms.NewGoKMSMasterKeyProvider()
	if err != nil {
		Exit(fmt.Sprintf("Problem creating master key provider: %v", err), 2)
	}

	// Create the KMS Crypto Provider
	kms.KmsCrypto, err = kms.NewDefaultCryptoProvider()
	if err != nil {
		Exit(fmt.Sprintf("Problem creating crypto provider: %v", err), 2)
	}

	flag.Parse()
	addr, _ := startServer(fmt.Sprintf(":%d", *port))
	log.Infof("Started Arx RPC server: %s", addr)
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
