package main

import (
	"flag"
	"fmt"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	arxpb "github.com/keithballdotnet/arx/proto"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "testdata/server1.pem", "The TLS cert file")
	keyFile  = flag.String("key_file", "testdata/server1.key", "The TLS key file")
	port     = flag.Int("port", 10000, "The server port")
)

type arxServer struct {
}

// CreateGroup
func (s *arxServer) CreateKey(ctx context.Context, in *arxpb.CreateKeyRequest) (*arxpb.KeyMetadata, error) {

	grpclog.Printf("CreateKey Start: %v", ctx)

	km := arxpb.KeyMetadata{Description: in.Description}

	return &km, nil
}

func newServer() *arxServer {
	s := new(arxServer)
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		grpclog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	grpcServer := grpc.NewServer(opts...)
	fmt.Printf("Starting Arx RPC server: %s", lis.Addr().String())

	arxpb.RegisterArxServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
