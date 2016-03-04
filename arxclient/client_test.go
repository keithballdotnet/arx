// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"testing"

	arxpb "github.com/keithballdotnet/arx/proto"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

func Test_CreateKey_Success(t *testing.T) {
	var opts []grpc.DialOption
	if *tls {
		var sn string
		if *serverHostOverride != "" {
			sn = *serverHostOverride
		}
		var creds credentials.TransportAuthenticator
		if *caFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(*caFile, sn)
			if err != nil {
				grpclog.Fatalf("Failed to create TLS credentials %v", err)
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := arxpb.NewArxClient(conn)

	testDescription := "KommunistPartei"
	ckr := &arxpb.CreateKeyRequest{Description: testDescription}

	km, err := client.CreateKey(context.Background(), ckr)
	require.NoError(t, err)

	require.NotNil(t, km)
	require.Equal(t, km.Description, ckr.Description)
}

/*func Benchmark_Create(b *testing.B) {
	var opts []grpc.DialOption
	if *tls {
		var sn string
		if *serverHostOverride != "" {
			sn = *serverHostOverride
		}
		var creds credentials.TransportAuthenticator
		if *caFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(*caFile, sn)
			if err != nil {
				grpclog.Fatalf("Failed to create TLS credentials %v", err)
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewGroupsClient(conn)

	//bench
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		newGroup := &pb.Group{Name: "KommunistPartei"}

		_, err := client.CreateGroup(context.Background(), newGroup)

		if err != nil {
			b.Fatal(err)
		}
	}
}*/
