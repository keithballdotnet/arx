// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package main

import (
	"fmt"
	"io"
	"os"

	arxpb "github.com/keithballdotnet/arx/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Author = "Keith Ball"
	app.Copyright = "2016 - Keith Ball"
	app.Name = "ArxClient"
	app.Version = "1.0"
	app.Usage = "The client for arx"

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "tls",
			Usage: "Connection uses TLS if true, else plain TCP",
		},
		cli.StringFlag{
			Name:  "ca_file, c",
			Value: "testdata/ca.pem",
			Usage: "The file containning the CA root cert file",
		},
		cli.StringFlag{
			Name:  "server_addr, a",
			Value: "127.0.0.1:10000",
			Usage: "The server address in the format of host:port",
		},
		cli.StringFlag{
			Name:  "server_host_override, sho",
			Value: "my.hostoverride.com",
			Usage: "The server name use to verify the hostname returned by TLS handshake",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:  "create",
			Usage: "create a new key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "description, d",
					Usage: "Description for the key",
				},
			},
			Action: func(c *cli.Context) {
				client, err := getClient(c)
				if err != nil {
					fmt.Printf("Unable to get client: %v", err)
					os.Exit(2)
				}
				createKey(client, c.String("description"))
			},
		},
		cli.Command{
			Name:  "list",
			Usage: "list keys",
			Action: func(c *cli.Context) {
				client, err := getClient(c)
				if err != nil {
					fmt.Printf("Unable to get client: %v", err)
					os.Exit(2)
				}
				listKeys(client)
			},
		},
		cli.Command{
			Name:  "enable",
			Usage: "enable a key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "keyid, k",
					Usage: "The key to enable",
				},
			},
			Action: func(c *cli.Context) {
				client, err := getClient(c)
				if err != nil {
					fmt.Printf("Unable to get client: %v", err)
					os.Exit(2)
				}
				enableKey(client, c.String("keyid"))
			},
		},
		cli.Command{
			Name:  "disable",
			Usage: "disable a key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "keyid, k",
					Usage: "The key to disable",
				},
			},
			Action: func(c *cli.Context) {
				client, err := getClient(c)
				if err != nil {
					fmt.Printf("Unable to get client: %v", err)
					os.Exit(2)
				}
				disableKey(client, c.String("keyid"))
			},
		},
		cli.Command{
			Name:  "rotate",
			Usage: "rotate a key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "keyid, k",
					Usage: "The key to rotate",
				},
			},
			Action: func(c *cli.Context) {
				client, err := getClient(c)
				if err != nil {
					fmt.Printf("Unable to get client: %v", err)
					os.Exit(2)
				}
				rotateKey(client, c.String("keyid"))
			},
		},
	}

	app.Run(os.Args)

}

func getClient(c *cli.Context) (arxpb.ArxClient, error) {
	var opts []grpc.DialOption
	if c.GlobalBool("tls") {
		var sn string
		if c.GlobalString("server_host_override") != "" {
			sn = c.GlobalString("server_host_override")
		}
		var creds credentials.TransportAuthenticator
		if c.GlobalString("ca_file") != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(c.GlobalString("ca_file"), sn)
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
	conn, err := grpc.Dial(c.GlobalString("server_addr"), opts...)
	if err != nil {
		grpclog.Fatalf("fail to dial: %v", err)
	}
	client := arxpb.NewArxClient(conn)

	return client, nil
}

// rotateKey
func rotateKey(client arxpb.ArxClient, keyid string) {
	grpclog.Println("Rotate a key")

	ctx := context.TODO()

	rokr := arxpb.RotateKeyRequest{KeyID: keyid}
	km, err := client.RotateKey(ctx, &rokr)
	if err != nil {
		grpclog.Fatalf("%v.RotateKey(_) = _, %v: ", client, err)
	}
	grpclog.Println(km)
}

// disableKey
func disableKey(client arxpb.ArxClient, keyid string) {
	grpclog.Println("Disable a key")

	ctx := context.TODO()

	disr := arxpb.DisableKeyRequest{KeyID: keyid}
	km, err := client.DisableKey(ctx, &disr)
	if err != nil {
		grpclog.Fatalf("%v.DisableKey(_) = _, %v: ", client, err)
	}
	grpclog.Println(km)
}

// enableKey
func enableKey(client arxpb.ArxClient, keyid string) {
	grpclog.Println("Enable a key")

	ctx := context.TODO()

	enr := arxpb.EnableKeyRequest{KeyID: keyid}
	km, err := client.EnableKey(ctx, &enr)
	if err != nil {
		grpclog.Fatalf("%v.EnableKey(_) = _, %v: ", client, err)
	}
	grpclog.Println(km)
}

// createKey
func createKey(client arxpb.ArxClient, description string) {
	grpclog.Println("Create new key")

	ckr := &arxpb.CreateKeyRequest{Description: description}

	ctx := context.TODO()

	km, err := client.CreateKey(ctx, ckr)
	if err != nil {
		grpclog.Fatalf("%v.CreateKey(_) = _, %v: ", client, err)
	}
	grpclog.Println(km)
}

func listKeys(client arxpb.ArxClient) {
	grpclog.Println("List keys")

	ctx := context.TODO()

	lkr := arxpb.ListKeysRequest{}
	stream, err := client.ListKeys(ctx, &lkr)
	if err != nil {
		grpclog.Fatalf("%v.ListKeys(_) = _, %v: ", client, err)
	}
	for {
		km, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			grpclog.Fatalf("%v.ListKeys(_) = _, %v: ", client, err)
		}

		grpclog.Println(km)
	}
}
