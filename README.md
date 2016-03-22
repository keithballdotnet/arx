# Arx - Key Management Service

[![GoDoc](https://godoc.org/github.com/keithballdotnet/arx?status.svg)](https://godoc.org/github.com/keithballdotnet/arx)
[![Build Status](https://travis-ci.org/keithballdotnet/arx.svg)](https://travis-ci.org/keithballdotnet/arx)
[![Coverage Status](https://coveralls.io/repos/github/keithballdotnet/arx/badge.svg?branch=master)](https://coveralls.io/github/keithballdotnet/arx?branch=master)
[![Go Report Card](https://goreportcard.com/badge/keithballdotnet/arx)](https://goreportcard.com/report/github.com/keithballdotnet/arx)

## What is Arx?

Arx is an encryption Key Management Service written in GO.  Modelled extensively on AWS KMS behaviour, the API is used for symmetrical key management.  It offers Cryptography as a Service (CaaS) functionality such as encryption / decryption / re-encryption without exposing keys.

The crypto provider is based on [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and a key size of 256bits using the [GCM cipher](http://en.wikipedia.org/wiki/Galois/Counter_Mode) to provide confidentiality as well as authentication.  

Keys are encrypted and stored on disk/couchbase/boltdb, using a master key which is derived using [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) from a passphrase.

### Arxclient - Command Line Interface

Arxclient is a command line interface which can be used to manage and interact with arx.

## Features

- AES Key store
- Cryptography as a Service
	+ Encrypt
	+ Decrypt
	+ Re-encrypt
- Keys encrypted while at rest
- Key rotation on demand

## How-To

### Install arx

```shell
$ go get github.com/keithballdotnet/arx
```

### Start service with defaults

```shell
$ arx --ph "some 32 character passphrase that you can use to be your derived key"
```

### Create a new key

```shell
$ arxclient create -d "example"
2016/03/22 21:17:16 Create new key
2016/03/22 21:17:16 KeyID:"ddb6b5d0-15da-4f41-92db-6480953464df" CreationDateRFC3339Nano:"2016-03-22T20:17:16.558504583Z" Description:"example" Enabled:true
```

## AWS Style Key Management Service

The encryption follows the pattern as specified in the in the [KMS Cryptographic Whitepaper](https://d0.awsstatic.com/whitepapers/KMS-Cryptographic-Details.pdf).

![](keyheirarchy.png?raw=true)

For each peice of data that needs encryption a new DataKey will be requested from KMS.  The key will return an encrypted version of the key and a plaintext version of the key.  The plaintext version of the key will be used to encrypt the data.  It will be then combined into an envelop of data ready for persistence.

![](aws_encrypt.png?raw=true)

Upon a request for decryption the data envelope will be inspected, the encrypted key extracted and then decrypted by the KMS server.  The decrypted key can then be used to decrypt the body of the data.

![](aws_decrypt.png?raw=true)


## Good resources:

### KMS

- AWS KMS: https://d0.awsstatic.com/whitepapers/KMS-Cryptographic-Details.pdf
- MS Key Vault: https://msdn.microsoft.com/en-US/library/azure/dn903623

## Roadmap

+ Key Pairs auth?
+ Some other auth modes
+ Key audit logs?
+ Diagnostics?

## Protobuf Development Set Up

### Install protobuf
Download version 3 from... [https://github.com/google/protobuf/releases](https://github.com/google/protobuf/releases)

### Install the golang grpc
sudo -E go get -a github.com/golang/protobuf/protoc-gen-go

### Install the grpc examples
go get -u google.golang.org/grpc

### Converting the .proto file
protoc --go_out=plugins=grpc:. src/github.com/keithballdotnet/arx/proto/arx.proto
