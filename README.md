# arx
Is a gRPC KMS (Key Management System).  More to come...

[![GoDoc](https://godoc.org/github.com/keithballdotnet/arx?status.svg)](https://godoc.org/github.com/keithballdotnet/arx)
[![Build Status](https://travis-ci.org/keithballdotnet/arx.svg)](https://travis-ci.org/keithballdotnet/arx)
[![Coverage Status](https://coveralls.io/repos/github/keithballdotnet/arx/badge.svg?branch=master)](https://coveralls.io/github/keithballdotnet/arx?branch=master)

## Todo
+ Key Pairs auth
+ Import KMS logic
+ 

## Development Set Up
### Install protobuf
Download version 3 from... [https://github.com/google/protobuf/releases](https://github.com/google/protobuf/releases)

### Install the golang grpc
sudo -E go get -a github.com/golang/protobuf/protoc-gen-go

### Install the grpc examples
go get -u google.golang.org/grpc

### Converting the .proto file
protoc --go_out=plugins=grpc:. src/github.com/keithballdotnet/arx/proto/arx.proto
