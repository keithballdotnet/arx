# arx
gRPC KMS (Key Management System)

## Development Set Up
### Install protobuf
Download version 3 from... [https://github.com/google/protobuf/releases](https://github.com/google/protobuf/releases)

### Install the golang grpc
sudo -E go get -a github.com/golang/protobuf/protoc-gen-go

### Install the grpc examples
go get -u google.golang.org/grpc

### Converting the .proto file
protoc --go_out=plugins=grpc:. src/github.com/keithballdotnet/arx/proto/arx.proto
