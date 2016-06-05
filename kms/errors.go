// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package kms

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// ErrorMessages is a list of errors messages mapped to an error code
var ErrorMessages = map[int]string{
	EcodeKeyNotFound:     "Key not found",
	ECodeCryptoError:     "Crypto error",
	EcodeInvalidArgument: "Invalid argument",
	EcodeUnknown:         "Unknown error",
}

// ErrorCodes is a list of grpc Codes that maps to an Error Code
var ErrorCodes = map[int]codes.Code{
	EcodeKeyNotFound:     codes.NotFound,
	ECodeCryptoError:     codes.Internal,
	EcodeInvalidArgument: codes.InvalidArgument,
	EcodeUnknown:         codes.Unknown,
}

// ErrorCodes
const (
	EcodeKeyNotFound = 100
	ECodeCryptoError = 101

	EcodeInvalidArgument = 200

	EcodeUnknown = 500
)

// NewError will create a new KmsError
func NewError(errorCode int) error {
	return &Error{errorCode: errorCode}
}

// Error is an internal KMS error
type Error struct {
	error
	errorCode int
}

// Error ...
func (kmsError *Error) Error() string {
	return ErrorMessages[kmsError.errorCode]
}

// GrpcError will return a grpc format error
func (kmsError Error) GrpcError() error {
	return grpc.Errorf(ErrorCodes[kmsError.errorCode], ErrorMessages[kmsError.errorCode])
}
