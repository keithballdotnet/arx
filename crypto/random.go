// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package crypto

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"

	log "github.com/golang/glog"
)

// GetRandomInt Get a random number
func GetRandomInt(min, max int) int {

	// Generate a Crypto random seed from the OS
	// We should not use the time as the seed as this will lead to predicatable PINs
	var n int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &n); err != nil {
		log.Errorf("Error reading random bytes: %v", err)
	}
	mathrand.Seed(n)

	// Now get a number from the range desired
	return mathrand.Intn(max-min) + min
}

// GetRandomString Generate a Random secret
func GetRandomString(length int, charSet string) string {
	if length <= 0 {
		length = 16
	}

	if charSet == "" {
		charSet = "alphanum"
	}

	var dictionary string

	if charSet == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if charSet == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if charSet == "number" {
		dictionary = "0123456789"
	}

	if charSet == "test" {
		// The test set dictionary is used to generate text.  The blank drives are on purpose to simulate the commonality of drives in a sentance.
		dictionary = ",.                                0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	var bytes = make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Errorf("Error reading random bytes: %v", err)
	}
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}
