// Arx
// Copyright (C) 2016 Keith Ball
// License: GPL3

package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"

	log "github.com/golang/glog"
)

// GetHmac256 will generate a HMAC hash encoded to base64
func GetHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	if _, err := h.Write([]byte(message)); err != nil {
		log.Errorf("Error computing MAC: %v", err)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ComputeMd5Checksum This returns the data's MD5 checksum.
//
// WARNING: Do NOT Use MD5 in security contexts (defending against
// intentional manipulations of data from untrusted sources);
// use only for checking data integrity against machine errors.
func ComputeMd5Checksum(data []byte) []byte {
	h := md5.New()
	if _, err := h.Write(data); err != nil {
		log.Errorf("Error computing MD5 checksum: %v", err)
	}
	return h.Sum(nil)
}

// ComputeMd5ChecksumString returns the md5 checksum
func ComputeMd5ChecksumString(data []byte) string {
	h := md5.New()
	if _, err := h.Write(data); err != nil {
		log.Errorf("Error computing MD5 checksum: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeSha256Checksum This returns the data's Sha256 checksum
func ComputeSha256Checksum(data []byte) []byte {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		log.Errorf("Error computing SHA-256 checksum: %v", err)
	}
	return hash.Sum(nil)
}

// GetSha256HashString This returns the data's Sha256 checksum as a string representation
func GetSha256HashString(data []byte) string {
	return hex.EncodeToString(ComputeSha256Checksum(data))
}

// GetSha256HashStringFromStream Return a hash from a stream reader
func GetSha256HashStringFromStream(stream io.Reader) string {
	hash := sha256.New()
	if _, err := io.Copy(hash, stream); err != nil {
		log.Errorf("Error computing SHA-256 checksum: %v", err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// ValidateMd5Checksum This returns true if the data matches the provided checksum.
func ValidateMd5Checksum(data []byte, sum []byte) bool {
	ourSum := ComputeMd5Checksum(data)
	return bytes.Equal(ourSum, sum)
}

// ValidateSha256Checksum This returns true if the data matches the provided checksum.
func ValidateSha256Checksum(data []byte, sum []byte) bool {
	ourSum := ComputeSha256Checksum(data)
	return bytes.Equal(ourSum, sum)
}

// CompareChecksums Compare two check sums.  Return true if they are they same
func CompareChecksums(first []byte, second []byte) bool {
	return bytes.Equal(first, second)
}
