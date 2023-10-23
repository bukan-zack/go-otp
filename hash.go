package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type Hash uint8

const (
	HashSHA1 Hash = iota + 1
	HashSHA256
	HashSHA512
)

// String returns the representation of hash in string.
func (h Hash) String() string {
	switch h {
	case HashSHA1:
		return "SHA1"
	case HashSHA256:
		return "SHA256"
	}

	return "SHA512"
}

// Size returns the size of a checksum for hash in bytes.
func (h Hash) Size() int {
	switch h {
	case HashSHA1:
		return sha1.Size
	case HashSHA256:
		return sha256.Size
	}

	return sha512.Size
}

// Hash returns [hash.Hash], computing checksum for hash.
func (h Hash) Hash() hash.Hash {
	switch h {
	case HashSHA1:
		return sha1.New()
	case HashSHA256:
		return sha256.New()
	}

	return sha512.New()
}
