// A simple to use implementation of ECDH with curve25519 for Go.  The core
// mathematics of this algorithm are already present in
// golang.org/x/crypto/curve25519, this library just implements the algorithm
// in such a way that knowledge of the underlying mathematics is not necessary.
package ecdh25519

import (
    "crypto/rand"
    "errors"

    "golang.org/x/crypto/curve25519"
)

// PrivateKey represents the private portion of a curve25519 ECDH key pair.
type PrivateKey struct {
    rprv [KeySize]byte
    rpub *PublicKey
    publicHasBeenComputed bool
}

// PublicKey represents the public portion of a curve25519 ECHD key pair.
type PublicKey [KeySize]byte

// KeySize is the length, in bytes, of both Private and Public keys.
const KeySize int = 32

// KeySizeError is returned if the provided key is not the correct length.
// It can only be returned from PrivateFromBytes and PublicFromBytes.
var KeySizeError error = errors.New("The data provided was not 32 bytes in length.")

// GenerateKey generates a new curve25519 private key.  The public portion can
// be retrieved by calling Public().
func GenerateKey() (*PrivateKey, error) {
    var k [KeySize]byte
    _, err := rand.Read(k[:])
    if err != nil { return nil, err }

    k[0] &= 248
    k[31] &= 127
    k[31] |= 64

    return &PrivateKey{k, nil, false}, nil
}

// Public returns the public key corresponding to prv.
func (prv *PrivateKey) Public() *PublicKey {
    if prv.publicHasBeenComputed {
        return prv.rpub
    }

    var dst [KeySize]byte
    curve25519.ScalarBaseMult(&dst, &prv.rprv)

    rpub := PublicKey(dst)
    prv.rpub = &rpub
    return prv.rpub
}

// ComputeSecret computes the shared secret value for the calling private key
// when combined with the given public key.
func (prv *PrivateKey) ComputeSecret(pub *PublicKey) []byte {
    rpub := [KeySize]byte(*pub)

    var dst [KeySize]byte
    curve25519.ScalarMult(&dst, &prv.rprv, &rpub)

    return dst[:]
}

// PrivateFromBytes creates a PrivateKey from the given input byte slice.
func PrivateFromBytes(raw []byte) (*PrivateKey, error) {
    if len(raw) != KeySize {
        return nil, KeySizeError
    }

    var arr [KeySize]byte
    copy(arr[:], raw)

    return &PrivateKey{arr, nil, false}, nil
}

// PublicFromBytes creates a PublicKey from the given input byte slice.
func PublicFromBytes(raw []byte) (*PublicKey, error) {
    if len(raw) != KeySize {
        return nil, KeySizeError
    }

    var arr [KeySize]byte
    copy(arr[:], raw)

    rpub := PublicKey(arr)
    return &rpub, nil
}

// ToBytes marshals the given Private Key to a byte slice.  It can be loaded
// back into a PrivateKey by using PrivateFromBytes.
func (prv *PrivateKey) ToBytes() []byte {
    r := make([]byte, KeySize)
    copy(r, prv.rprv[:])
    return r
}

// ToBytes marhsals the given Public Key to a byte slice.  It can be loaded
// back into a PublicKey by using PublicFromBytes.
func (pub *PublicKey) ToBytes() []byte {
    r := make([]byte, KeySize)
    copy(r, pub[:])
    return r
}
