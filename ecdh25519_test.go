package ecdh25519

import (
	"bytes"
	"testing"
)

func TestPrecompute(t *testing.T) {
	prv1, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}

	raw := prv1.ToBytes()

	prv2, err := PrivateFromBytes(raw, false)
	if err != nil {
		t.Error(err)
	}

	prv3, err := PrivateFromBytes(raw, true)
	if err != nil {
		t.Error(err)
	}

	if prv2.publicHasBeenComputed || !prv3.publicHasBeenComputed {
		t.Errorf("Public key precomputation failed.\nprv2: %v, prv3: %v", prv2.publicHasBeenComputed, prv3.publicHasBeenComputed)
	}
}

func TestComputeSecret(t *testing.T) {
	prv1, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}

	prv2, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}

	pub1 := prv1.Public()
	pub2 := prv2.Public()

	s1 := prv1.ComputeSecret(pub2)
	s2 := prv2.ComputeSecret(pub1)

	if bytes.Compare(s1, s2) != 0 {
		t.Errorf("Secrets do not match.")
	}
}

func TestMarshal(t *testing.T) {
	prv1, err := GenerateKey()
	if err != nil {
		t.Error(err)
		return
	}

	pub1 := prv1.Public()

	rawprv := prv1.ToBytes()
	rawpub := pub1.ToBytes()

	prv2, err := PrivateFromBytes(rawprv, false)
	if err != nil {
		t.Error(err)
		return
	}

	pub2, err := PublicFromBytes(rawpub)
	if err != nil {
		t.Error(err)
		return
	}

	pubarr1 := [KeySize]byte(*pub1)
	pubarr2 := [KeySize]byte(*pub2)
	pubarr3 := [KeySize]byte(*prv2.Public())
	prvc := bytes.Compare(prv2.rprv[:], prv1.rprv[:])
	pubc1 := bytes.Compare(pubarr2[:], pubarr1[:])
	pubc2 := bytes.Compare(pubarr3[:], pubarr2[:])

	if prvc != 0 || pubc1 != 0 || pubc2 != 0 {
		t.Errorf("Key marshalling test failed.")
	}
}
