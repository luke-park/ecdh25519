![](icon.png)

<a href="https://godoc.org/github.com/luke-park/ecdh25519"><img src="https://godoc.org/github.com/luke-park/ecdh25519?status.svg" alt="GoDoc"></a>

# ecdh25519
A simple to use implementation of ECDH with curve25519 for Go.  The core
mathematics of this algorithm are already present in
golang.org/x/crypto/curve25519, this library just implements the algorithm
in such a way that knowledge of the underlying mathematics is not necessary.

## Example
The below example does not include proper error handling.
```go
package main

import (
    "github.com/luke-park/ecdh25519"
)

func main() {
    prv1, _ := ecdh25519.GenerateKey()
    prv2, _ := ecdh25519.GenerateKey()

    s1 := prv1.ComputeSecret(prv2.Public())
    s2 := prv2.ComputeSecret(prv1.Public())
    // bytes.Compare(s1, s2) == 0
}
```

## Documentation
The full documentation of this package can be found on [GoDoc](https://godoc.org/github.com/luke-park/ecdh25519).
