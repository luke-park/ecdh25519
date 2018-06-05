.PHONY: travis fmt vet

NAME = ecdh25519

GOPATH = ${CURDIR}/../..
GOOS = windows
GOARCH = amd64

travis:
	GOPATH="$(GOPATH)" GOOS="$(GOOS)" GOARCH="$(GOARCH)"
	go get -u golang.org/x/crypto/curve25519
	go test "./..."

fmt:
	gofmt -w -l "$(GOPATH)"

vet:
	go vet "$(NAME)/..."
