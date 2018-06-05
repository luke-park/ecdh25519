.PHONY: travis fmt vet

NAME = ecdh25519

GOPATH = ${CURDIR}/../..
GOOS = windows
GOARCH = amd64

travis:
	GOPATH="$(GOPATH)" GOOS="$(GOOS)" GOARCH="$(GOARCH)"
	go test "./..."

fmt:
	gofmt -w -l "$(GOPATH)"

vet:
	go vet "$(NAME)/..."
