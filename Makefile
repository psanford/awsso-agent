BIN=awsso

GOSRC=$(wildcard *.go) $(wildcard **/*.go)
GOMOD=$(wildcard go.mod) $(wildcard go.sum)

$(BIN): $(GOSRC) $(GOMOD)
	go test -v ./...
	go build -o $@
