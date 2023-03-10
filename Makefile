APP:=nuts-jwt-generator

default: build

.PHONY: release
release:
	rm -fr release
	mkdir release
	GOOS=windows GOARCH=amd64 go build -o release/$(APP)-amd64-win.exe .
	GOOS=darwin GOARCH=amd64 go build -o release/$(APP)-amd64-darwin .
	GOOS=darwin GOARCH=arm64 go build -o release/$(APP)-arm64-darwin .
	GOOS=linux GOARCH=amd64 go build -o release/$(APP)-amd64-linux .

build:
	go build .

test:
	go test .
