.PHONY: deps clean build

deps:
	go get -u ./...

clean: 
	rm -rf ./testservice/testservice
	
build:
	GOOS=linux GOARCH=amd64 go build -o testservice/testservice ./testservice