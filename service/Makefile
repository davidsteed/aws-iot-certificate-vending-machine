.PHONY: deps clean build

deps:
	go get -u ./...

clean: 
	rm -rf ./testservice/testservice
	
build:
	GOOS=linux GOARCH=amd64 go build -o testservice/testservice ./testservice

deploy:
	sam package --template-file template.yaml --s3-bucket testsam773478 --output-template-file packaged-template.yml
	aws cloudformation deploy --template-file /Users/davidsteed/aws/aws-iot-certificate-vending-machine/service/packaged-template.yml --stack-name testiotlambda --capabilities CAPABILITY_NAMED_IAM
