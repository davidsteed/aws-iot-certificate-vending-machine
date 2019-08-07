.PHONY: deps clean build



clean: 
	rm lambda/cvm-iot.zip
	
build:
	zip lambda/cvm-iot.zip lambda/*

deploy:
	aws s3 cp lambda/cvm-iot.zip s3://testsam773478
	aws cloudformation deploy --template-file template.yaml --stack-name certificatevendingmachine --capabilities CAPABILITY_IAM