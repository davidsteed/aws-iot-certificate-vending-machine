package main

import (
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

//var svc *iot.IoT

// func init() {
// 	svc = iot.New(session.New())

// }

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	//res, err := svc.DescribeCertificate(
	//	&iot.DescribeCertificateInput{CertificateId: aws.String(request.RequestContext.Identity.User)})

	return events.APIGatewayProxyResponse{
		Body:       fmt.Sprintf("%+v\n", request.RequestContext.Identity.User),
		StatusCode: 200,
	}, nil
}

func main() {
	lambda.Start(handler)
}
