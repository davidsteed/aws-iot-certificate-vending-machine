package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iot"
)

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	region := os.Getenv("AWS_REGION")
	accountID := request.RequestContext.AccountID

	svc := iot.New(session.New(), &aws.Config{Region: aws.String(region)})

	alias, err := svc.ListRoleAliases(&iot.ListRoleAliasesInput{})

	return events.APIGatewayProxyResponse{
		Body:       fmt.Sprintf(" %v  %v %v %v", accountID, region, alias, err),
		StatusCode: 200,
	}, nil
}

func main() {
	lambda.Start(handler)
}
