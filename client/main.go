package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const awsPEM = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----`

const service = `https://g79e4xxv6j.execute-api.us-east-1.amazonaws.com/Prod/hello`

const certificateArn = `arn:aws:iot:us-east-1:491933654996:cert/eef301064d61e9764c033d8a09487eba1f6eecacf735c57d899cff8e224f7010`
const certificateID = `eef301064d61e9764c033d8a09487eba1f6eecacf735c57d899cff8e224f7010`
const certificatePem = "-----BEGIN CERTIFICATE-----\nMIIDWjCCAkKgAwIBAgIVAJrvucLQVe9EDXJB3ljcZT5A+P6WMA0GCSqGSIb3DQEB\nCwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\nIEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xOTA4MDIxMzQ0\nNThaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\ndGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClpVjEbMSU2EnkeRhv\ntnVGwH9MJZ2rHHBW+8YhUKnNN+r4z4mNh/UDf2vJBbpu5db2RlD3JzLc5t5vUrVo\nz/Qs+Z2ZRSvGR5W3KhS2TwFroKh/7atlHCrfF1AGNw+v/sB2glBUK3POb5uEBezw\nDxQd47WToLcx3KSce5y1tD0vIQ3K7WOquyH6zdJ2WaQGn/KASOPdbOgEFQEl9pEL\npMVfY60E/WSplZ5LkZzkulWSGlaJ4jKgWfKZer3moI5nq3N1bM+M2Kf644TAmbjC\npAqqRpTc74vnLGct8DSjRWXi4LcRVMaqb3J+cOZYImljIUXmaXilTANouW4Mkb5H\n2doPAgMBAAGjYDBeMB8GA1UdIwQYMBaAFDorIwXB2VypP2dou/4hR6pTYyeFMB0G\nA1UdDgQWBBQigAn0jrroy9CiBGOHosgCFQ2HbDAMBgNVHRMBAf8EAjAAMA4GA1Ud\nDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAqJUTKYihGXoyu0+gVL5J/1G2\nMnWbqdlVK21i4E4wnSoqVmyezHY1dDUVyqQljcMie1iSdFRTgxqicTHdmYOCfXCj\nUKj2/8yoZEc00ELbver9vwW8MhXOcfb2k+Fh68almYWXa8XO1d/8B5Ok3a93ACQP\nPPYizPVtTqrTpWUt69Wr4JW6/4dTdRQBOKe+KtzrM8TcI+E5pawrm327qT8ELr4Y\nW/0TY/jZW+vmLTMMMMDTzRK7fvXC2tVtQWXdDoaQjdojQUJ7OY7CyR8TD0//wmq6\nlc8nPy9jEBwsdQ7BZ0OjasE93hr5gdEDmsuEU3BCCtRXORm0Hju5Oehw79C+sg==\n-----END CERTIFICATE-----\n"
const publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApaVYxGzElNhJ5HkYb7Z1\nRsB/TCWdqxxwVvvGIVCpzTfq+M+JjYf1A39ryQW6buXW9kZQ9ycy3Obeb1K1aM/0\nLPmdmUUrxkeVtyoUtk8Ba6Cof+2rZRwq3xdQBjcPr/7AdoJQVCtzzm+bhAXs8A8U\nHeO1k6C3MdyknHuctbQ9LyENyu1jqrsh+s3SdlmkBp/ygEjj3WzoBBUBJfaRC6TF\nX2OtBP1kqZWeS5Gc5LpVkhpWieIyoFnymXq95qCOZ6tzdWzPjNin+uOEwJm4wqQK\nqkaU3O+L5yxnLfA0o0Vl4uC3EVTGqm9yfnDmWCJpYyFF5ml4pUwDaLluDJG+R9na\nDwIDAQAB\n-----END PUBLIC KEY-----\n"
const privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEApaVYxGzElNhJ5HkYb7Z1RsB/TCWdqxxwVvvGIVCpzTfq+M+J\njYf1A39ryQW6buXW9kZQ9ycy3Obeb1K1aM/0LPmdmUUrxkeVtyoUtk8Ba6Cof+2r\nZRwq3xdQBjcPr/7AdoJQVCtzzm+bhAXs8A8UHeO1k6C3MdyknHuctbQ9LyENyu1j\nqrsh+s3SdlmkBp/ygEjj3WzoBBUBJfaRC6TFX2OtBP1kqZWeS5Gc5LpVkhpWieIy\noFnymXq95qCOZ6tzdWzPjNin+uOEwJm4wqQKqkaU3O+L5yxnLfA0o0Vl4uC3EVTG\nqm9yfnDmWCJpYyFF5ml4pUwDaLluDJG+R9naDwIDAQABAoIBAEnxSHHOd+ZVso6J\nu+3KTgm6TljohbxnYoKBu40Nm+7e4kYVJrsGEMpx6+R9aR6t/MpM00GwvtS7PloF\nWrOh+MbG2qIbrZHCTMPJxhsno2OvAOiyaIsnCsAxgOh1VcxjdPix7TfVecmSKqLB\nnmX+5ST+jASNfpmEe/radzbpcVKCv7qNBK7a5fz/suHA55vUfqHJCV8W28s9Amfx\nvZIpPA8WW0KOmQGAEFaST5SScNc15j/bTjagfnCXtZ0XOfN4xDnRTPdsHfQz9I5y\n8/88Sxk8c5bouSBMGWPwj651MaRz7hATv4NuJ4o8fE5MTFHJsdAxzW08u1uVCaW8\nErjdiEECgYEA2EdOadwFMUhId7SrPD8wkvbBAHm85flbVCiyV2EZUsY12nkrfSy+\nEIA4eaT/K3JWVTlJ5IgufqrSyO75tgqs7OoBDELpT6x11hj2kxZD2466XvuhktWv\nTIrMlklUOcj7UBRACqFiy7+EPbx4kHhSjoxXgiqs6zZe8YbbxF4yTC8CgYEAxBF2\nXK6bt0bLZUwQ1pK/HR4O732Nau9a4havkthG+w/RCU714cgJIK+PKa6DmCheqy80\n1f4RsvrYK881KkxTpUxKCi4f6p1BSJnwJh4zlnuo8Lq4Y5/rv/i2SpcMhGOz53cn\ncmxjvOzddngCEN45VCoPCxzW5qFcUnFFlDjYeCECgYEAuQ9CpEf0VXgBMhRwlMuI\n96eV+58vKCTWpctw1l2qOm6JtBgMQz5en2XnbQbmpDlgb+nmNVrlVdM7K114Y/D8\niHeuT9yNIHR0G68ehTr+80ZMaGutlCOtrLPzXQD/xbYYfCvnpHD1RVvpfp3fF9cs\n5PZnBmUXsufCE66OK5diOFcCgYEAivotwehqq/Dcf4L5dH80RHln8M44DZJ4A0Y9\nUYNIXPGLJGP52f6mqaqHee4fjR0gbYraksyy0wEHdZY8gyzzJXn8CVdEfFLXUZT8\nKqjBvGsPBwPza3qR6tNqs1h6IOVjQjCtn2fBEst691x9amN6k3P0kdXxZiz+edmc\njkH0/sECgYBz6QpV7r1iFu7Po/5vDhCbo3asre7cItmV8GrYtw+lfhkXw/lD50XQ\n5Q3crVsaCBIPz032JzPm8JrNgVUR+ZuAPHWsffb4ZBdRfmF9whbAdaqQYLAT0QI0\nG3E0f+TuhoVjBOc9rYaRPD7AsJxO1UGEL5ayXND4ZR1RRrH8J6RLNQ==\n-----END RSA PRIVATE KEY-----\n"
const rootCA = "-----BEGIN CERTIFICATE-----\r\nMIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\r\nyjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\nExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\nU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\nZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\naG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\r\nMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\r\nZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\r\nbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\r\nU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\r\naXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\r\nnmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\r\nt0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\r\nSdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\r\nBO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\r\nrCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\r\nNIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\r\nBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\r\nBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\r\naXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\r\nMzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\r\np6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\r\n5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\r\nWE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\r\n4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\r\nhnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\r\n-----END CERTIFICATE-----"
const thingname = "ascas"

const cvm = `https://bm6ekmhoyk.execute-api.us-east-1.amazonaws.com/LATEST/getcert?serialNumber=%v&deviceToken=%v`

const endpoint = `https://c26qx0g6fxbjka.credentials.iot.us-east-1.amazonaws.com/role-aliases/DeviceRole/credentials`

type keypair struct {
	PublicKey  string
	PrivateKey string
	RootCA     string
}

type cert struct {
	CertificateArn string  `json:"certificateArn"`
	CertificateID  string  `json:"certificateId"`
	CertificatePem string  `json:"certificatePem"`
	KeyPair        keypair `json:"keyPair"`
}

type credentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SessionToken    string `json:"sessionToken"`
	SecretAccessKey string `json:"secretAccessKey"`
}

type access struct {
	Credentials credentials `json:"credentials"`
}

func main() {
	key := cert{}

	sn := flag.String("sn", "", "Serial Number")
	pin := flag.String("pin", "", "PIN")
	create := flag.Bool("create", false, "Create Device")
	flag.Parse()
	if *sn == "" || *pin == "" {
		flag.PrintDefaults()
		return
	}
	if *create {
		resp, err := http.Get(fmt.Sprintf(cvm, *sn, *pin))
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		fmt.Println("body", string(body))
		err = json.Unmarshal(body, &key)

		ioutil.WriteFile(*sn+"cer.pem", []byte(key.CertificatePem), 0644)
		ioutil.WriteFile(*sn+"pri.pem", []byte(key.KeyPair.PrivateKey), 0644)
	} else {
		b, err := ioutil.ReadFile(*sn + "cer.pem")
		if err != nil {
			log.Fatal(*sn + "cer.pem Does not exist")
		}
		key.CertificatePem = string(b)
		b, err = ioutil.ReadFile(*sn + "pri.pem")
		if err != nil {
			log.Fatal(*sn + "cer.pri Does not exist")
		}
		key.KeyPair.PrivateKey = string(b)
	}
	// svc := iot.New(session.New(), &aws.Config{})

	// ip := iot.DescribeEndpointInput{EndpointType: aws.String("iot:CredentialProvider")}
	// ep, err := svc.DescribeEndpoint(&ip)
	// fmt.Println(ep, err)

	// alias,err:=svc.ListRoleAliases(&iot.ListRoleAliasesInput{})

	// ip2 := iot.CreateRoleAliasInput{RoleAlias: aws.String("DeviceRole"), RoleArn: aws.String("arn:aws:iam::491933654996:role/IOTDeviceRole")}

	// alias, err := svc.CreateRoleAlias(&ip2)
	// fmt.Println("Alias", alias, err)
	//curl --cert your certficate --key your device certificate key pair -H "x-amzn-iot-thingname: your thing name" --cacert AmazonRootCA1.pem https://your endpoint/role-aliases/your role alias/credentials

	// curl --cert cert.pem --key private.pem -H "x-amzn-iot-thingname: ascas" --cacert AmazonRootCA1.pem https://c26qx0g6fxbjka.credentials.iot.us-east-1.amazonaws.com/role-aliases/DeviceRole/credentials

	tlscert, err := tls.X509KeyPair([]byte(key.CertificatePem), []byte(key.KeyPair.PrivateKey))
	if err != nil {
		log.Fatal(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(awsPEM))
	if !ok {
		log.Fatal("failed to parse root certificate")
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlscert},
		RootCAs:      roots,
	}
	tlsConfig.BuildNameToCertificate()

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", endpoint, nil)
	req.Header.Add("x-amzn-iot-thingname", *sn)

	conn, err := client.Do(req)

	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Body.Close()
	data, err := ioutil.ReadAll(conn.Body)
	if err != nil {
		log.Fatal(err)
	}

	a := access{}
	err = json.Unmarshal(data, &a)

	ioutil.WriteFile(*sn+"access.key", []byte(a.Credentials.AccessKeyID), 0644)
	ioutil.WriteFile(*sn+"session.key", []byte(a.Credentials.SessionToken), 0644)
	ioutil.WriteFile(*sn+"secret.key", []byte(a.Credentials.SecretAccessKey), 0644)

	fmt.Println(a.Credentials)
}
