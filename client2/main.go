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

	"net/url"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
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

const cvm = `https://24u6hl089c.execute-api.us-east-1.amazonaws.com/LATEST/getcert?serialNumber=%v&deviceToken=%v`

const role = "DeviceRole"
const providerName = `IOTCredentialsEndpointProvider`

const expiryWindow = 5 * time.Minute
const endpoint = `c26qx0g6fxbjka.credentials.iot.us-east-1.amazonaws.com`
const service = `https://ufollr6yvd.execute-api.us-east-1.amazonaws.com/Prod/hello`

var caCertPool *x509.CertPool

type keypair struct {
	PublicKey  string
	PrivateKey string
	RootCA     string
}

// Cert is the certifiates returned from AWS IOT
type Cert struct {
	CertificateArn string  `json:"certificateArn"`
	CertificateID  string  `json:"certificateId"`
	CertificatePem string  `json:"certificatePem"`
	KeyPair        keypair `json:"keyPair"`
}

func init() {

	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(awsPEM))
}

// NewCredentials returns a Credentials wrapper for retrieving credentials from an iot credential provider endpoint concurrently.
func NewCredentials(endpointAddress, thingName, roleAlias string, certPEMBlock, keyPEMBlock []byte) (*credentials.Credentials, error) {
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}
	return credentials.NewCredentials(&provider{
		endpointAddress: endpointAddress,
		thingName:       thingName,
		roleAlias:       roleAlias,
		c: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{cert},
				},
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}), nil
}

type provider struct {
	endpointAddress string
	thingName       string
	roleAlias       string
	c               *http.Client
	credentials.Expiry
}

func (p *provider) Retrieve() (credentials.Value, error) {
	req, err := http.NewRequest(http.MethodGet, (&url.URL{
		Scheme: "https",
		Host:   p.endpointAddress,
		Path:   path.Join("/role-aliases", p.roleAlias, "credentials"),
	}).String(), nil)
	if err != nil {
		return credentials.Value{}, err
	}
	req.Header.Set("x-amzn-iot-thingname", p.thingName)
	resp, err := p.c.Do(req)
	if err != nil {
		return credentials.Value{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var result struct {
		Credentials struct {
			AccessKeyID     string    `json:"accessKeyId"`
			SecretAccessKey string    `json:"secretAccessKey"`
			SessionToken    string    `json:"sessionToken"`
			Expiration      time.Time `json:"expiration"`
		} `json:"credentials"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return credentials.Value{}, err
	}
	p.SetExpiration(result.Credentials.Expiration, expiryWindow)
	return credentials.Value{
		AccessKeyID:     result.Credentials.AccessKeyID,
		SecretAccessKey: result.Credentials.SecretAccessKey,
		SessionToken:    result.Credentials.SessionToken,
		ProviderName:    providerName,
	}, nil
}

func main() {
	key := Cert{}

	sn := flag.String("sn", "", "Serial Number")
	pin := flag.String("pin", "", "PIN")
	create := flag.Bool("create", false, "Create Device")
	flag.Parse()
	if *sn == "" || *pin == "" {
		flag.PrintDefaults()
		return
	}
	if *create {
		err := key.GetCerts(*sn, *pin)
		if err != nil {
			log.Fatal(err)
		}
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

	creds, _ := NewCredentials(endpoint, *sn, role, []byte(key.CertificatePem), []byte(key.KeyPair.PrivateKey))

	signer := v4.NewSigner(creds)

	cl := new(http.Client)
	req, err := http.NewRequest("GET", service, nil)
	if err != nil {
		log.Fatal("Create New Request", err)
	}

	_, err = signer.Sign(req, nil, "execute-api", "us-east-1", time.Now())
	if err != nil {
		log.Fatal("Signer err", err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("response to", service, "\n", string(data))

}

// GetCerts get the certificates for a device from AWS IOT
func (key *Cert) GetCerts(sn, pin string) (err error) {
	resp, err := http.Get(fmt.Sprintf(cvm, sn, pin))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	err = json.Unmarshal(body, &key)
	return err
}
