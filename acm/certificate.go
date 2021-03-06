package acm

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	awsacm "github.com/aws/aws-sdk-go/service/acm"
	"github.com/jpignata/fargate/console"
	"golang.org/x/time/rate"
)

type Certificate struct {
	Arn                     string
	Status                  string
	SubjectAlternativeNames []string
	DomainName              string
	Validations             []CertificateValidation
	Type                    string
}

func (c *Certificate) AddValidation(v CertificateValidation) {
	c.Validations = append(c.Validations, v)
}

func (c *Certificate) Inflate(d *awsacm.CertificateDetail) *Certificate {
	c.Status = aws.StringValue(d.Status)
	c.SubjectAlternativeNames = aws.StringValueSlice(d.SubjectAlternativeNames)
	c.Type = aws.StringValue(d.Type)

	for _, domainValidation := range d.DomainValidationOptions {
		validation := CertificateValidation{
			Status:     aws.StringValue(domainValidation.ValidationStatus),
			DomainName: aws.StringValue(domainValidation.DomainName),
		}

		if domainValidation.ResourceRecord != nil {
			validation.ResourceRecord = CertificateResourceRecord{
				Type:  aws.StringValue(domainValidation.ResourceRecord.Type),
				Name:  aws.StringValue(domainValidation.ResourceRecord.Name),
				Value: aws.StringValue(domainValidation.ResourceRecord.Value),
			}
		}

		c.AddValidation(validation)
	}

	return c
}

func (c *Certificate) IsIssued() bool {
	return c.Status == awsacm.CertificateStatusIssued
}

type CertificateValidation struct {
	Status         string
	DomainName     string
	ResourceRecord CertificateResourceRecord
}

func (v *CertificateValidation) IsPendingValidation() bool {
	return v.Status == awsacm.DomainStatusPendingValidation
}

func (v *CertificateValidation) IsSuccess() bool {
	return v.Status == awsacm.DomainStatusSuccess
}

func (v *CertificateValidation) IsFailed() bool {
	return v.Status == awsacm.DomainStatusFailed
}

func (v *CertificateValidation) ResourceRecordString() string {
	if v.ResourceRecord.Type == "" {
		return ""
	}

	return fmt.Sprintf("%s %s -> %s",
		v.ResourceRecord.Type,
		v.ResourceRecord.Name,
		v.ResourceRecord.Value,
	)
}

type CertificateResourceRecord struct {
	Type  string
	Name  string
	Value string
}

func (c *Certificate) IsPendingValidation() bool {
	return c.Status == awsacm.CertificateStatusPendingValidation
}

func ValidateDomainName(domainName string) error {
	if len(domainName) < 1 || len(domainName) > 253 {
		return fmt.Errorf("The domain name must be between 1 and 253 characters in length")
	}

	if strings.Count(domainName, ".") > 62 {
		return fmt.Errorf("The domain name cannot exceed 63 octets")
	}

	if strings.Count(domainName, ".") == 0 {
		return fmt.Errorf("The domain name requires at least 2 octets")
	}

	return nil
}

func ValidateAlias(domainName string) error {
	if len(domainName) < 1 || len(domainName) > 253 {
		return fmt.Errorf("The alias domain name must be between 1 and 253 characters in length")
	}

	if strings.Count(domainName, ".") > 252 {
		return fmt.Errorf("The alias domain name cannot exceed 253 octets")
	}

	if strings.Count(domainName, ".") == 0 {
		return fmt.Errorf("The alias domain name requires at least 2 octets")
	}

	return nil
}

func (acm *ACM) RequestCertificate(domainName string, aliases []string) {
	console.Debug("Requesting ACM certificate")

	requestCertificateInput := &awsacm.RequestCertificateInput{
		DomainName:       aws.String(domainName),
		ValidationMethod: aws.String(awsacm.ValidationMethodDns),
	}

	if len(aliases) > 0 {
		requestCertificateInput.SetSubjectAlternativeNames(aws.StringSlice(aliases))
	}

	_, err := acm.svc.RequestCertificate(requestCertificateInput)

	if err != nil {
		console.ErrorExit(err, "Couldn't request ACM certificate")
	}
}

func (acm *ACM) ListCertificates() []*Certificate {
	var wg sync.WaitGroup

	ctx := context.Background()
	ch := make(chan *Certificate)
	certificates := acm.listCertificates()
	limiter := rate.NewLimiter(10, 1)

	for i := 0; i < 4; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for c := range ch {
				if err := limiter.Wait(ctx); err == nil {
					certificateDetail := acm.describeCertificate(c.Arn)
					c.Inflate(certificateDetail)
				}
			}
		}()
	}

	for _, c := range certificates {
		ch <- c
	}

	close(ch)

	wg.Wait()

	return certificates
}

func (acm *ACM) DescribeCertificate(domainName string) *Certificate {
	var certificate *Certificate

	for _, c := range acm.listCertificates() {
		if c.DomainName == domainName {
			certificateDetail := acm.describeCertificate(c.Arn)
			certificate = c.Inflate(certificateDetail)

			break
		}
	}

	if certificate == nil {
		err := fmt.Errorf("Could not find ACM certificate for %s", domainName)
		console.ErrorExit(err, "Couldn't describe ACM certificate")
	}

	return certificate
}

func (acm *ACM) ListCertificateDomainNames(certificateArns []string) []string {
	var domainNames []string

	for _, certificate := range acm.listCertificates() {
		for _, certificateArn := range certificateArns {
			if certificate.Arn == certificateArn {
				domainNames = append(domainNames, certificate.DomainName)
			}
		}
	}

	return domainNames
}

func (acm *ACM) ImportCertificate(certificate, privateKey, certificateChain []byte) {
	console.Debug("Importing ACM certificate")

	input := &awsacm.ImportCertificateInput{
		Certificate: certificate,
		PrivateKey:  privateKey,
	}

	if len(certificateChain) != 0 {
		input.SetCertificateChain(certificateChain)
	}

	_, err := acm.svc.ImportCertificate(input)

	if err != nil {
		console.ErrorExit(err, "Couldn't import certificate")
	}
}

func (acm *ACM) DeleteCertificate(domainName string) {
	var err error

	certificates := acm.listCertificates()

	for _, certificate := range certificates {
		if certificate.DomainName == domainName {
			_, err := acm.svc.DeleteCertificate(
				&awsacm.DeleteCertificateInput{
					CertificateArn: aws.String(certificate.Arn),
				},
			)

			if err != nil {
				console.ErrorExit(err, "Couldn't destroy certificate")
			}

			return
		}
	}

	err = fmt.Errorf("Certificate for %s not found", domainName)
	console.ErrorExit(err, "Couldn't destroy certificate")
}

func (acm *ACM) describeCertificate(arn string) *awsacm.CertificateDetail {
	resp, err := acm.svc.DescribeCertificate(
		&awsacm.DescribeCertificateInput{
			CertificateArn: aws.String(arn),
		},
	)

	if err != nil {
		console.ErrorExit(err, "Couldn't describe ACM certificate")
	}

	return resp.Certificate
}

func (acm *ACM) listCertificates() []*Certificate {
	certificates := []*Certificate{}

	err := acm.svc.ListCertificatesPagesWithContext(
		context.Background(),
		&awsacm.ListCertificatesInput{},
		func(resp *awsacm.ListCertificatesOutput, lastPage bool) bool {
			for _, c := range resp.CertificateSummaryList {
				certificates = append(
					certificates,
					&Certificate{
						Arn:        aws.StringValue(c.CertificateArn),
						DomainName: aws.StringValue(c.DomainName),
					},
				)
			}

			return true
		},
	)

	if err != nil {
		console.ErrorExit(err, "Could not list ACM certificates")
	}

	return certificates
}
