package csrgenerator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

const keyBits int = 4096

// Subject within CSR
type Subject pkix.Name

// Service _
type Service struct {
	Subj Subject
}

// NewCSR _
func NewService(s Subject) *Service {
	return &Service{Subj: s}
}

func (c *Service) GenPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBits)
}

// GenCSRTemplate _
func (c *Service) GenCSR(key *rsa.PrivateKey) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name(c.Subj),
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, err
	}

	return PEMEncode(csrDER), nil
}

func PEMEncode(csrDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}
