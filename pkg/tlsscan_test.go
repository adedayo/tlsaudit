package tlsaudit

import (
	"strings"
	"testing"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

var (
	config = tlsmodel.ScanConfig{
		Timeout: 5,
	}
)

func TestIncompleteChain(t *testing.T) {
	for _, scan := range ScanCIDRTLS("incomplete-chain.badssl.com:443", config) {
		hs := scan.ToHumanScanResult()
		if len(hs.CertificatesWithChainIssue) == 0 {
			t.Errorf("Expected to find a chain issue %#v", hs)
		}
	}
}

func TestRSA8192(t *testing.T) {
	for _, scan := range ScanCIDRTLS("rsa8192.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "RSA" {
				t.Errorf("Expecting an RSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[0]
			if kl != "8192" {
				t.Errorf("Expecting cert key length of 8192, but got %s", kl)
			}
		}
	}
}

func TestECDSA384(t *testing.T) {
	for _, scan := range ScanCIDRTLS("ecc384.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "ECDSA" {
				t.Errorf("Expecting an ECDSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[1]
			if kl != "384" {
				t.Errorf("Expecting cert key length of 384, but got %s", kl)
			}
		}
	}
}
