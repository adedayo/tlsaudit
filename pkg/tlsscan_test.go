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

func TestRSA4096(t *testing.T) {
	for _, scan := range ScanCIDRTLS("rsa4096.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "RSA" {
				t.Errorf("Expecting an RSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[0]
			if kl != "4096" {
				t.Errorf("Expecting cert key length of 4096, but got %s", kl)
			}
		}
	}
}

func TestRSA2048(t *testing.T) {
	for _, scan := range ScanCIDRTLS("rsa2048.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "RSA" {
				t.Errorf("Expecting an RSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[0]
			if kl != "2048" {
				t.Errorf("Expecting cert key length of 2048, but got %s", kl)
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

func TestECDSA256(t *testing.T) {
	for _, scan := range ScanCIDRTLS("ecc256.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "ECDSA" {
				t.Errorf("Expecting an ECDSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[1]
			if kl != "256" {
				t.Errorf("Expecting cert key length of 256, but got %s", kl)
			}
		}
	}
}

func TestSHA256(t *testing.T) {
	for _, scan := range ScanCIDRTLS("sha256.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if strings.Split(cert.SignatureAlgorithm, "-")[0] != "SHA256" {
				t.Errorf("Expecting a SHA256 signature algorithm but got %s", cert.SignatureAlgorithm)
			}
		}
	}
}

func TestSHA384(t *testing.T) {
	for _, scan := range ScanCIDRTLS("sha384.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if strings.Split(cert.SignatureAlgorithm, "-")[0] != "SHA384" {
				t.Errorf("Expecting a SHA384 signature algorithm but got %s", cert.SignatureAlgorithm)
			}
		}
	}
}

func TestSHA512(t *testing.T) {
	for _, scan := range ScanCIDRTLS("sha512.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if strings.Split(cert.SignatureAlgorithm, "-")[0] != "SHA512" {
				t.Errorf("Expecting a SHA512 signature algorithm but got %s", cert.SignatureAlgorithm)
			}
		}
	}
}

func TestSHA1InChain(t *testing.T) {
	for _, scan := range ScanCIDRTLS("sha1-intermediate.badssl.com:443", config) {
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			found := false
			chain := []string{}
			for _, cert := range certChain {
				chain = append(chain, cert.SignatureAlgorithm)
				if strings.Split(cert.SignatureAlgorithm, "-")[0] == "SHA1" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expecting a certificate chain with SHA1 signature algorithm in it but got %s", strings.Join(chain, ", "))
			}
		}
	}
}
