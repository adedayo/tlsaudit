package tlsaudit

//TODO implement tests
import (
	"strings"
	"testing"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

var (
	config = tlsmodel.ScanConfig{}
)

// func TestIncompleteChain(t *testing.T) {
// 	for scan := range ScanCIDRTLS("incomplete-chain.badssl.com:443", config) {
// 		if len(scan.CertificatesWithChainIssue) == 0 {
// 			t.Errorf("Expected to find a chain issue")
// 		}
// 	}
// }

func TestRSA8192(t *testing.T) {
	// results := []<-chan tlsmodel.ScanResult{}
	// scans := make(map[string]tlsmodel.ScanResult)

	// results = append(results, ScanCIDRTLS("rsa8192.badssl.com:443", config))
	// for result := range MergeResultChannels(results...) {
	// 	key := result.Server + result.Port
	// 	if _, present := scans[key]; !present {
	// 		scans[key] = result
	// 	}
	// }

	t.Logf("\nStarted scan\n")
	for _, scan := range ScanCIDRTLS("rsa8192.badssl.com:443", config) {
		t.Log("Got a scan")
		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
			cert := certChain[0]
			if cert.PublicKeyAlgorithm != "RSAs" {
				t.Errorf("Expecting an RSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
			}
			kl := strings.Split(cert.Key, " ")[0]
			if kl != "8192" {
				t.Errorf("Expecting cert key length of 8192, but got %s", kl)
			}
		}
	}
}

// func TestECDSA384(t *testing.T) {
// 	for scan := range ScanCIDRTLS("ecc384.badssl.com:443", config) {
// 		for _, certChain := range scan.ToHumanScanResult().CertificatesPerProtocol {
// 			cert := certChain[0]
// 			if cert.PublicKeyAlgorithm != "ECDSA" {
// 				t.Errorf("Expecting an ECDSA public key algorithm but got %s", cert.PublicKeyAlgorithm)
// 			}
// 			kl := strings.Split(cert.Key, " ")[1]
// 			if kl != "384" {
// 				t.Errorf("Expecting cert key length of 384, but got %s", kl)
// 			}
// 		}
// 	}
// }
