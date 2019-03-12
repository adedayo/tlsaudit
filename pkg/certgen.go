package tlsaudit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
)

var (
	certsPath = ".tlsaudit/certs"
)

func init() {
	home, err := homedir.Expand(filepath.FromSlash("~/.tlsaudit/certs"))
	if err == nil {
		certsPath = home
	}
	//create certificates directory if it doesn't exist
	if _, err := os.Stat(certsPath); os.IsNotExist(err) {
		if err2 := os.MkdirAll(certsPath, 0755); err2 != nil {
			log.Errorln("Could not create the path ", certsPath)
		}
	}
}

func genRootCert() (x509.Certificate, *ecdsa.PrivateKey, error) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)
	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = saveKey("rootCAKey.key", key)
	if err != nil {
		return x509.Certificate{}, key, err
	}
	cert := x509.Certificate{
		SerialNumber:          serialNo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject: pkix.Name{
			Organization: []string{"TLS Audit Root"},
			CommonName:   "TLS Audit Root CA",
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return x509.Certificate{}, key, err
	}

	if _, err = saveCert("rootCACert.pem", der); err != nil {
		return x509.Certificate{}, key, err
	}
	return cert, key, nil
}

func genCerts() (certFile, keyFile string, err error) {
	//names of certificate and key files for the TLSAudit API service endpoint
	suppliedCert := filepath.Join(certsPath, "tlsaudit.pem")
	suppliedKey := filepath.Join(certsPath, "tlsaudit.key")
	//if certificate and key are provided, attempt to use them, otherwise generate self-signed ones
	if _, err := os.Stat(suppliedCert); !os.IsNotExist(err) {
		if _, err := os.Stat(suppliedKey); !os.IsNotExist(err) {
			return suppliedCert, suppliedKey, nil
		}
	}
	rootCert, rootKey, err := genRootCert()
	if err != nil {
		return certFile, keyFile, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certFile, keyFile, err
	}
	keyFile, err = saveKey("tlsaudit-self-signed.key", key)
	if err != nil {
		return certFile, keyFile, err
	}
	serialNo, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return certFile, keyFile, err
	}
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 6, 0)
	cert := x509.Certificate{
		SerialNumber:          serialNo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject: pkix.Name{
			Organization: []string{"TLS Audit organisation"},
			CommonName:   "TLS Audit Organisation certificate",
		},
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &cert, &rootCert, &key.PublicKey, rootKey)
	if err != nil {
		return certFile, keyFile, err
	}
	certFile, err = saveCert("tlsaudit-self-signed-cert.pem", der)
	if err != nil {
		return certFile, keyFile, err
	}
	return certFile, keyFile, nil
}

func saveKey(fileName string, key *ecdsa.PrivateKey) (string, error) {
	fileName = filepath.Join(certsPath, fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return fileName, err
	}
	defer file.Close()
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fileName, err
	}
	if err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		return fileName, err
	}
	return fileName, nil
}

func saveCert(fileName string, der []byte) (string, error) {
	fileName = filepath.Join(certsPath, fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return fileName, err
	}
	defer file.Close()
	if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fileName, err
	}
	return fileName, nil
}
