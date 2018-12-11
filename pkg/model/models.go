package tlsmodel

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureAnonymous = 0
	signatureRSA       = 1
	signatureDSA       = 2
	signatureECDSA     = 3
)

//CipherConfig extracts the important elements of a Ciphersuit based on its name
type CipherConfig struct {
	Cipher         string
	KeyExchange    string
	Authentication string
	IsExport       bool
	Encryption     string
	MACPRF         string //MAC (TLS <=1.1) or PseudoRandomFunction (TLS >= 1.2)
}

//IsAuthenticated returns whether the cipher supports authentication
func (cc *CipherConfig) IsAuthenticated() bool {
	return !(cc.Authentication == "NULL" || cc.Authentication == "anon")
}

//GetEncryptionKeyLength returns the effective key lengths of encryption algorithms used in the cipher
//See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf for details
func (cc *CipherConfig) GetEncryptionKeyLength() int {
	kl := -1 //key length
	enc := cc.Encryption
	switch {
	case enc == "NULL" || cc.Cipher == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" || cc.Cipher == "TLS_FALLBACK_SCSV":
		kl = 0
	case strings.Contains(enc, "3DES"):
		kl = 112
	case strings.Contains(enc, "DES40") || strings.Contains(enc, "CBC_40"):
		kl = 40
	case enc == "DES_CBC":
		kl = 56
	case enc == "SEED_CBC" || enc == "IDEA_CBC": //see https://tools.ietf.org/html/rfc4269 for SEED.
		kl = 128
	case enc == "CHACHA20_POLY1305": //see https://tools.ietf.org/html/rfc7539#section-4
		kl = 256
	case len(strings.Split(enc, "_")) >= 2:
		k := strings.Split(enc, "_")[1]
		kk, err := strconv.Atoi(k)
		if err != nil {
			kl = -1
		} else {
			kl = kk
		}
	}
	return kl
}

//GetKeyExchangeKeyLength returns the key length indicated by the cipher
func (cc *CipherConfig) GetKeyExchangeKeyLength(cipher, protocol uint16, scan ScanResult) int {
	kl := -1
	kx := cc.KeyExchange
	switch {
	case kx == "NULL":
		kl = 0
	case kx == "RSA" || (cc.Authentication == "RSA" && strings.Contains(kx, "DH") && func() bool {
		//deal with DH ciphers that use RSA for key exchange
		ex, ok := scan.KeyExchangeByProtocolByCipher[protocol]
		if ok {
			if _, ok2 := ex[cipher]; !ok2 { //ensure that the cipher does not actually exchange keys
				return true
			}
		}
		return false
	}()):
		if c, ok := scan.CertificatesPerProtocol[protocol]; ok {
			certs, err := c.GetCertificates()
			if err == nil && len(certs) > 0 && certs[0].PublicKeyAlgorithm.String() == "RSA" {
				if pub, ok := certs[0].PublicKey.(*rsa.PublicKey); ok {
					kl = pub.N.BitLen()
				}
			}
		}
	case strings.Contains(kx, "DH"): // see https://www.ietf.org/rfc/rfc5480.txt and pp 133 https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf for comparable strength
		if ex, ok := scan.KeyExchangeByProtocolByCipher[protocol]; ok {
			if kex, ok := ex[cipher]; ok {
				if key := kex.Key; len(key) > 2 {
					cid := uint16(key[1])<<8 | uint16(key[2])
					if k, ok := NamedCurveStrength[cid]; ok {
						kl = k
					}
				}
			}
		}
	}

	return kl
}

//GetCipherConfig extracts a `CipherConfig` from the Cipher's IANA string name
// does some basic sanity checks and returns an error if the input cipher name is not sane
// NOTE however, only IANA names from here are assumed and "supported": https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
func GetCipherConfig(cipher string) (config CipherConfig, err error) {
	config.Cipher = cipher
	if cipher == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" || cipher == "TLS_FALLBACK_SCSV" {
		return
	}
	cipher = strings.TrimPrefix(cipher, "TLS_")
	cs := strings.Split(cipher, "_WITH_")
	if len(cs) != 2 {
		return config, fmt.Errorf("Expects a cipher name that contains _WITH_ but got %s", config.Cipher)
	}
	kxAuth, encMAC := cs[0], cs[1]
	config.IsExport = strings.Contains(kxAuth, "EXPORT")
	ka := strings.Split(kxAuth, "_")
	if len(ka) == 1 {
		config.KeyExchange = ka[0]
		config.Authentication = ka[0]
	}
	if len(ka) >= 2 {
		if ka[1] == "EXPORT" {
			config.KeyExchange = kxAuth
			config.Authentication = kxAuth
		} else {
			config.KeyExchange = ka[0]
			config.Authentication = ka[1]
		}
	}

	em := strings.Split(encMAC, "_")
	m := em[len(em)-1]
	if strings.Contains(m, "SHA") || strings.Contains(m, "MD5") || m == "NULL" {
		config.MACPRF = m
		config.Encryption = strings.Join(em[:len(em)-1], "_")
	} else {
		config.Encryption = encMAC
	}

	return
}

//ScanRequest is a model to describe a given TLS Audit scan
type ScanRequest struct {
	CIDRs  []string
	Config ScanConfig
	ScanID string //Non-empty ScanID means this is a ScanRequest to resume an existing, possibly incomplete, scan
}

//PersistedScanRequest persisted version of ScanRequest
type PersistedScanRequest struct {
	Request   ScanRequest
	Hosts     []string
	ScanStart time.Time
	ScanEnd   time.Time
	Progress  int
}

//Marshall scan request
func (psr PersistedScanRequest) Marshall() []byte {
	result := bytes.Buffer{}
	gob.Register(PersistedScanRequest{})
	err := gob.NewEncoder(&result).Encode(&psr)
	if err != nil {
		log.Print(err)
	}
	return result.Bytes()
}

//UnmasharlPersistedScanRequest builds PersistedScanRequest from bytes
func UnmasharlPersistedScanRequest(data []byte) (PersistedScanRequest, error) {

	psr := PersistedScanRequest{}
	gob.Register(psr)
	buf := bytes.NewBuffer(data)
	err := gob.NewDecoder(buf).Decode(&psr)
	if err != nil {
		return psr, err
	}
	return psr, nil
}

//ScanProgress contains partial scam results with an indication of progress
type ScanProgress struct {
	ScanID      string
	Progress    float32
	ScanResults []HumanScanResult // this is the latest scan results delta, at the end of scan all cummulative scans are sent
	Narrative   string            //freeflow text
}

//ScanConfig describes details of how the TLS scan should be carried out
type ScanConfig struct {
	ProtocolsOnly bool
	Timeout       int
	//Number of Packets per Second to send out during underlying port scan
	PacketsPerSecond int
	//Suppress certificate output
	HideCerts bool
	//control whether to produce a running commentary of scan progress or stay quiet till the end
	Quiet bool
}

//SecurityScore contains the overall grading of a TLS/SSL port
type SecurityScore struct {
	ProtocolScore         int
	KeyExchangeScore      int
	CipherEncryptionScore int
	CertificateScore      int
	Grade                 string
	Warnings              []string
}

// KeyExchangeAlgorithm says what it is
type KeyExchangeAlgorithm int

//HostAndPort is a model representing a hostname and a given port
type HostAndPort struct {
	Hostname string
	Port     string
}

// ServerHelloMessage is the TLS server hello message
type ServerHelloMessage struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	TicketSupported              bool
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string
}

// ServerKeyExchangeMsg is the key exchange message
type ServerKeyExchangeMsg struct {
	Raw []byte
	Key []byte
}

// HelloAndKey bundles server hello and ServerKeyExchange messages
type HelloAndKey struct {
	Hello  ServerHelloMessage
	Key    ServerKeyExchangeMsg
	HasKey bool
}

// CertificateMessage simply exporting the internal certificateMsg
type CertificateMessage struct {
	Raw          []byte
	Certificates [][]byte
}

//GetCertificates returns the list of certificates in a TLS certificate message
func (cert CertificateMessage) GetCertificates() (certs []*x509.Certificate, e error) {

	for _, c := range cert.Certificates {
		cc, err := x509.ParseCertificate(c)
		if err != nil {
			return certs, err
		}
		certs = append(certs, cc)
	}
	return

}

// ScanResult is the scan result of a server TLS settings
type ScanResult struct {
	Server                                 string
	Port                                   string
	SupportedProtocols                     []uint16
	HasCipherPreferenceOrderByProtocol     map[uint16]bool
	CipherPreferenceOrderByProtocol        map[uint16][]uint16
	OcspStaplingByProtocol                 map[uint16]bool
	SelectedCipherByProtocol               map[uint16]uint16
	ALPNByProtocol                         map[uint16]string
	SecureRenegotiationSupportedByProtocol map[uint16]bool
	CipherSuiteByProtocol                  map[uint16][]uint16
	ServerHelloMessageByProtocolByCipher   map[uint16]map[uint16]ServerHelloMessage
	CertificatesPerProtocol                map[uint16]CertificateMessage
	KeyExchangeByProtocolByCipher          map[uint16]map[uint16]ServerKeyExchangeMsg
	IsSTARTLS                              bool
	IsSSH                                  bool
	SupportsTLSFallbackSCSV                bool
}

//UnmarsharlScanResult builds ScanResults from bytes
func UnmarsharlScanResult(data []byte) ([]ScanResult, error) {

	sr := []ScanResult{}
	gob.Register(sr)
	buf := bytes.NewBuffer(data)
	err := gob.NewDecoder(buf).Decode(&sr)
	if err != nil {
		return sr, err
	}
	return sr, nil
}

//HumanScanResult is a Stringified version of ScanResult
type HumanScanResult struct {
	Server                                 string
	HostName                               string
	Port                                   string
	SupportsTLS                            bool
	SupportedProtocols                     []string
	HasCipherPreferenceOrderByProtocol     map[string]bool
	CipherPreferenceOrderByProtocol        map[string][]string
	OcspStaplingByProtocol                 map[string]bool
	SelectedCipherByProtocol               map[string]string
	ALPNByProtocol                         map[string]string
	SecureRenegotiationSupportedByProtocol map[string]bool
	CipherSuiteByProtocol                  map[string][]string
	// ServerHelloMessageByProtocolByCipher   map[string]map[string]ServerHelloMessage
	// CertificatesPerProtocol                map[string]CertificateMessage
	// KeyExchangeByProtocolByCipher          map[string]map[string]ServerKeyExchangeMsg
	IsSTARTLS               bool
	IsSSH                   bool
	SupportsTLSFallbackSCSV bool
	Score                   SecurityScore
}

func getCurve(protocol, cipher uint16, scan ScanResult) string {
	curveID := ""
	if c, ok := scan.KeyExchangeByProtocolByCipher[protocol]; ok {
		if ex, ok := c[cipher]; ok {
			key := ex.Key
			if len(key) > 4 && key[0] == 3 {
				//named curve
				cid := uint16(key[1])<<8 | uint16(key[2])
				curveID = fmt.Sprintf(" (Named Curve: %s)", NamedCurves[cid])
			}
		}
	}
	return fmt.Sprintf("%s (0x%x) %s", CipherSuiteMap[cipher], cipher, curveID)
}

//ToStringStruct returns a string-decoded form of ScanResult
func (s ScanResult) ToStringStruct() (out HumanScanResult) {
	out.Server = s.Server
	ip, err := net.LookupAddr(s.Server)
	if err == nil {
		out.HostName = strings.Join(ip, ", ")
	}
	out.Port = s.Port
	out.SupportsTLS = s.SupportsTLS()
	for _, p := range s.SupportedProtocols {
		out.SupportedProtocols = append(out.SupportedProtocols, TLSVersionMap[p])
	}
	out.HasCipherPreferenceOrderByProtocol = make(map[string]bool)
	for p := range s.HasCipherPreferenceOrderByProtocol {
		out.HasCipherPreferenceOrderByProtocol[TLSVersionMap[p]] = s.HasCipherPreferenceOrderByProtocol[p]
	}
	out.CipherPreferenceOrderByProtocol = make(map[string][]string)
	for k, v := range s.CipherPreferenceOrderByProtocol {
		ciphers := []string{}
		if s.HasCipherPreferenceOrderByProtocol[k] {
			for _, c := range v {
				ciphers = append(ciphers, getCurve(k, c, s))
			}
		}
		out.CipherPreferenceOrderByProtocol[TLSVersionMap[k]] = ciphers
	}
	out.OcspStaplingByProtocol = make(map[string]bool)
	for k, v := range s.OcspStaplingByProtocol {
		out.OcspStaplingByProtocol[TLSVersionMap[k]] = v
	}

	out.SelectedCipherByProtocol = make(map[string]string)
	for k, v := range s.SelectedCipherByProtocol {
		out.SelectedCipherByProtocol[TLSVersionMap[k]] = getCurve(k, v, s)
	}

	out.ALPNByProtocol = make(map[string]string)
	for k, v := range s.ALPNByProtocol {
		out.ALPNByProtocol[TLSVersionMap[k]] = v
	}

	out.SecureRenegotiationSupportedByProtocol = make(map[string]bool)
	for k, v := range s.SecureRenegotiationSupportedByProtocol {
		out.SecureRenegotiationSupportedByProtocol[TLSVersionMap[k]] = v
	}

	out.CipherSuiteByProtocol = make(map[string][]string)
	for k, v := range s.CipherSuiteByProtocol {
		ciphers := []string{}
		for _, c := range v {
			ciphers = append(ciphers, getCurve(k, c, s))
		}
		out.CipherSuiteByProtocol[TLSVersionMap[k]] = ciphers
	}

	out.IsSTARTLS = s.IsSTARTLS
	out.IsSSH = s.IsSSH
	out.SupportsTLSFallbackSCSV = s.SupportsTLSFallbackSCSV
	out.Score = s.CalculateScore()
	return
}

//ToJSON returns a JSON-formatted string representation of the ScanResult
func (s ScanResult) ToJSON() (js string) {
	return
}

// SupportsTLS determines whether the port on the specified server supports TLS at all
func (s ScanResult) SupportsTLS() bool {
	if len(s.SupportedProtocols) == 0 {
		return false
	}
	return true
}

//ToString generates a string output
func (s ScanResult) ToString(config ScanConfig) (result string) {
	hn, err := net.LookupAddr(s.Server)
	hostname := s.Server
	if err == nil {
		hostname = strings.Join(hn, ",")
	}
	result += fmt.Sprintf("%s (%s)\n\tPort: %s\n", s.Server, hostname, s.Port)
	if len(s.SupportedProtocols) == 0 {
		result += "\tNo supported SSL/TLS protocol found\n"
	} else {
		sortedSupportedProtocols := s.SupportedProtocols
		sort.Slice(sortedSupportedProtocols, func(i, j int) bool { return sortedSupportedProtocols[i] > sortedSupportedProtocols[j] })
		for _, tls := range sortedSupportedProtocols {
			startTLS := ""
			if s.IsSTARTLS {
				startTLS = " (STARTTLS)"
			}
			result += fmt.Sprintf("\t%s%s:\n", TLSVersionMap[tls], startTLS)
			result += fmt.Sprintf("\t\tSupports secure renegotiation: %t\n", s.SecureRenegotiationSupportedByProtocol[tls])
			result += fmt.Sprintf("\t\tApplication Layer Protocol Negotiation: %s\n", s.ALPNByProtocol[tls])
			if !config.ProtocolsOnly {

				result += fmt.Sprintf("\t\tHas a cipher preference order: %t\n", s.HasCipherPreferenceOrderByProtocol[tls])
				result += fmt.Sprintf("\t\tSelected cipher when all client ciphers (in numerical order) are presented: %s\n", CipherSuiteMap[s.SelectedCipherByProtocol[tls]])
				if s.HasCipherPreferenceOrderByProtocol[tls] {
					result += "\t\tSupported Ciphersuites (in order of preference):\n"
					for _, cipher := range s.CipherPreferenceOrderByProtocol[tls] {
						result += fmt.Sprintf("\t\t\t%s - %s\n", getCurve(tls, cipher, s), scoreCipher(cipher, tls, s))
					}
				} else {
					result += "\n\t\tSupported Ciphersuites (server has no order preference):\n"
					for _, cipher := range s.CipherSuiteByProtocol[tls] {
						result += fmt.Sprintf("\t\t\t%s - %s\n", getCurve(tls, cipher, s), scoreCipher(cipher, tls, s))
					}
				}
			}
			if certM, ok := s.CertificatesPerProtocol[tls]; !config.HideCerts && ok {
				certs, err := certM.GetCertificates()
				if err == nil && len(certs) > 0 {
					result += "\tCertificate Information:\n"
					cert := certs[0]
					result += "\t\tSubject: " + cert.Subject.String() + "\n\t\tSubject Serial Number: " + cert.Subject.SerialNumber + "\n"
					result += "\t\tSubject Common names: " + cert.Subject.CommonName + "\n"
					result += "\t\tAlternative names: " + strings.Join(cert.DNSNames, ", ") + "\n"
					result += fmt.Sprintf("\t\tSerial Number: %x\n", cert.SerialNumber)
					result += "\t\tValid from: " + cert.NotBefore.String() + "\n"
					result += "\t\tValid until: " + cert.NotAfter.String() + "\n"
					result += "\t\tIssuer: " + cert.Issuer.String() + "\n"
					result += "\t\tSignature algorithm: " + cert.SignatureAlgorithm.String() + "\n"
					sigLen := len(cert.Signature) - 1
					result += fmt.Sprintf("\t\tSignature: %x...%x\n", cert.Signature[:8], cert.Signature[sigLen-8:sigLen])
					if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
						result += fmt.Sprintf("\t\tKey: %d bits (e %d)\n", key.N.BitLen(), key.E)
					}
					result += fmt.Sprintf("\t\tSupports OCSP stapling: %t\n", s.OcspStaplingByProtocol[tls])
					result += fmt.Sprintf("\t\tChain length: %d\n", len(certs))
					if len(certs) > 1 {
						for i := 0; i < len(certs); i++ {
							c := certs[i]
							result += fmt.Sprintf("\t\t\tChain %d (CA: %t): %s. (Expires: %s)\n", len(certs)-i-1, c.IsCA, c.Subject.String(), c.NotAfter.String())
						}
					}
				}
			}
		}
	}
	score := s.CalculateScore()
	result += fmt.Sprintf("\nOverall Grade for %s (%s) on Port %s: %s\n", s.Server, hostname, s.Port, score.Grade)
	result += fmt.Sprintf("Protocol score: %d, Cipher key exchange score: %d, Cipher encryption score: %d\n", score.ProtocolScore, score.KeyExchangeScore, score.CipherEncryptionScore)

	return
}

func (s ScanResult) String() string {
	return s.ToString(ScanConfig{})
}

//CalculateScore computes an SSLLab-esque score for the scan
// https://github.com/ssllabs/research/wiki/SS
// https://community.qualys.com/docs/DOC-6321-ssl-labs-grading-2018
//SecurityScoreL-Server-Rating-Guide contains the overall grading of a TLS/SSL port
func (s *ScanResult) CalculateScore() (result SecurityScore) {
	max := uint16(0)
	min := uint16(1000)
	for _, p := range s.SupportedProtocols {
		if p > max {
			max = p
		}
		if p < min {
			min = p
		}
	}

	highProtocol := scoreProtocol(max)
	lowProtocol := scoreProtocol(min)

	result.ProtocolScore = (highProtocol + lowProtocol) / 2

	if s.SupportsTLS() {

		cipherKeyExchangeScore := 1000
		cipherStrengthMinScore := 1000
		cipherStrengthMaxScore := 0
		for _, p := range s.SupportedProtocols {
			c := s.SelectedCipherByProtocol[p]
			selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
			if s.HasCipherPreferenceOrderByProtocol[p] {
				for _, c := range s.CipherPreferenceOrderByProtocol[p] {
					selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
				}
			} else {
				for _, c := range s.CipherSuiteByProtocol[p] {
					selectMinimalKeyExchangeScore(c, p, &cipherKeyExchangeScore, &cipherStrengthMinScore, &cipherStrengthMaxScore, *s)
				}
			}
		}

		result.KeyExchangeScore = cipherKeyExchangeScore

		result.CipherEncryptionScore = (cipherStrengthMaxScore + cipherStrengthMinScore) / 2

		result.Grade = toTLSGrade((30*result.ProtocolScore + 30*result.KeyExchangeScore + 40*result.CipherEncryptionScore) / 100)
		result.adjustScore(*s)
	} else {
		//No TLS
		result.Grade = toTLSGrade(-1)
	}
	return
}

func scoreProtocol(protocol uint16) (score int) {
	switch protocol {
	case VersionSSL20:
		score = 0
	case tls.VersionSSL30:
		score = 80
	case tls.VersionTLS10:
		score = 90
	case tls.VersionTLS11:
		score = 95
	case tls.VersionTLS12:
		score = 100
	case VersionTLS13:
		score = 100
	}
	return
}

//SecurityScore contains the overall grading of a TLS/SSL port
func (score *SecurityScore) adjustScore(scan ScanResult) {

	if !supportsTLS12(scan) {
		cap(score, "C", "TLS v1.2 not suported")
	}

	if !supportsPFS(scan) {
		cap(score, "B", "Forward Secrecy not suported")
	}

	if !supportsAEAD(scan) {
		cap(score, "B", "Authenticated Encryption (AEAD) not suported")
	}

	adjustUsingCertificateSecurity(score, scan)

	if scan.SupportsTLSFallbackSCSV && score.Grade == "A" {
		score.Grade = "A+"
	}

}

func adjustUsingCertificateSecurity(score *SecurityScore, scan ScanResult) {
	for _, c := range scan.CertificatesPerProtocol {
		certs, err := c.GetCertificates()
		if err != nil {
			cap(score, "T", "Error in obtaining certificates. Untrusted")
			return
		}
		for _, cert := range certs {
			publicKey := cert.PublicKey
			switch cert.SignatureAlgorithm {
			case signatureRSA:
				if pk, ok := publicKey.(*rsa.PublicKey); ok {
					bitlength := pk.N.BitLen()
					switch {
					case bitlength >= 1024 && bitlength < 2048:
						cap(score, "B", fmt.Sprintf("Public key length is %d (< 2048)", bitlength))
					case bitlength < 1024:
						cap(score, "F", fmt.Sprintf("Public key length is %d (< 1024)", bitlength))
					}
				} else {
					cap(score, "T", fmt.Sprintf("Got malformed public key format"))
				}
			case signatureECDSA:
				if pk, ok := publicKey.(*ecdsa.PublicKey); ok {
					bitlength := pk.Y.BitLen()
					switch {
					case bitlength >= 1024 && bitlength < 2048:
						cap(score, "B", fmt.Sprintf("Public key length is %d (< 2048)", bitlength))
					case bitlength < 1024:
						cap(score, "F", fmt.Sprintf("Public key length is %d (< 1024)", bitlength))
					}
				} else {
					cap(score, "T", fmt.Sprintf("Got malformed public key format"))
				}
			case signatureDSA:
				if pk, ok := publicKey.(*dsa.PublicKey); ok {
					bitlength := pk.Y.BitLen()
					switch {
					case bitlength >= 1024 && bitlength < 2048:
						cap(score, "B", fmt.Sprintf("Public key length is %d (< 2048)", bitlength))
					case bitlength < 1024:
						cap(score, "F", fmt.Sprintf("Public key length is %d (< 1024)", bitlength))
					}
				} else {
					cap(score, "T", fmt.Sprintf("Got malformed public key format"))
				}
			case signatureAnonymous:
				cap(score, "T", "Using anonymous signature algorithm")
			}

			sigAlgo := cert.SignatureAlgorithm.String()
			switch {
			case strings.Contains(sigAlgo, "MD"): //cap MD2 and MD5 signatures to F
				cap(score, "T", fmt.Sprintf("Insecure/Untrusted %s signature algorithm", sigAlgo))
			case strings.Contains(sigAlgo, "SHA1") || strings.Contains(sigAlgo, "SHA-1"):
				cap(score, "T", fmt.Sprintf("Insecure/Untrusted %s signature algorithm", sigAlgo))
			}
		}
	}
}

//SecurityScore contains the overall grading of a TLS/SSL port
func cap(score *SecurityScore, grade, reason string) {
	score.Warnings = append(score.Warnings, fmt.Sprintf("%s: capped to %s", reason, grade))
	if grade > score.Grade {
		score.Grade = grade
	}
}

func supportsTLS12(scan ScanResult) (yes bool) {
	for _, p := range scan.SupportedProtocols {
		if p == tls.VersionTLS12 {
			yes = true
			break
		}
	}
	return
}

//check Forward Secrecy support
func supportsPFS(scan ScanResult) bool {
	pfs := true

	for _, p := range scan.SupportedProtocols {
		cipher := scan.SelectedCipherByProtocol[p]
		cc, _ := GetCipherConfig(CipherSuiteMap[cipher])
		if !strings.Contains(cc.KeyExchange, "DHE") {
			pfs = false
			break
		}
		if !pfs {
			break
		}
	}
	return pfs
}

//check for Authenticate Encryption with Associated Data (AEAD) support
func supportsAEAD(scan ScanResult) bool {
	aead := false
	aeadProtocols := []uint16{tls.VersionTLS12}
	for _, aeP := range aeadProtocols {
		for _, p := range scan.SupportedProtocols {
			if p == aeP {
				var ciphers []uint16
				if scan.HasCipherPreferenceOrderByProtocol[p] {
					ciphers = scan.CipherPreferenceOrderByProtocol[p]
				} else {
					ciphers = scan.CipherSuiteByProtocol[p]
				}
				for _, c := range ciphers {
					cc, _ := GetCipherConfig(CipherSuiteMap[c])
					if strings.Contains(cc.Encryption, "GCM") || strings.Contains(cc.Encryption, "POLY1305") || strings.Contains(cc.Encryption, "CCM") {
						aead = true
						break
					}
				}
				if aead {
					break
				}
			}
		}
	}
	return aead
}

func toTLSGrade(score int) (grade string) {
	switch {
	case score >= 80:
		grade = "A"
	case score >= 65:
		grade = "B"
	case score >= 50:
		grade = "C"
	case score >= 35:
		grade = "D"
	case score >= 20:
		grade = "E"
	case score < 0:
		grade = "U" // for untrusted, possibly plaintext connection
	default:
		grade = "F"
	}
	return
}

func mapKeyExchangeKeylengthToScore(kl int) (score int) {
	switch {
	case kl >= 4096:
		score = 100
	case kl >= 2048:
		score = 90
	case kl >= 1024:
		score = 80
	case kl >= 512:
		score = 40
	case kl > 0:
		score = 20
	default:
		score = 0
	}
	return
}

func mapEncKeyLengthToScore(kl int) (score int) {
	switch {
	case kl >= 256:
		score = 100
	case kl >= 128:
		score = 80
	case kl > 0:
		score = 20
	default:
		score = 0
	}
	return
}

func selectMinimalKeyExchangeScore(cipher, protocol uint16, keyExchangeScore, cipherStrengthMinScore, cipherStrengthMaxScore *int, scan ScanResult) {
	if c, ok := CipherSuiteMap[cipher]; ok {
		if cc, err := GetCipherConfig(c); err == nil {
			kl := cc.GetKeyExchangeKeyLength(cipher, protocol, scan)
			if score := mapKeyExchangeKeylengthToScore(kl); score < *keyExchangeScore {
				*keyExchangeScore = score
			}
			ks := cc.GetEncryptionKeyLength()
			score := mapEncKeyLengthToScore(ks)
			if *cipherStrengthMinScore > score {
				*cipherStrengthMinScore = score
			}

			if *cipherStrengthMaxScore < score {
				*cipherStrengthMaxScore = score
			}
		}
	}
}

func scoreCipher(cipher, protocol uint16, scan ScanResult) (score string) {
	if cc, err := GetCipherConfig(CipherSuiteMap[cipher]); err == nil {
		s := (40*mapEncKeyLengthToScore(cc.GetEncryptionKeyLength()) + 30*scoreProtocol(protocol) +
			30*mapKeyExchangeKeylengthToScore(cc.GetKeyExchangeKeyLength(cipher, protocol, scan))) / 100
		return toTLSGrade(s)
	}
	return
}
