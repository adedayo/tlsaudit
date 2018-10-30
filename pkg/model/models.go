package tlsmodel

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
)

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

// KeyExchangeAlgorithm says what it is
type KeyExchangeAlgorithm int

// //See https://www.gnu.org/software/gnutls/reference/gnutls-gnutls.html#gnutls-kx-algorithm-t
// //https://github.com/jatovm/classpath/blob/master/gnu/javax/net/ssl/provider/KeyExchangeAlgorithm.java
// const (
// 	UNKNOWN KeyExchangeAlgorithm = iota
// 	RSA
// 	DHE_DSS
// 	DHE_RSA
// 	ANON_DH
// 	SRP
// 	RSA_EXPORT
// 	SRP_RSA
// 	SRP_DSS
// 	PSK
// 	DHE_PSK
// 	ANON_ECDH
// 	ECDHE_RSA
// 	ECDHE_ECDSA
// 	ECDHE_PSK
// )

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
	IsSTARTLS bool
	IsSSH     bool
}

func addCurve(protocol, cipher uint16, scan ScanResult) string {

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
		for _, c := range v {
			ciphers = append(ciphers, addCurve(k, c, s))
		}
		out.CipherPreferenceOrderByProtocol[TLSVersionMap[k]] = ciphers
	}
	out.OcspStaplingByProtocol = make(map[string]bool)
	for k, v := range s.OcspStaplingByProtocol {
		out.OcspStaplingByProtocol[TLSVersionMap[k]] = v
	}

	out.SelectedCipherByProtocol = make(map[string]string)
	for k, v := range s.SelectedCipherByProtocol {
		out.SelectedCipherByProtocol[TLSVersionMap[k]] = addCurve(k, v, s)
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
			ciphers = append(ciphers, addCurve(k, c, s))
		}
		out.CipherSuiteByProtocol[TLSVersionMap[k]] = ciphers
	}

	out.IsSTARTLS = s.IsSTARTLS
	out.IsSSH = s.IsSSH
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
			result += fmt.Sprintf("\t%s:\n", TLSVersionMap[tls])
			result += fmt.Sprintf("\t\tSupports secure renegotiation: %t\n", s.SecureRenegotiationSupportedByProtocol[tls])
			result += fmt.Sprintf("\t\tApplication Layer Protocol Negotiation: %s\n", s.ALPNByProtocol[tls])
			if !config.ProtocolsOnly {

				result += fmt.Sprintf("\t\tHas a cipher preference order: %t\n", s.HasCipherPreferenceOrderByProtocol[tls])
				result += fmt.Sprintf("\t\tSelected cipher when all client ciphers (in numerical order) are presented: %s\n", CipherSuiteMap[s.SelectedCipherByProtocol[tls]])
				if s.HasCipherPreferenceOrderByProtocol[tls] {
					result += "\t\tSupported Ciphersuites (in order of preference):\n"
					for _, cipher := range s.CipherPreferenceOrderByProtocol[tls] {
						result += fmt.Sprintf("\t\t\t%s\n", addCurve(tls, cipher, s))
					}
				} else {
					result += "\n\t\tSupported Ciphersuites (server has no order preference):\n"
					for _, cipher := range s.CipherSuiteByProtocol[tls] {
						result += fmt.Sprintf("\t\t\t%s\n", addCurve(tls, cipher, s))
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
	return
}

func (s ScanResult) String() string {
	return s.ToString(ScanConfig{})
}
