package tlsaudit

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	portscan "github.com/adedayo/tcpscan"
	gotls "github.com/adedayo/tlsaudit/pkg/golang"
	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

var (
	//timeout for network read deadlines
	patientTimeout = 10 * time.Second
	defaultTimeout = 5 * time.Second
)

type orderedCipherStruct struct {
	Protocol   uint16
	Preference bool
	Ciphers    []uint16
}

//ScanCIDRTLS combines a port scan with TLS scan for a CIDR range to return the open ports, and the TLS setting for each port over the result channel
func ScanCIDRTLS(cidr string, config tlsmodel.ScanConfig) <-chan tlsmodel.ScanResult {
	scanResults := make(chan tlsmodel.ScanResult)
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Error: %+v\n", r)
			os.Exit(1)
		}
	}()
	go func() {
		defer close(scanResults)
		fmt.Printf("Scanning TLS for host %s using IP addresses\n", cidr)
		scan := make(map[string]portscan.PortACK)
		ackChannels := []<-chan portscan.PortACK{}
		resultChannels := []<-chan tlsmodel.ScanResult{}
		result := portscan.ScanCIDR(portscan.ScanConfig{
			Timeout:          config.Timeout,
			PacketsPerSecond: config.PacketsPerSecond,
			Quiet:            true,
		}, cidr)
		ackChannels = append(ackChannels, result)
		hostnames := make(map[string]string)
		for ack := range mergeACKChannels(ackChannels...) {
			if ack.IsOpen() {
				fmt.Printf("Got Open ACK: %#v\n", ack)
				port := strings.Split(ack.Port, "(")[0]
				key := ack.Host + ack.Port
				domain := ""
				if _, present := hostnames[ack.Host]; !present {
					println("Looking up ", ack.Host)
					cname, err := net.LookupCNAME(ack.Host)
					if err == nil {
						domain = cname
					}
					hostnames[ack.Host] = domain
					println("Finished Looking up", ack.Host, " Got :", cname)
				} else {
					domain = hostnames[ack.Host]
				}
				if _, present := scan[key]; !present {
					scan[key] = ack
					println("TLS Scanning ", ack.Host)
					channel := scanHost(tlsmodel.HostAndPort{
						Hostname: ack.Host,
						Port:     port,
					}, config, domain)
					resultChannels = append(resultChannels, channel)
				}
			}
		}
		for res := range MergeResultChannels(resultChannels...) {
			fmt.Printf("Got Merged Scan result of Server %s:%s\n", res.Server, res.Port)
			scanResults <- res
		}
	}()
	return scanResults
}

func mergeACKChannels(ackChannels ...<-chan portscan.PortACK) <-chan portscan.PortACK {
	var wg sync.WaitGroup
	out := make(chan portscan.PortACK)
	output := func(c <-chan portscan.PortACK) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(ackChannels))
	for _, c := range ackChannels {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

//MergeResultChannels as suggested
func MergeResultChannels(channels ...<-chan tlsmodel.ScanResult) <-chan tlsmodel.ScanResult {
	var wg sync.WaitGroup
	out := make(chan tlsmodel.ScanResult)
	output := func(c <-chan tlsmodel.ScanResult) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(channels))
	for _, c := range channels {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

//ServerHelloAndCert struct holds server hello message and certificate (indicating whether it was STARTTLS), otherwise the error
type ServerHelloAndCert struct {
	ServerHello tlsmodel.ServerHelloMessage
	Cert        tlsmodel.CertificateMessage
	StartTLS    bool
	Err         error
}

func mergeHandShakeChannels(channels ...<-chan ServerHelloAndCert) <-chan ServerHelloAndCert {
	var wg sync.WaitGroup
	out := make(chan ServerHelloAndCert)
	output := func(c <-chan ServerHelloAndCert) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(channels))
	for _, c := range channels {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func mergeHelloKeyChannels(channels ...<-chan tlsmodel.HelloAndKey) <-chan tlsmodel.HelloAndKey {
	var wg sync.WaitGroup
	out := make(chan tlsmodel.HelloAndKey)
	output := func(c <-chan tlsmodel.HelloAndKey) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(channels))
	for _, c := range channels {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

//scanHost finds whether a port on a host supports TLS and if so what protocols and ciphers are supported
func scanHost(hostPort tlsmodel.HostAndPort, config tlsmodel.ScanConfig, serverName string) chan tlsmodel.ScanResult {
	resultChannel := make(chan tlsmodel.ScanResult)
	patientTimeout = time.Duration(config.Timeout) * time.Second
	go func() {
		defer close(resultChannel)
		host := hostPort.Hostname
		port := hostPort.Port
		hostnameWithPort := fmt.Sprintf("%s:%s", host, port)
		result := tlsmodel.ScanResult{}
		result.Server = host
		result.Port = port
		result.CipherSuiteByProtocol = make(map[uint16][]uint16)
		result.OcspStaplingByProtocol = make(map[uint16]bool)
		result.SelectedCipherByProtocol = make(map[uint16]uint16)
		result.ALPNByProtocol = make(map[uint16]string)
		result.SecureRenegotiationSupportedByProtocol = make(map[uint16]bool)
		result.HasCipherPreferenceOrderByProtocol = make(map[uint16]bool)
		result.CipherPreferenceOrderByProtocol = make(map[uint16][]uint16)
		result.ServerHelloMessageByProtocolByCipher = make(map[uint16]map[uint16]tlsmodel.ServerHelloMessage)
		result.CertificatesPerProtocol = make(map[uint16]tlsmodel.CertificateMessage)
		result.KeyExchangeByProtocolByCipher = make(map[uint16]map[uint16]tlsmodel.ServerKeyExchangeMsg)

		handshakeChannels := []<-chan ServerHelloAndCert{}
		//check for protocol support with all ciphersuites present
		for _, tlsVersion := range tlsmodel.TLSVersions {
			hsc := func(versionOfTLS uint16) <-chan ServerHelloAndCert {
				config := &gotls.Config{
					InsecureSkipVerify: true,
					MinVersion:         versionOfTLS,
					MaxVersion:         versionOfTLS,
					CipherSuites:       tlsmodel.AllCipherSuites,
					NextProtos:         tlsmodel.AllALPNProtos,
				}
				if serverName != "" {
					config.ServerName = serverName
				}
				handshakeChan := HandShakeClientHelloGetServerCert(hostnameWithPort, config, patientTimeout)
				return handshakeChan
			}(tlsVersion)
			handshakeChannels = append(handshakeChannels, hsc)
		}

		for res := range mergeHandShakeChannels(handshakeChannels...) {
			process(res, &result)
		}
		sort.Sort(uint16Sorter(result.SupportedProtocols))

		//chech support for TLS_FALLBACK_SCSV
		checkFallbackSCSVSupport(&result, hostnameWithPort, serverName, patientTimeout)

		// fmt.Printf("Got result %s, %s, %#v \n", result.Server, result.Port, result.SupportedProtocols)
		if !config.ProtocolsOnly {
			//now test each cipher for only the supported protocols
			outChannels := []<-chan tlsmodel.HelloAndKey{}
			for _, tlsVersion := range result.SupportedProtocols {
				for _, cipher := range tlsmodel.AllCipherSuites {
					out := testConnection(hostnameWithPort, tlsVersion, cipher, result.IsSTARTLS, serverName)
					outChannels = append(outChannels, out)
				}
			}
			processConnectionTest(outChannels, &result)

			//check cipher ordering per protocol
			orderedCipherChannels := make([]<-chan orderedCipherStruct, len(result.SupportedProtocols))
			for ind, tlsVersion := range result.SupportedProtocols {
				result.CipherSuiteByProtocol[tlsVersion] = makeUnique(result.CipherSuiteByProtocol[tlsVersion])
				oChan := func() chan orderedCipherStruct {
					outOrdered := make(chan orderedCipherStruct)
					go func(tlsVer uint16) {
						defer close(outOrdered)
						sort.Sort(uint16Sorter(result.CipherSuiteByProtocol[tlsVer]))
						ciphers := result.CipherSuiteByProtocol[tlsVer]
						preference := false
						cipherCount := len(ciphers)
						nextCipher := 0
						orderedCiphers := make([]uint16, cipherCount)

					CheckPoint:
						cipherCount = len(ciphers)
						if cipherCount == 1 {
							//single cipher is assumed to support ordering ;-)
							preference = true
						} else {
							config := &gotls.Config{
								InsecureSkipVerify: true,
								MinVersion:         tlsVer,
								MaxVersion:         tlsVer,
								CipherSuites:       ciphers,
							}
							if serverName != "" {
								config.ServerName = serverName
							}
							msg, err := HandShakeClientHello(hostnameWithPort, config, result.IsSTARTLS, defaultTimeout)
							if err == nil {
								//reverse the ciphers
								reverseCiphers := make([]uint16, cipherCount)
								for i := cipherCount - 1; i >= 0; i-- {
									reverseCiphers[cipherCount-i-1] = ciphers[i]
								}
								config.CipherSuites = reverseCiphers
								msg2, err := HandShakeClientHello(hostnameWithPort, config, result.IsSTARTLS, defaultTimeout)
								if err == nil && msg.CipherSuite == msg2.CipherSuite {
									//if on reverse we get the same cipher, then there is a server preference
									preference = true
									orderedCiphers[nextCipher] = msg.CipherSuite
									nextCipher++
									cipherCount = len(reverseCiphers) - 1
									retryCount := 0
									maxRetries := 2 * cipherCount
									for cipherCount >= 2 {
										ciphers = make([]uint16, cipherCount)
										next := 0
										for _, c := range reverseCiphers {
											if c != msg.CipherSuite && len(ciphers) > next {
												ciphers[next] = c
												next++
											}
										}
										config.CipherSuites = ciphers
										reverseCiphers = ciphers
										cipherCount = len(reverseCiphers) - 1
										msg2, err = HandShakeClientHello(hostnameWithPort, config, result.IsSTARTLS, defaultTimeout)
										if err == nil {
											msg = msg2
											orderedCiphers[nextCipher] = msg.CipherSuite
											nextCipher++
										} else {
											retryCount++
											if retryCount > maxRetries {
												//assume server does not support order
												preference = false
												break //stop trying
											}
										}
									}
									//Last two ciphers - add the cipher that was not preferred
									if preference {
										for _, c := range reverseCiphers {
											if c != msg.CipherSuite {
												orderedCiphers[nextCipher] = c
												nextCipher++
											}
										}
									}
								} else {
									//0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" causes problems for the cipher ordering check. Exclude and redo if present
									if msg.CipherSuite == 0xcca8 || msg2.CipherSuite == 0xcca8 {
										ciphers2 := []uint16{}
										for _, c := range ciphers {
											if c != 0xcca8 {
												ciphers2 = append(ciphers2, c)
											}
										}
										ciphers = ciphers2
										orderedCiphers[nextCipher] = 0xcca8
										nextCipher++
										goto CheckPoint
									}
								}
							}
						}

						outOrdered <- orderedCipherStruct{
							Protocol:   tlsVer,
							Preference: preference,
							Ciphers:    orderedCiphers,
						}
					}(tlsVersion)
					return outOrdered
				}()
				orderedCipherChannels[ind] = oChan
			}

			for out := range mergeOrderedCiperChannnels(orderedCipherChannels...) {
				vers := out.Protocol
				result.HasCipherPreferenceOrderByProtocol[vers] = out.Preference
				if out.Preference {
					result.CipherPreferenceOrderByProtocol[vers] = out.Ciphers
				}

			}
		}
		resultChannel <- result
	}()
	return resultChannel
}

func checkFallbackSCSVSupport(result *tlsmodel.ScanResult, hostnameWithPort, serverName string, patientTimeout time.Duration) {
	maxProtocol := tlsmodel.VersionSSL20
	if len(result.SupportedProtocols) > 0 {
		switch result.SupportedProtocols[0] {
		case tls.VersionTLS12:
			maxProtocol = tls.VersionTLS11
		case tls.VersionTLS11:
			maxProtocol = tls.VersionTLS10
		case tls.VersionTLS10:
			maxProtocol = tls.VersionSSL30
		default:
			maxProtocol = tlsmodel.VersionSSL20
		}

		ciphers := []uint16{}
		for _, p := range result.SupportedProtocols {
			ciphers = append(ciphers, result.SelectedCipherByProtocol[p])
		}
		ciphers = append(ciphers, 0x5600) //add TLS_FALLBACK_SCSV last in line with section 4 of https://datatracker.ietf.org/doc/rfc7507/

		config := &gotls.Config{
			InsecureSkipVerify: true,
			MinVersion:         maxProtocol,
			MaxVersion:         maxProtocol,
			CipherSuites:       ciphers,
			NextProtos:         tlsmodel.AllALPNProtos,
		}
		if serverName != "" {
			config.ServerName = serverName
		}

		rawConn, err := net.DialTimeout("tcp", hostnameWithPort, patientTimeout)
		if err != nil {
			return
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(patientTimeout))
		c := gotls.MakeClientConnection(rawConn, config)
		hello, err := gotls.MakeClientHello(config)
		if err != nil {
			return
		}
		if _, err := c.WriteRecord(gotls.RecordTypeHandshake, hello.Marshal()); err != nil {
			return
		}

		if _, err := c.ReadServerHello(); err != nil {
			if strings.Contains(err.Error(), "inappropriate fallback") {
				result.SupportsTLSFallbackSCSV = true
			}
		}
	}
}

//make sure the slice only contains unique values
func makeUnique(data []uint16) (result []uint16) {
	m := make(map[uint16]bool)
	for _, d := range data {
		m[d] = true
	}
	for d := range m {
		result = append(result, d)
	}
	return
}

type uint16Sorter []uint16

func (k uint16Sorter) Len() int {
	return len(k)
}

func (k uint16Sorter) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}
func (k uint16Sorter) Less(i, j int) bool {
	return k[i] > k[j]
}

func mergeOrderedCiperChannnels(channels ...<-chan orderedCipherStruct) <-chan orderedCipherStruct {
	var wg sync.WaitGroup
	out := make(chan orderedCipherStruct)
	output := func(c <-chan orderedCipherStruct) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(channels))
	for _, c := range channels {
		go output(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func process(res ServerHelloAndCert, result *tlsmodel.ScanResult) {
	if res.Err == nil { //protocol supported
		msg := res.ServerHello
		c := msg.CipherSuite
		result.SupportedProtocols = append(result.SupportedProtocols, msg.Vers)
		result.OcspStaplingByProtocol[msg.Vers] = msg.OcspStapling
		result.SecureRenegotiationSupportedByProtocol[msg.Vers] = msg.SecureRenegotiationSupported
		result.SelectedCipherByProtocol[msg.Vers] = c
		result.IsSTARTLS = res.StartTLS
		result.ALPNByProtocol[msg.Vers] = msg.AlpnProtocol
		result.CertificatesPerProtocol[msg.Vers] = res.Cert
	}
}

func processConnectionTest(outChannels []<-chan tlsmodel.HelloAndKey, scan *tlsmodel.ScanResult) {
	count := 0
	for hk := range mergeHelloKeyChannels(outChannels...) {
		count++
		hello := hk.Hello
		tlsVersion := hello.Vers
		scan.CipherSuiteByProtocol[tlsVersion] = append(scan.CipherSuiteByProtocol[tlsVersion], hello.CipherSuite)
		if val, ok := scan.ServerHelloMessageByProtocolByCipher[tlsVersion]; ok {
			val[hello.CipherSuite] = hello
			scan.ServerHelloMessageByProtocolByCipher[tlsVersion] = val
		} else {
			scan.ServerHelloMessageByProtocolByCipher[tlsVersion] = make(map[uint16]tlsmodel.ServerHelloMessage)
			scan.ServerHelloMessageByProtocolByCipher[tlsVersion][hello.CipherSuite] = hello
		}
		processECDHCipher(hk, scan)
	}
}

func processECDHCipher(hk tlsmodel.HelloAndKey, result *tlsmodel.ScanResult) {
	if hk.HasKey {
		hello := hk.Hello
		tlsVersion := hello.Vers
		serverKey := hk.Key
		if k, ok := result.KeyExchangeByProtocolByCipher[tlsVersion]; ok {
			k[hello.CipherSuite] = serverKey
			result.KeyExchangeByProtocolByCipher[tlsVersion] = k
		} else {
			result.KeyExchangeByProtocolByCipher[tlsVersion] = make(map[uint16]tlsmodel.ServerKeyExchangeMsg)
			result.KeyExchangeByProtocolByCipher[tlsVersion][hello.CipherSuite] = serverKey
		}
	}
}

func fixedLength(data string, length int, delim string) string {
	raws := []string{}
	runes := []rune{}
	for i, r := range []rune(data) {
		runes = append(runes, r)
		if (i+1)%length == 0 {
			raws = append(raws, string(runes))
			runes = []rune{}
		}
	}
	raws = append(raws, string(runes))
	return strings.Join(raws, delim)
}

func testConnection(hostnameWithPort string, tlsVersion, cipher uint16, startTLS bool, serverName string) <-chan tlsmodel.HelloAndKey {
	out := make(chan tlsmodel.HelloAndKey)
	go func() {
		defer close(out)
		config := &gotls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tlsVersion,
			MaxVersion:         tlsVersion,
			CipherSuites:       []uint16{cipher},
		}
		if serverName != "" {
			config.ServerName = serverName
		}

		hk, err := HandShakeUpToKeyExchange(hostnameWithPort, config, startTLS, patientTimeout)

		if err != nil && hk.Hello.Vers != 0 && !hk.HasKey { // the scenario for ciphers that pass server hello stage but don't use key exchange
			out <- hk
		}
		if err == nil || err.Error() == tlsmodel.NkxErrorMessage {
			out <- hk
		}
	}()
	return out
}
