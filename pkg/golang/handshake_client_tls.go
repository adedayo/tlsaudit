// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gotls

import (
	"errors"
	"io"
	"net"
)

//MakeClientConnection returns a TLS connection using the raw connection and the configuration
//--changed by dayo
func MakeClientConnection(rawConn net.Conn, config *Config) *Conn {
	return &Conn{conn: rawConn, config: config, isClient: true}
}

// MakeClientHello returns a Client Hello Message
//--changed by dayo
func MakeClientHello(config *Config) (*clientHelloMsg, ecdheParameters, error) {
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("tls: NextProtos values too large")
	}

	supportedVersions := config.supportedVersions(true)
	if len(supportedVersions) == 0 {
		return nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	clientHelloVersion := supportedVersions[0]
	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if clientHelloVersion > VersionTLS12 {
		clientHelloVersion = VersionTLS12
	}

	// ecdsas := []SignatureScheme{ECDSAWithSHA1, ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512}
	hello := &clientHelloMsg{
		vers:                         clientHelloVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(),
		supportedPoints:              []uint8{pointFormatUncompressed},
		nextProtoNeg:                 len(config.NextProtos) > 0,
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
		// supportedSignatureAlgorithms:     ecdsas,
		// supportedSignatureAlgorithmsCert: ecdsas,
	}
	possibleCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

	// NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		// for _, suite := range cipherSuites {
		//--changed by dayo: remove this safety net, we don't need this behaviour
		// if suite.id != suiteId {
		// 	continue
		// }
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		//--changed by dayo: we don't need this behaviour
		// if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
		// 	continue
		// }
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
		// continue NextCipherSuite
		// }
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
		return nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}
	var params ecdheParameters

	if hello.supportedVersions[0] == VersionTLS13 {
		// -- dayo -- we've got all possible ciphers to test against the server, including non-TLS 1.3 ones! Not planning to be well-behaved! :-)
		//hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13()...)
		curveID := config.curvePreferences()[0]
		// -- dayo -- remove this safety check. We are not planning to complete the handshake
		// if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
		// 	return nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		// }
		params, err = generateECDHEParameters(config.rand(), curveID)
		if err != nil {
			return nil, nil, err
		}
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	return hello, params, nil
}
