// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package gotls

import (
	"bytes"
	"errors"
	"fmt"

	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

// WriteRecord writes a TLS record with the given type and payload to the
// connection and updates the record layer state.
// L < c.out.Mutex.
//--changed by dayo (to make it public)
func (c *Conn) WriteRecord(typ recordType, data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writeRecordLocked(typ, data)
}

//ReadServerHello does exactly what it says
//--introduced by dayo
func (c *Conn) ReadServerHello() (tlsmodel.ServerHelloMessage, error) {
	message := tlsmodel.ServerHelloMessage{}
	msg, err := c.readHandshake()
	if err != nil {
		return message, err
	}
	if srvHello, ok := msg.(*serverHelloMsg); ok {
		serverHello := srvHello.Export()
		if err := c.pickTLSVersion(srvHello); err == nil {
			serverHello.Vers = c.vers //need to overwrite as the server hello message version for TLS 1.3 is actually that for TLS 1.2
		}
		return serverHello, nil
	}
	return message, fmt.Errorf("Expecting a server hello message but got %#v", msg)
}

//ReadServerCertificate does exactly what it says
//--introduced by dayo
func (c *Conn) ReadServerCertificate(clientHello *clientHelloMsg, sHello *tlsmodel.ServerHelloMessage, ecdheParams ecdheParameters) (tlsmodel.CertificateMessage, error) {
	certMessage := tlsmodel.CertificateMessage{}

	if c.vers == VersionTLS13 {
		if serverHello, ok := sHello.RawHello.(*serverHelloMsg); ok {
			hs := &clientHandshakeStateTLS13{
				c:           c,
				serverHello: serverHello,
				hello:       clientHello,
				ecdheParams: ecdheParams,
				// session:     session,
				// earlySecret: earlySecret,
				// binderKey:   binderKey,
			}

			// In TLS 1.3, session tickets are delivered after the handshake.
			if err := processTLS13Handshake(hs); err != nil {
				return certMessage, err
			}

			sHello.AlpnProtocol = c.clientProtocol
			sHello.SecureRenegotiationSupported = c.secureRenegotiation
			sHello.CipherSuite = c.cipherSuite
			if c.peerCertificates != nil {
				certMessage.Certs = c.peerCertificates
				return certMessage, nil
			}
		}
	}

	crt, err := c.readHandshake()
	if err != nil {
		return certMessage, err
	}
	cert, ok := crt.(*certificateMsg)
	if !ok {
		return certMessage, errors.New("Not a certificate")

	}
	return cert.Export(), nil
}

func processTLS13Handshake(hs *clientHandshakeStateTLS13) error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.ecdheParams == nil || len(hs.hello.keyShares) != 1 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()
	hs.transcript.Write(hs.hello.marshal())

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	hs.transcript.Write(hs.serverHello.marshal())

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	return nil
}

//ReadServerKeyExchange does exactly what it says - skips certificate/certificate status messages
//--introduced by dayo
func (c *Conn) ReadServerKeyExchange(clientHello *clientHelloMsg, sHello *tlsmodel.ServerHelloMessage, ecdheParams ecdheParameters) (tlsmodel.ServerKeyExchangeMsg, error) {

	keyExchangeMsg := tlsmodel.ServerKeyExchangeMsg{}
	if c.vers == tlsmodel.VersionTLS13 {
		if serverHello, ok := sHello.RawHello.(*serverHelloMsg); ok {
			sharedKey := ecdheParams.SharedKey(serverHello.serverShare.data)
			if sharedKey == nil {
				return keyExchangeMsg, errors.New("tls: invalid TLS v1.3 server key share")
			}
			keyExchangeMsg.Key = sharedKey
			keyExchangeMsg.Group = tlsmodel.CurveID(serverHello.serverShare.group)
			return keyExchangeMsg, nil
		}
		return keyExchangeMsg, errors.New("tls: invalid TLS v1.3 server hello message")
	}
	msg, err := c.readHandshake()
	if err != nil {
		return keyExchangeMsg, err
	}

	_, ok := msg.(*certificateMsg)
	if !ok {
		//if the certificate is optional, test whether we got a key exchange message :-s
		kx, ok := msg.(*serverKeyExchangeMsg)
		if ok {
			return kx.Export(), nil
		}
		return keyExchangeMsg, errors.New("Weird error: neither cert nor key exchange message was sent by server after server hello")
	}

	//we got a cert, try to read server key exchange
	msg, err = c.readHandshake()
	if err != nil {
		return keyExchangeMsg, err
	}

	//we could have gotten a certificate status message at this point for OCSP-stapled certs
	_, ok = msg.(*certificateStatusMsg)
	if !ok {
		//if not a cert status, check we got our key exchange
		kx, ok := msg.(*serverKeyExchangeMsg)
		if ok {
			return kx.Export(), nil
		}
		return keyExchangeMsg, errors.New("Weird error: neither cert/cert status nor key exchange message was sent by server after server hello")
	}
	msg, err = c.readHandshake()
	if err != nil {
		return keyExchangeMsg, err
	}
	keyExchange, ok := msg.(*serverKeyExchangeMsg)
	if !ok {
		return keyExchangeMsg, errors.New(tlsmodel.NkxErrorMessage)
	}
	return keyExchange.Export(), nil
}
