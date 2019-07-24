package tlsaudit

import (
	"net"
	"net/textproto"
	"strings"
	"time"

	gotls "github.com/adedayo/tlsaudit/pkg/golang"
	tlsmodel "github.com/adedayo/tlsaudit/pkg/model"
)

// HandShakeUpToKeyExchange starts the handshake up till the acquisition of server key exchanges
func HandShakeUpToKeyExchange(hostname string, config *gotls.Config, startTLS bool, timeout time.Duration) (tlsmodel.HelloAndKey, error) {
	hk := tlsmodel.HelloAndKey{}
	serverHello := tlsmodel.ServerHelloMessage{}
	c := &gotls.Conn{}
	if startTLS {
		rawConn2, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return hk, err
		}
		defer rawConn2.Close()
		rawConn2.SetDeadline(time.Now().Add(timeout))
		err = checkAndSetupForStartTLS(rawConn2)
		if err != nil {
			return hk, err
		}
		c = gotls.MakeClientConnection(rawConn2, config)
	} else {
		rawConn, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return hk, err
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(timeout))
		c = gotls.MakeClientConnection(rawConn, config)
	}

	hello, ecdheParameters, err := gotls.MakeClientHello(config)
	if err != nil {
		return hk, err
	}

	// send ClientHello
	if _, err := c.WriteRecord(gotls.RecordTypeHandshake, hello.Marshal()); err != nil {
		return hk, err
	}

	serverHello, rawHello, err := c.ReadServerHello()
	if err != nil {
		return hk, err
	}

	k, err := c.ReadServerKeyExchange(hello, &serverHello, rawHello, ecdheParameters)

	if err != nil {
		return tlsmodel.HelloAndKey{Hello: serverHello, Key: k, HasKey: false}, err
	}

	return tlsmodel.HelloAndKey{Hello: serverHello, Key: k, HasKey: true}, nil
}

// HandShakeClientHello sends client hello and gets Server Hello and Certificates
func HandShakeClientHello(hostname string, config *gotls.Config, startTLS bool, timeout time.Duration) (tlsmodel.ServerHelloMessage, error) {
	serverHello := tlsmodel.ServerHelloMessage{}
	// dialer := new(net.Dialer)
	c := &gotls.Conn{}

	if startTLS {
		// dialer := new(net.Dialer)
		rawConn2, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return serverHello, err
		}
		defer rawConn2.Close()
		rawConn2.SetDeadline(time.Now().Add(timeout))
		err = checkAndSetupForStartTLS(rawConn2)
		if err != nil {
			return serverHello, err
		}
		c = gotls.MakeClientConnection(rawConn2, config)
	} else {
		rawConn, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return serverHello, err
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(timeout))

		c = gotls.MakeClientConnection(rawConn, config)

	}

	hello, _, err := gotls.MakeClientHello(config)
	if err != nil {
		return serverHello, err
	}

	// send ClientHello
	if _, err := c.WriteRecord(gotls.RecordTypeHandshake, hello.Marshal()); err != nil {
		return serverHello, err
	}

	serverHello, _, err = c.ReadServerHello()
	return serverHello, err
}

// HandShakeClientHelloGetServerCert sends client hello and gets Server Hello and Certificates
func HandShakeClientHelloGetServerCert(hostname string, config *gotls.Config, timeout time.Duration) <-chan ServerHelloAndCert {
	hs := make(chan ServerHelloAndCert)
	go func() {
		defer close(hs)
		serverHello := tlsmodel.ServerHelloMessage{}
		certs := tlsmodel.CertificateMessage{}
		rawConn, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
			return
		}
		defer rawConn.Close()
		rawConn.SetDeadline(time.Now().Add(timeout))
		c := gotls.MakeClientConnection(rawConn, config)

		clientHello, ecdheParameters, err := gotls.MakeClientHello(config)
		if err != nil {
			hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
			return
		}

		// send ClientHello
		if _, err := c.WriteRecord(gotls.RecordTypeHandshake, clientHello.Marshal()); err != nil {
			hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
			return
		}
		var rawHello interface{}
		serverHello, rawHello, err = c.ReadServerHello()
		startTLS := false
		if err != nil {
			//If ServerHello fails, check STARTTLS
			rawConn2, err := net.DialTimeout("tcp", hostname, timeout)
			if err != nil {
				hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
				return
			}
			defer rawConn2.Close()
			rawConn2.SetDeadline(time.Now().Add(timeout))
			err = checkAndSetupForStartTLS(rawConn2)
			if err != nil {
				hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
			}
			c = gotls.MakeClientConnection(rawConn2, config)

			clientHello, ecdheParameters, err = gotls.MakeClientHello(config)
			if err != nil {
				hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
				return
			}

			// send ClientHello
			if _, err := c.WriteRecord(gotls.RecordTypeHandshake, clientHello.Marshal()); err != nil {
				hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
				return
			}

			serverHello, rawHello, err = c.ReadServerHello()
			if err != nil {
				hs <- ServerHelloAndCert{ServerHello: serverHello, Cert: certs, Err: err}
				return
			}
			startTLS = true
		}
		certs, err = c.ReadServerCertificate(clientHello, &serverHello, rawHello, ecdheParameters)
		hs <- ServerHelloAndCert{ServerHello: serverHello, StartTLS: startTLS, Cert: certs, Err: err}
		return
	}()
	return hs
}

//Test whether connection is STARTTLS
func checkAndSetupForStartTLS(rawConn net.Conn) error {
	smtp := textproto.NewConn(rawConn)
	_, _, err := smtp.ReadResponse(220)
	if err != nil {
		//Not SMTP
		smtp.Close()
		return err
	}
	id, err := smtp.Cmd("EHLO %s", "localhost")
	if err != nil {
		return err
	}
	smtp.StartResponse(id)

	_, m, err := smtp.ReadResponse(250)
	smtp.EndResponse(id)
	if err != nil {
		return err
	}
	if !strings.Contains(m, "STARTTLS") {
		return err
	}

	id, err = smtp.Cmd("STARTTLS")
	if err != nil {
		return err
	}
	smtp.StartResponse(id)

	_, m, err = smtp.ReadResponse(220)
	smtp.EndResponse(id)

	if err != nil {
		return err
	}
	return nil

}
