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
	_, port, _ := net.SplitHostPort(hostname)
	c := &gotls.Conn{}
	if startTLS {
		rawConn2, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return hk, err
		}
		defer rawConn2.Close()
		rawConn2.SetDeadline(time.Now().Add(timeout))
		err = checkAndSetupForStartTLS(rawConn2, port)
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
	_, port, _ := net.SplitHostPort(hostname)
	if startTLS {
		// dialer := new(net.Dialer)
		rawConn2, err := net.DialTimeout("tcp", hostname, timeout)
		if err != nil {
			return serverHello, err
		}
		defer rawConn2.Close()
		rawConn2.SetDeadline(time.Now().Add(timeout))
		err = checkAndSetupForStartTLS(rawConn2, port)
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

// handShakeClientHelloGetServerCert sends client hello and gets Server Hello and Certificates
func handShakeClientHelloGetServerCert(hostname string, config *gotls.Config, timeout time.Duration) <-chan ServerHelloAndCert {
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
			_, port, _ := net.SplitHostPort(hostname)
			err = checkAndSetupForStartTLS(rawConn2, port)
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

//Test whether connection is STARTTLS - check POP3/IMAP/SMTP based on common ports
func checkAndSetupForStartTLS(rawConn net.Conn, port string) error {
	switch port {
	case "110", "995": //pop3
		return pop3(rawConn)
	case "25", "587", "2525", "465": //smtp
		return smtp(rawConn)
	case "143", "993": //imap
		return imap(rawConn)
	default:
		return smtp(rawConn)
	}
}

func pop3(rawConn net.Conn) (err error) {
	//https://tools.ietf.org/html/rfc2595#section-4
	pop := textproto.NewConn(rawConn)
	if text, err := pop.ReadLine(); err == nil {
		text = strings.ToUpper(text)
		if strings.Contains(text, "OK") && strings.Contains(text, "POP") {
			if _, err = pop.Cmd("STLS"); err == nil {
				if text, err = pop.ReadLine(); err == nil {
					text = strings.ToUpper(text)
					if strings.Contains(text, "OK") && strings.Contains(text, "TLS") {
						return nil
					}
				}
			}
		}
	}
	return err
}

func imap(rawConn net.Conn) (err error) {
	//https://tools.ietf.org/html/rfc2595#section-3.1
	pop := textproto.NewConn(rawConn)
	text, err := pop.ReadLine()
	if err == nil {
		text = strings.ToUpper(text)
		if strings.Contains(text, "OK") && strings.Contains(text, "STARTTLS") {
			if _, err = pop.Cmd("a1 STARTTLS"); err == nil {
				if text, err = pop.ReadLine(); err == nil {
					text = strings.ToUpper(text)
					if strings.Contains(text, "OK") && strings.Contains(text, "TLS") {
						return nil
					}
				}
			}
		}
	}
	return err
}

func smtp(rawConn net.Conn) error {
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
