// smtpconn.go handles communication with remote SMTP servers

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message"
)

type SMTPConnection struct {
	smtpUrl string
	user    string
	pass    string
	cli     *smtp.Client
}

func NewSMTPConnection(smtpUrl, user, password string) *SMTPConnection {
	return &SMTPConnection{smtpUrl, user, password, nil}
}

func (c *SMTPConnection) Close() error {
	return c.cli.Close()
}

//
// Open the connection to the SMTP server and authenticate
// Returns nil on success
//
func (c *SMTPConnection) Connect() error {
	// Get ourselves a connection, this part is a bit messy
	u, err := url.Parse(c.smtpUrl)
	if err != nil {
		return err
	}

	port := 587
	startTls := true

	if u.Scheme == "smtp" {
		// SMTP Submission port, opportunistic TLS
		port = 587
		startTls = true
	} else if u.Scheme == "smtps" {
		// Implicit TLS
		port = 465
		startTls = false
	}

	// User specified port overrides it (e.g. allows port 25 selection if necessary)
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return err
		}
	}

	addr := fmt.Sprintf("%v:%v", u.Hostname(), port)
	var conn net.Conn
	tlsConfig := &tls.Config{ServerName: u.Hostname()}
	if startTls {
		// Open a plain TCP socket, we'll do TLS later
		conn, err = net.Dial("tcp", addr)
	} else {
		// Open a TLS socket
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	}
	if err != nil {
		return err
	}

	ownHost, err := os.Hostname()
	if err != nil {
		return err
	}
	// Open a new SMTP client
	c.cli, err = smtp.NewClient(conn, ownHost)
	if err != nil {
		return err
	}

	// Begin opportunistic TLS if we need to
	if startTls {
		err = c.cli.StartTLS(tlsConfig)
		if err != nil {
			return err
		}
	}

	// Finally, check the authentication
	authSupported, params := c.cli.Extension("AUTH")
	if !authSupported {
		return errors.New("authentication not supported by this server")
	}

	var auth smtp.Auth
	if strings.Contains(params, "CRAM-MD5") {
		auth = smtp.CRAMMD5Auth(c.user, c.pass)
	} else if strings.Contains(params, "PLAIN") {
		auth = smtp.PlainAuth("", c.user, c.pass, ownHost)
	} else {
		return fmt.Errorf("unexpected authentication params %v", params)
	}
	return c.cli.Auth(auth)
}

func (c *SMTPConnection) Send(from, to, subject, msg string) error {
	if c.cli == nil {
		err := c.Connect()
		if err != nil {
			return err
		}
	}
	c.cli.Mail(from)
	c.cli.Rcpt(to)
	wr, err := c.cli.Data()
	defer wr.Close()

	h := message.Header{}
	h.SetContentType("text/plain", nil)
	h.Set("From", from)
	h.Set("To", to)
	h.Set("Subject", subject)
	h.Set("Date", time.Now().Format(time.RFC1123)) // Not sure this is the right one, should check
	w, err := message.CreateWriter(wr, h)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, msg)
	if err != nil {
		return err
	}
	return nil
}
