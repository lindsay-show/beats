package sip

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/elastic/beats/packetbeat/protos/sip/header"
	"github.com/elastic/beats/packetbeat/protos/sip/parser"
	"io"
	"strings"
)

type Request interface {
	Message

	GetMethod() string
	SetMethod(method string) error
	GetRequestURI() string
	SetRequestURI(uri string) error
}

const (
	ACK       = "ACK"
	BYE       = "BYE"
	CANCEL    = "CANCEL"
	INVITE    = "INVITE"
	OPTIONS   = "OPTIONS"
	REGISTER  = "REGISTER"
	NOTIFY    = "NOTIFY"
	SUBSCRIBE = "SUBSCRIBE"
	MESSAGE   = "MESSAGE"
	REFER     = "REFER"
	INFO      = "INFO"
	PRACK     = "PRACK"
	UPDATE    = "UPDATE"
)

////////////////////////////////////////////////////////////////////////////////
type request struct {
	message

	method     string
	requestURI string
}

func NewRequest(method, requestURI string, body io.Reader) *request {
	this := &request{
		message: message{
			sipVersion: "SIP/2.0",
			header:     make(Header),
			body:       body,
		},
		method:     method,
		requestURI: requestURI,
	}
	this.StartLineWriter = this
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			this.SetContentLength(int64(v.Len()))
		case *bytes.Reader:
			this.SetContentLength(int64(v.Len()))
		case *strings.Reader:
			this.SetContentLength(int64(v.Len()))
		}
	}

	return this
}

func (this *request) GetMethod() string {
	return this.method
}

func (this *request) SetMethod(method string) error {
	this.method = method
	return nil
}

func (this *request) GetRequestURI() string {
	return this.requestURI
}

func (this *request) SetRequestURI(requestURI string) error {
	this.requestURI = requestURI
	return nil
}

//Method RequestURI SIP/2.0
func (this *request) StartLineWrite(w io.Writer) (err error) {
	if _, err = fmt.Fprintf(w, "%s %s SIP/2.0\r\n", this.GetMethod(), this.GetRequestURI()); err != nil {
		return err
	}
	return nil
}

// ReadMessage reads and parses an incoming message from b.
func ReadRequestMessage(b *bufio.Reader) (msg Request, err error) {
	tp := newTextprotoReader(b)

	// First line: INVITE sip:bob@biloxi.com SIP/2.0 or SIP/2.0 180 Ringing
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	s1 := strings.Index(s, " ")
	s2 := strings.Index(s[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return nil, fmt.Errorf("malformed SIP request %s", s)
	}
	s2 += s1 + 1

	if strings.TrimSpace(s[:s1]) == "SIP/2.0" {
		return
	} else {
		method, requestURI, sipVersion := s[:s1], s[s1+1:s2], s[s2+1:]
		if _, _, ok := ParseSIPVersion(sipVersion); !ok {
			return nil, fmt.Errorf("malformed SIP version", sipVersion)
		}
		msg = NewRequest(method, requestURI, nil)
	}

	////////////////////////////////////////////////////////////////////////////
	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	msg.SetHeader(Header(mimeHeader))

	////////////////////////////////////////////////////////////////////////////

	contentLens := msg.GetHeader()["Content-Length"]
	if len(contentLens) > 1 { // harden against SIP request smuggling. See RFC 7230.
		return nil, errors.New("http: message cannot contain multiple Content-Length headers")
	} else if len(contentLens) == 0 {
		msg.SetContentLength(0)
	} else {
		if cl, err := parser.NewContentLengthParser("Content-Length: " + contentLens[0]).Parse(); err != nil {
			return nil, err
		} else {
			msg.SetContentLength(int64(cl.(header.ContentLengthHeader).GetContentLength()))
		}
	}

	////////////////////////////////////////////////////////////////////////////

	if msg.GetContentLength() > 0 {
		msg.SetBody(io.LimitReader(b, int64(msg.GetContentLength())))
	} else {
		msg.SetBody(nil)
	}

	return msg, nil
}
