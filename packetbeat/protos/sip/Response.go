package sip

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/elastic/beats/packetbeat/protos/sip/header"
	"github.com/elastic/beats/packetbeat/protos/sip/parser"
	"io"
	"strconv"
	"strings"
)

type Response interface {
	Message

	SetStatusCode(statusCode int) error
	GetStatusCode() int
	SetReasonPhrase(reasonPhrase string) error
	GetReasonPhrase() string
}

const (
	TRYING                             = 100
	RINGING                            = 180
	CALL_IS_BEING_FORWARDED            = 181
	QUEUED                             = 182
	SESSION_PROGRESS                   = 183
	OK                                 = 200
	ACCEPTED                           = 202
	MULTIPLE_CHOICES                   = 300
	MOVED_PERMANENTLY                  = 301
	MOVED_TEMPORARILY                  = 302
	USE_PROXY                          = 305
	ALTERNATIVE_SERVICE                = 380
	BAD_REQUEST                        = 400
	UNAUTHORIZED                       = 401
	PAYMENT_REQUIRED                   = 402
	FORBIDDEN                          = 403
	NOT_FOUND                          = 404
	METHOD_NOT_ALLOWED                 = 405
	NOT_ACCEPTABLE                     = 406
	PROXY_AUTHENTICATION_REQUIRED      = 407
	REQUEST_TIMEOUT                    = 408
	GONE                               = 410
	REQUEST_ENTITY_TOO_LARGE           = 413
	REQUEST_URI_TOO_LONG               = 414
	UNSUPPORTED_MEDIA_TYPE             = 415
	UNSUPPORTED_URI_SCHEME             = 416
	BAD_EXTENSION                      = 420
	EXTENSION_REQUIRED                 = 421
	INTERVAL_TOO_BRIEF                 = 423
	TEMPORARILY_UNAVAILABLE            = 480
	CALL_OR_TRANSACTION_DOES_NOT_EXIST = 481
	LOOP_DETECTED                      = 482
	TOO_MANY_HOPS                      = 483
	ADDRESS_INCOMPLETE                 = 484
	AMBIGUOUS                          = 485
	BUSY_HERE                          = 486
	REQUEST_TERMINATED                 = 487
	NOT_ACCEPTABLE_HERE                = 488
	BAD_EVENT                          = 489
	REQUEST_PENDING                    = 491
	UNDECIPHERABLE                     = 493
	SERVER_INTERNAL_ERROR              = 500
	NOT_IMPLEMENTED                    = 501
	BAD_GATEWAY                        = 502
	SERVICE_UNAVAILABLE                = 503
	SERVER_TIMEOUT                     = 504
	VERSION_NOT_SUPPORTED              = 505
	MESSAGE_TOO_LARGE                  = 513
	BUSY_EVERYWHERE                    = 600
	DECLINE                            = 603
	DOES_NOT_EXIST_ANYWHERE            = 604
	SESSION_NOT_ACCEPTABLE             = 606
)

////////////////////////////////////////////////////////////////////////////////
type response struct {
	message

	statusCode   int
	reasonPhrase string
}

func NewResponse(statusCode int, reasonPhrase string, body io.Reader) *response {
	this := &response{
		message: message{
			sipVersion: "SIP/2.0",
			header:     make(Header),
			body:       body,
		},
		statusCode:   statusCode,
		reasonPhrase: reasonPhrase,
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

func (this *response) SetStatusCode(statusCode int) error {
	this.statusCode = statusCode
	return nil
}

func (this *response) GetStatusCode() int {
	return this.statusCode
}

func (this *response) SetReasonPhrase(reasonPhrase string) error {
	this.reasonPhrase = reasonPhrase
	return nil
}

func (this *response) GetReasonPhrase() string {
	return this.reasonPhrase
}

//SIP/2.0 StatusCode reasonPhrase
func (this *response) StartLineWrite(w io.Writer) (err error) {
	if _, err = fmt.Fprintf(w, "SIP/2.0 %d %s\r\n", this.GetStatusCode(), this.GetReasonPhrase()); err != nil {
		return err
	}
	return nil
}

// ReadMessage reads and parses an incoming message from b.
func ReadResponseMessage(b *bufio.Reader) (msg Response, err error) {
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
		var statusCode int
		if statusCode, err = strconv.Atoi(s[s1+1 : s2]); err != nil {
			return nil, fmt.Errorf("malformed SIP status code %s", s[s1+1:s2])
		}
		sipVersion, reasonPhrase := s[:s1], s[s2+1:]
		if _, _, ok := ParseSIPVersion(sipVersion); !ok {
			return nil, fmt.Errorf("malformed SIP version", sipVersion)
		}
		msg = NewResponse(statusCode, reasonPhrase, nil)
	} else {
		return
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
