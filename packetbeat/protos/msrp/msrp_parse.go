package msrp

import (
	"bytes"
	"github.com/elastic/beats/libbeat/common"
	//"github.com/elastic/beats/libbeat/common/streambuf"
	//"github.com/elastic/beats/libbeat/logp"
	"time"
)

// MSRP Message
type message struct {
	Ts               time.Time
	hasContentType   bool
	hasContentLength bool
	IsRequest        bool
	TCPTuple         common.TcpTuple
	CmdlineTuple     *common.CmdlineTuple
	Direction        uint8
	IsError          bool
	headerOffset     int
	bodyOffset       int
	Size             uint64
	//Request Info
	TransactionID common.NetString
	Method        common.NetString

	Message common.NetString

	//Response Info
	StatusCode   common.NetString
	StatusPhrase common.NetString

	// Msrp Headers
	Headers       map[string]common.NetString
	ToPath        common.NetString
	FromPath      common.NetString
	MessageId     common.NetString
	ContentLength int
	ContentType   common.NetString
	//Raw Data
	Raw []byte

	Notes []string

	//Timing
	start int
	end   int

	next *message
}
type parser struct {
	config *parserConfig
}

type parserConfig struct {
	SendHeaders    bool
	SendAllHeaders bool
}

var (
	constCRLF     = []byte("\r\n")
	nameToPath    = []byte("to-path")
	nameFromPath  = []byte("from-path")
	nameMessageId = []byte("message-id")
)

func newParser(config *parserConfig) *parser {
	return &parser{config: config}
}
func (parser *parser) parse(s *MsrpStream) (bool, bool) {
	m := s.message

	for s.parseOffset < len(s.data) {
		switch s.parseState {
		case msrpStateStart:
			if cont, ok, complete := parser.parseMSRPLine(s, m); !cont {
				return ok, complete
			}
		case msrpStateHeaders:
			if cont, ok, complete := parser.parseHeaders(s, m); !cont {
				return ok, complete
			}
		case msrpStateBody:
			return parser.parseBody(s, m)
		}
	}

	return true, false
}
func (*parser) parseMSRPLine(s *MsrpStream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset
	i := bytes.Index(s.data[s.parseOffset:], []byte("\r\n"))
	if i == -1 {
		return false, true, false
	}

	// Very basic tests on the first line. Just to check that
	// we have what looks as an MSRP message
	fline := s.data[s.parseOffset:i]
	if len(fline) < 4 {
		if isDebug {
			debugf("First line too small")
		}
		return false, false, false
	}
	slices := bytes.Fields(fline)
	if len(slices) == 4 || len(slices) == 5 {
		//RESPONSE
		m.IsRequest = false

		m.TransactionID = common.NetString(slices[1])
		m.StatusCode = common.NetString(slices[2])
		p := bytes.LastIndexByte(fline, ' ')
		if p == -1 {
			return false, false, false
		}
		m.StatusPhrase = fline[p+1:]
		//m.StatusPhrase = common.NetString(slices[3])

		if isDebug {
			debugf("MSRP transactionID=%s, status_code=%s, status_phrase=%s", m.TransactionID, m.StatusCode, m.StatusPhrase)
		}
	} else if len(slices) == 3 {
		// REQUEST
		m.IsRequest = true
		m.TransactionID = common.NetString(slices[1])
		m.Method = common.NetString(slices[2])
		if isDebug {
			debugf("MSRP transactionID=%s, method=%s", m.TransactionID, m.Method)
		}

	}

	// ok so far
	s.parseOffset = i + 2
	m.headerOffset = s.parseOffset
	s.parseState = msrpStateHeaders
	return true, true, true
}
func (parser *parser) parseHeaders(s *MsrpStream, m *message) (cont, ok, complete bool) {
	if len(s.data)-s.parseOffset >= 2 &&
		bytes.Equal(s.data[s.parseOffset:s.parseOffset+2], []byte("\r\n")) {
		// EOH
		s.parseOffset += 2
		m.bodyOffset = s.parseOffset
		if !m.IsRequest {
			m.end = s.parseOffset
			m.Size = uint64(m.end - m.start)
			return false, true, true
		}

		if m.ContentLength == 0 && (m.IsRequest || m.hasContentLength) {
			if isDebug {
				debugf("Empty content length, ignore body")
			}
			// Ignore body for request that contains a message body but not a Content-Length
			m.end = s.parseOffset
			m.Size = uint64(m.end - m.start)
			return false, true, true
		}

		if isDebug {
			debugf("Read body")
		}
		s.parseState = msrpStateBody
	} else {
		ok, hfcomplete, offset := parser.parseHeader(m, s.data[s.parseOffset:])
		if !ok {
			return false, false, false
		}
		if !hfcomplete {
			return false, true, false
		}
		s.parseOffset += offset
	}
	return true, true, true
}

func (parser *parser) parseHeader(m *message, data []byte) (bool, bool, int) {
	if m.Headers == nil {
		m.Headers = make(map[string]common.NetString)
	}
	i := bytes.Index(data, []byte(":"))
	if i == -1 {
		// Expected \":\" in headers. Assuming incomplete"
		return true, false, 0
	}

	// enabled if required. Allocs for parameters slow down parser big times
	if isDetailed {
		detailedf("Data: %s", data)
		detailedf("Header: %s", data[:i])
	}

	// skip folding line
	for p := i + 1; p < len(data); {
		q := bytes.Index(data[p:], constCRLF)
		if q == -1 {
			// Assuming incomplete
			return true, false, 0
		}
		p += q
		if len(data) > p && (data[p+1] == ' ' || data[p+1] == '\t') {
			p = p + 2
		} else {
			var headerNameBuf [140]byte
			headerName := toLower(headerNameBuf[:], data[:i])
			headerVal := trim(data[i+1 : p])
			if isDebug {
				debugf("Header: '%s' Value: '%s'\n", data[:i], headerVal)
			}
			if bytes.Equal(headerName, nameToPath) {
				m.ToPath = common.NetString(headerVal)
			} else if bytes.Equal(headerName, nameFromPath) {
				m.FromPath = common.NetString(headerVal)
			} else if bytes.Equal(headerName, nameMessageId) {
				m.MessageId = common.NetString(headerVal)
			}
			return true, true, p + 2
		}
	}

	return true, false, len(data)
}
func (*parser) parseBody(s *MsrpStream, m *message) (ok, complete bool) {

	return true, false
}

func trim(buf []byte) []byte {
	return trimLeft(trimRight(buf))
}

func trimLeft(buf []byte) []byte {
	for i, b := range buf {
		if b != ' ' && b != '\t' {
			return buf[i:]
		}
	}
	return nil
}

func trimRight(buf []byte) []byte {
	for i := len(buf) - 1; i > 0; i-- {
		b := buf[i]
		if b != ' ' && b != '\t' {
			return buf[:i+1]
		}
	}
	return nil
}
func toLower(buf, in []byte) []byte {
	if len(in) > len(buf) {
		goto unbufferedToLower
	}

	for i, b := range in {
		if b > 127 {
			goto unbufferedToLower
		}

		if 'A' <= b && b <= 'Z' {
			b = b - 'A' + 'a'
		}
		buf[i] = b
	}
	return buf[:len(in)]

unbufferedToLower:
	return bytes.ToLower(in)
}
