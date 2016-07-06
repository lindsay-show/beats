package msrp

import (
	"bytes"
	"github.com/elastic/beats/libbeat/common"
	"time"
	//"github.com/elastic/beats/libbeat/common/streambuf"
	//"github.com/elastic/beats/libbeat/logp"
)

// MSRP Message
type message struct {
	Ts           time.Time
	IsRequest    bool
	TCPTuple     common.TcpTuple
	CmdlineTuple *common.CmdlineTuple
	Direction    uint8
	IsError      bool
	headerOffset int
	bodyOffset   int
	//Request Info
	TransactionID common.NetString
	Method        common.NetString

	Message common.NetString

	//Response Info
	StatusCode   common.NetString
	StatusPhrase common.NetString

	// Msrp Headers
	Headers   map[string]common.NetString
	ToPath    common.NetString
	FromPath  common.NetString
	MessageId common.NetString
	Size      uint64
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
	nameToPath    = []byte("To-Path")
	nameFromPath  = []byte("From-Path")
	nameMessageId = []byte("Message-ID")
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
	if bytes.Equal(fline[0:4], []byte("MSRP")) {
		//RESPONSE
		m.IsRequest = false
		slices := bytes.Fields(fline)
		if len(slices) != 4 {
			if isDebug {
				debugf("Couldn't understand MSRP response: %s", fline)
			}
			return false, false, false
		}
		m.IsRequest = false

		m.TransactionID = common.NetString(slices[1])
		m.StatusCode = common.NetString(slices[2])
		m.StatusPhrase = common.NetString(slices[3])

		if isDebug {
			debugf("MSRP transactionID=%s, status_code=%d, status_phrase=%s", m.TransactionID, m.StatusCode, m.StatusPhrase)
		}
	} else {
		// REQUEST
		slices := bytes.Fields(fline)
		if len(slices) != 3 {
			if isDebug {
				debugf("Couldn't understand MSRP request: %s", fline)
			}
			return false, false, false
		}

		m.TransactionID = common.NetString(slices[1])
		m.Method = common.NetString(slices[2])
		// TO DO
		if bytes.Equal(slices[0], []byte("MSRP")) {
			m.IsRequest = true
		} else {
			if isDebug {
				debugf("Couldn't understand MSRP version: %s", fline)
			}
			return false, false, false
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

	//config := parser.config

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
