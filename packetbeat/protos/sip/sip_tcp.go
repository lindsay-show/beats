package sip

// sip based tcp(to do)
/*import (
	"encoding/binary"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
)

const MaxSipMessageSize = (1 << 16) - 1

// RFC 1035
// The 2 first bytes contain the length of the message
const DecodeOffset = 2

// SipStream contains SIP data from one side of a TCP transmission. A pair
// of SipStream's are used to represent the full conversation.
type SipStream struct {
	tcpTuple    *common.TcpTuple
	rawData     []byte
	parseOffset int
	message     *SipMessage
}

// sipConnectionData contains two SipStream's that hold data from a complete TCP
// transmission. Element zero contains the response data. Element one contains
// the request data.
// prevRequest (previous Request) is used to add Notes to a transaction when a failing answer is encountered
type sipConnectionData struct {
	Data        [2]*SipStream
	prevRequest *SipMessage
}

func (sip *Sip) Parse(pkt *protos.Packet, tcpTuple *common.TcpTuple, dir uint8, private protos.ProtocolData) protos.ProtocolData {
	defer logp.Recover("Sip ParseTcp")

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), len(pkt.Payload))

	conn := ensureSipConnection(private)

	conn = sip.doParse(conn, pkt, tcpTuple, dir)
	if conn == nil {
		return nil
	}

	return conn
}

func ensureSipConnection(private protos.ProtocolData) *sipConnectionData {
	if private == nil {
		return &sipConnectionData{}
	}

	conn, ok := private.(*sipConnectionData)
	if !ok {
		logp.Warn("Sip connection data type error, create new one")
		return &sipConnectionData{}
	}
	if conn == nil {
		logp.Warn("Unexpected: sip connection data not set, create new one")
		return &sipConnectionData{}
	}

	return conn
}

func (sip *Sip) doParse(conn *sipConnectionData, pkt *protos.Packet, tcpTuple *common.TcpTuple, dir uint8) *sipConnectionData {
	stream := conn.Data[dir]
	payload := pkt.Payload

	if stream == nil {
		stream = newStream(pkt, tcpTuple)
		conn.Data[dir] = stream
	} else {
		if stream.message == nil { // nth message of the same stream
			stream.message = &SipMessage{Ts: pkt.Ts, Tuple: pkt.Tuple}
		}

		stream.rawData = append(stream.rawData, payload...)
		if len(stream.rawData) > tcp.TCP_MAX_DATA_IN_STREAM {
			debugf("Stream data too large, dropping SIP stream")
			conn.Data[dir] = nil
			return conn
		}
	}
	decodedData, err := stream.handleTcpRawData()

	if err != nil {

		if err == IncompleteMsg {
			debugf("Waiting for more raw data")
			return conn
		}

		if dir == tcp.TcpDirectionReverse {
			sip.publishResponseError(conn, err)
		}

		debugf("%s addresses %s, length %d", err.Error(),
			tcpTuple.String(), len(stream.rawData))

		// This means that malformed requests or responses are being sent...
		// TODO: publish the situation also if Request
		conn.Data[dir] = nil
		return conn
	}

	sip.messageComplete(conn, tcpTuple, dir, decodedData)
	stream.PrepareForNewMessage()
	return conn
}

func newStream(pkt *protos.Packet, tcpTuple *common.TcpTuple) *SipStream {
	return &SipStream{
		tcpTuple: tcpTuple,
		rawData:  pkt.Payload,
		message:  &SipMessage{Ts: pkt.Ts, Tuple: pkt.Tuple},
	}
}

func (sip *Sip) messageComplete(conn *sipConnectionData, tcpTuple *common.TcpTuple, dir uint8, //decodedData *mkdns.Msg) {
	sip.handleSip(conn, tcpTuple, decodedData, dir)
}

func (sip *Sip) handleSip(conn *sipConnectionData, tcpTuple *common.TcpTuple, //decodedData *mkdns.Msg, dir uint8) {
	message := conn.Data[dir].message
	sipTuple := SipTupleFromIpPort(&message.Tuple, TransportTcp, decodedData.Id)

	message.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcpTuple.IpPort())
	message.Data = decodedData
	message.Length += DecodeOffset

	if decodedData.Response {
		sip.receivedSipResponse(&sipTuple, message)
		conn.prevRequest = nil
	} else  {
		sip.receivedSipRequest(&sipTuple, message)
		conn.prevRequest = message
	}
}

func (stream *SipStream) PrepareForNewMessage() {
	stream.rawData = stream.rawData[stream.parseOffset:]
	stream.message = nil
	stream.parseOffset = 0
}

func (sip *Sip) ReceivedFin(tcpTuple *common.TcpTuple, dir uint8, private protos.ProtocolData) protos.ProtocolData {
	if private == nil {
		return nil
	}
	conn, ok := private.(*sipConnectionData)
	if !ok {
		return private
	}
	stream := conn.Data[dir]

	if stream == nil || stream.message == nil {
		return conn
	}

	decodedData, err := stream.handleTcpRawData()

	if err == nil {
		sip.messageComplete(conn, tcpTuple, dir, decodedData)
		return conn
	}

	if dir == tcp.TcpDirectionReverse {
		sip.publishResponseError(conn, err)
	}

	debugf("%s addresses %s, length %d", err.Error(),
		tcpTuple.String(), len(stream.rawData))

	return conn
}

func (sip *Sip) GapInStream(tcpTuple *common.TcpTuple, dir uint8, nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {
	if private == nil {
		return private, true
	}
	conn, ok := private.(*sipConnectionData)
	if !ok {
		return private, false
	}
	stream := conn.Data[dir]

	if stream == nil || stream.message == nil {
		return private, false
	}

	decodedData, err := stream.handleTcpRawData()

	if err == nil {
		sip.messageComplete(conn, tcpTuple, dir, decodedData)
		return private, true
	}

	if dir == tcp.TcpDirectionReverse {
		sip.publishResponseError(conn, err)
	}

	debugf("%s addresses %s, length %d", err.Error(),
		tcpTuple.String(), len(stream.rawData))
	debugf("Dropping the stream %s", tcpTuple.String())

	// drop the stream because it is binary Data and it would be unexpected to have a decodable message later
	return private, true
}

// Add Notes to the transaction about a failure in the response
// Publish and remove the transaction
func (sip *Sip) publishResponseError(conn *sipConnectionData, err error) {
	streamOrigin := conn.Data[tcp.TcpDirectionOriginal]
	streamReverse := conn.Data[tcp.TcpDirectionReverse]

	if streamOrigin == nil || conn.prevRequest == nil || streamReverse == nil {
		return
	}

	dataOrigin := conn.prevRequest.Data
	sipTupleOrigin := SipTupleFromIpPort(&conn.prevRequest.Tuple, TransportTcp, dataOrigin.Id)
	hashSipTupleOrigin := (&sipTupleOrigin).Hashable()

	trans := sip.deleteTransaction(hashSipTupleOrigin)

	if trans == nil { // happens if Parse, Gap or Fin already published the response error
		return
	}
// TO DO SIP ERRORS
	errSip, ok := err.(*SIPError)
	if !ok {
		return
	}
	trans.Notes = append(trans.Notes, errSip.ResponseError())

	// Should we publish the length (bytes_out) of the failed Response?
	//streamReverse.message.Length = len(streamReverse.rawData)
	//trans.Response = streamReverse.message

	sip.publishTransaction(trans)
	sip.deleteTransaction(hashSipTupleOrigin)
}

// Manages data length prior to decoding the data and manages errors after decoding
func (stream *SipStream) handleTcpRawData() (*mkdns.Msg, error) {
	rawData := stream.rawData
	messageLength := len(rawData)

	if messageLength < DecodeOffset {
		return nil, IncompleteMsg
	}

	if stream.message.Length == 0 {
		stream.message.Length = int(binary.BigEndian.Uint16(rawData[:DecodeOffset]))
		messageLength := stream.message.Length
		stream.parseOffset = messageLength + DecodeOffset

		// TODO: This means that malformed requests or responses are being sent or
		// that someone is attempting to the DNS port for non-DNS traffic.
		// We might want to publish this in the future, for security reasons
		if messageLength <= 0 {
			return nil, ZeroLengthMsg
		}
		if messageLength > MaxDnsMessageSize { // Should never be true though ...
			return nil, UnexpectedLengthMsg
		}
	}

	if messageLength < stream.parseOffset {
		return nil, IncompleteMsg
	}

	decodedData, err := decodeSipData(TransportTcp, rawData[:stream.parseOffset])
	if err != nil {
		return nil, err
	}

	return decodedData, nil
}*/
