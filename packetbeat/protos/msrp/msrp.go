package msrp

import (
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
)

var debugf = logp.MakeDebug("msrp")
var detailedf = logp.MakeDebug("msrpdetailed")

type parserState uint8

const (
	msrpStateStart parserState = iota
	msrpStateHeaders
	msrpStateBody
)

type MsrpStream struct {
	tcptuple *common.TcpTuple

	data []byte

	parseOffset int
	parseState  parserState
	message     *message
}

type msrpPrivateData struct {
	Streams   [2]*MsrpStream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// Msrp application level protocol analyser plugin.
type Msrp struct {
	// config
	Range              PortRange
	SendRequest        bool
	SendResponse       bool
	parserConfig       parserConfig
	transactionTimeout time.Duration

	results publish.Transactions
}

var (
	isDebug    = false
	isDetailed = false
)

func init() {
	protos.Register("msrp", New)
}

func New(
	testMode bool,
	results publish.Transactions,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &Msrp{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

// Init initializes the Msrp protocol analyser.
func (msrp *Msrp) init(results publish.Transactions, config *msrpConfig) error {
	msrp.setFromConfig(config)

	isDebug = logp.IsDebug("msrp")
	isDetailed = logp.IsDebug("msrpdetailed")
	msrp.results = results
	return nil
}

func (msrp *Msrp) setFromConfig(config *msrpConfig) error {
	//msrp.Ports = config.Ports
	msrp.Range = config.Ports.Range
	msrp.SendRequest = config.SendRequest
	msrp.SendResponse = config.SendResponse
	msrp.transactionTimeout = config.TransactionTimeout
	return nil
}

// GetPorts lists the port numbers the Msrp protocol analyser will handle.
func (msrp *Msrp) GetPorts() []int {
	portrange := msrp.Range
	first := portrange[0]
	last := portrange[1]
	ports := make([]int, 0, last-first+1)
	for i := first; i <= last; i++ {
		ports = append(ports, i)
	}
	return ports
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (msrp *Msrp) messageGap(s *MsrpStream, nbytes int) (ok bool, complete bool) {

	m := s.message
	switch s.parseState {
	case msrpStateStart, msrpStateHeaders:
		// we know we cannot recover from these
		return false, false
	case msrpStateBody:
		if isDebug {
			debugf("gap in body: %d", nbytes)
		}

		if m.IsRequest {
			m.Notes = append(m.Notes, "Packet loss while capturing the request")
		} else {
			m.Notes = append(m.Notes, "Packet loss while capturing the response")
		}
	}
	// assume we cannot recover
	return false, false
}

func (stream *MsrpStream) PrepareForNewMessage() {
	stream.data = stream.data[stream.message.end:]
	stream.parseState = msrpStateStart
	stream.parseOffset = 0
	stream.message = nil
}

// Called when the parser has identified the boundary of a message.
func (msrp *Msrp) messageComplete(
	conn *msrpPrivateData,
	tcptuple *common.TcpTuple,
	dir uint8,
	stream *MsrpStream,
) {
	stream.message.Raw = stream.data[stream.message.start:stream.message.end]

	msrp.handleMsrp(conn, stream.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured Msrp transaction timeout.
func (msrp *Msrp) ConnectionTimeout() time.Duration {
	return msrp.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (msrp *Msrp) Parse(
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseHttp exception")

	conn := ensureMsrpConnection(private)
	conn = msrp.doParse(conn, pkt, tcptuple, dir)
	if conn == nil {
		return nil
	}
	return conn
}

func ensureMsrpConnection(private protos.ProtocolData) *msrpPrivateData {
	conn := getMsrpConnection(private)
	if conn == nil {
		conn = &msrpPrivateData{}
	}
	return conn
}

func getMsrpConnection(private protos.ProtocolData) *msrpPrivateData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*msrpPrivateData)
	if !ok {
		logp.Warn("msrp connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: msrp connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (msrp *Msrp) doParse(
	conn *msrpPrivateData,
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
) *msrpPrivateData {

	if isDetailed {
		detailedf("Payload received: [%s]", pkt.Payload)
	}

	st := conn.Streams[dir]
	if st == nil {
		st = newStream(pkt, tcptuple)
		conn.Streams[dir] = st
	} else {
		// concatenate bytes
		st.data = append(st.data, pkt.Payload...)
		if len(st.data) > tcp.TCP_MAX_DATA_IN_STREAM {
			if isDebug {
				debugf("Stream data too large, dropping TCP stream")
			}
			conn.Streams[dir] = nil
			return conn
		}
	}

	for len(st.data) > 0 {
		if st.message == nil {
			st.message = &message{Ts: pkt.Ts}
		}

		parser := newParser(&msrp.parserConfig)
		ok, complete := parser.parse(st)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.Streams[dir] = nil
			return conn
		}

		if !complete {
			// wait for more data
			break
		}

		// all ok, ship it
		msrp.messageComplete(conn, tcptuple, dir, st)

		// and reset stream for next message
		st.PrepareForNewMessage()
	}

	return conn
}
func newStream(pkt *protos.Packet, tcptuple *common.TcpTuple) *MsrpStream {
	return &MsrpStream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &message{Ts: pkt.Ts},
	}
}

// ReceivedFin will be called when TCP transaction is terminating.
func (msrp *Msrp) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	conn := getMsrpConnection(private)
	if conn == nil {
		return private
	}

	stream := conn.Streams[dir]
	if stream == nil {
		return conn
	}

	// send whatever data we got so far as complete. This
	// is needed for the Msrp/1.0 without Content-Length situation.
	if stream.message != nil && len(stream.data[stream.message.start:]) > 0 {
		stream.message.Raw = stream.data[stream.message.start:]
		msrp.handleMsrp(conn, stream.message, tcptuple, dir)

		// and reset message. Probably not needed, just to be sure.
		stream.PrepareForNewMessage()
	}

	return conn
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
// Called when a packets are missing from the tcp stream.
func (msrp *Msrp) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(msrp) exception")

	conn := getMsrpConnection(private)
	if conn == nil {
		return private, false
	}

	stream := conn.Streams[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	ok, complete := msrp.messageGap(stream, nbytes)
	if isDetailed {
		detailedf("messageGap returned ok=%v complete=%v", ok, complete)
	}
	if !ok {
		// on errors, drop stream
		conn.Streams[dir] = nil
		return conn, true
	}

	if complete {
		// Current message is complete, we need to publish from here
		msrp.messageComplete(conn, tcptuple, dir, stream)
	}

	// don't drop the stream, we can ignore the gap
	return private, false
}

func (msrp *Msrp) handleMsrp(
	conn *msrpPrivateData,
	m *message,
	tcptuple *common.TcpTuple,
	dir uint8,
) {

	m.TCPTuple = *tcptuple
	m.Direction = dir
	m.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())
	//msrp.hideHeaders(m)

	if m.IsRequest {
		if isDebug {
			debugf("Received request with tuple: %s", m.TCPTuple)
		}
		conn.requests.append(m)
	} else {
		if isDebug {
			debugf("Received response with tuple: %s", m.TCPTuple)
		}
		conn.responses.append(m)
		msrp.correlate(conn)
	}
}

func (msrp *Msrp) correlate(conn *msrpPrivateData) {
	// drop responses with missing requests
	if conn.requests.empty() {
		for !conn.responses.empty() {
			logp.Warn("Response from unknown transaction. Ingoring.")
			conn.responses.pop()
		}
		return
	}

	// merge requests with responses into transactions
	for !conn.responses.empty() && !conn.requests.empty() {
		requ := conn.requests.pop()
		resp := conn.responses.pop()
		trans := msrp.newTransaction(requ, resp)

		if isDebug {
			debugf("Msrp transaction completed")
		}
		msrp.publishTransaction(trans)
	}
}

func (msrp *Msrp) newTransaction(requ, resp *message) common.MapStr {
	status := common.OK_STATUS

	// resp_time in milliseconds
	responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

	src := common.Endpoint{
		Ip:   requ.TCPTuple.Src_ip.String(),
		Port: requ.TCPTuple.Src_port,
		Proc: string(requ.CmdlineTuple.Src),
	}
	dst := common.Endpoint{
		Ip: requ.TCPTuple.Dst_ip.String(),

		Port: requ.TCPTuple.Dst_port,
		Proc: string(requ.CmdlineTuple.Dst),
	}
	if requ.Direction == tcp.TcpDirectionReverse {
		src, dst = dst, src
	}

	details := common.MapStr{
		"phrase": resp.StatusPhrase,
		"code":   resp.StatusCode,
	}

	event := common.MapStr{
		"@timestamp":   common.Time(requ.Ts),
		"type":         "msrp",
		"status":       status,
		"responsetime": responseTime,
		"method":       requ.Method,
		"msrp":         details,
		"bytes_out":    resp.Size,
		"bytes_in":     requ.Size,
		"src":          &src,
		"dst":          &dst,
	}

	if msrp.SendRequest {
		event["request"] = string(msrp.cutMessageBody(requ))
	}
	if msrp.SendResponse {
		event["response"] = string(msrp.cutMessageBody(resp))
	}
	if len(requ.Notes)+len(resp.Notes) > 0 {
		event["notes"] = append(requ.Notes, resp.Notes...)
	}

	return event
}

func (msrp *Msrp) publishTransaction(event common.MapStr) {
	if msrp.results == nil {
		return
	}
	msrp.results.PublishTransaction(event)
}
func (msrp *Msrp) cutMessageBody(m *message) []byte {
	cutMsg := []byte{}

	// add headers always
	cutMsg = m.Raw[:m.bodyOffset]

	// add body
	if len(m.ContentType) == 0 {

		if isDebug {
			debugf("Body to include: [%s]", m.Raw[m.bodyOffset:])
		}
		cutMsg = append(cutMsg, m.Raw[m.bodyOffset:]...)
	}

	return cutMsg
}
func (ml *messageList) append(msg *message) {
	if ml.tail == nil {
		ml.head = msg
	} else {
		ml.tail.next = msg
	}
	msg.next = nil
	ml.tail = msg
}
func (ml *messageList) empty() bool {
	return ml.head == nil
}

func (ml *messageList) pop() *message {
	if ml.head == nil {
		return nil
	}

	msg := ml.head
	ml.head = ml.head.next
	if ml.head == nil {
		ml.tail = nil
	}
	return msg
}

func (ml *messageList) last() *message {
	return ml.tail
}
