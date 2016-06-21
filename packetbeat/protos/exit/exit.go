package exit

import (
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
)

// exit application level protocol analyzer plugin
type exit struct {
	ports        protos.PortsConfig
	parserConfig parserConfig
	transConfig  transactionConfig
	pub          transPub
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   transactions
}

// Uni-directioal tcp stream state for parsing messages.
type stream struct {
	parser parser
}

var (
	debugf = logp.MakeDebug("exit")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = false
)

func init() {
	protos.Register("exit", New)
}

// New create and initializes a new sip protocol analyzer instance.
func New(
	testMode bool,
	results publish.Transactions,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &exit{}
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

func (exit *exit) init(results publish.Transactions, config *exitConfig) error {
	if err := exit.setFromConfig(config); err != nil {
		return err
	}
	exit.pub.results = results

	isDebug = logp.IsDebug("http")
	return nil
}

func (exit *exit) setFromConfig(config *exitConfig) error {

	// set module configuration
	if err := exit.ports.Set(config.Ports); err != nil {
		return err
	}

	// set parser configuration
	parser := &exit.parserConfig
	parser.maxBytes = tcp.TCP_MAX_DATA_IN_STREAM

	// set transaction correlator configuration
	trans := &exit.transConfig
	trans.transactionTimeout = config.TransactionTimeout

	// set transaction publisher configuration
	pub := &exit.pub
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse

	return nil
}

// ConnectionTimeout returns the per stream connection timeout.
// Return <=0 to set default tcp module transaction timeout.
func (exit *exit) ConnectionTimeout() time.Duration {
	return exit.transConfig.transactionTimeout
}

// GetPorts returns the ports numbers packets shall be processed for.
func (exit *exit) GetPorts() []int {
	return exit.ports.Ports
}

// Parse processes a TCP packet. Return nil if connection
// state shall be dropped (e.g. parser not in sync with tcp stream)
func (exit *exit) Parse(
	pkt *protos.Packet,
	tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("Parse exit exception")

	conn := exit.ensureConnection(private)
	st := conn.streams[dir]
	if st == nil {
		st = &stream{}
		st.parser.init(&exit.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IpPort(), dir, msg)
		})
		conn.streams[dir] = st
	}

	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil {
		debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		exit.onDropConnection(conn)
		return nil
	}
	return conn
}

// ReceivedFin handles TCP-FIN packet.
func (exit *exit) ReceivedFin(
	tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream handles lost packets in tcp-stream.
func (exit *exit) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	conn := getConnection(private)
	if conn != nil {
		exit.onDropConnection(conn)
	}

	return nil, true
}

// onDropConnection processes and optionally sends incomplete
// transaction in case of connection being dropped due to error
func (exit *exit) onDropConnection(conn *connection) {
}

func (exit *exit) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&exit.transConfig, exit.pub.onTransaction)
	}
	return conn
}

func (conn *connection) dropStreams() {
	conn.streams[0] = nil
	conn.streams[1] = nil
}

func getConnection(private protos.ProtocolData) *connection {
	if private == nil {
		return nil
	}

	priv, ok := private.(*connection)
	if !ok {
		logp.Warn("exit connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: exit connection data not set")
		return nil
	}
	return priv
}
