// Package sip provides support for parsing SIP messages and reporting the results.
// Sip plugin initialization, message/transaction types and transaction initialization/publishing.
// This package supports the SIP protocol as defined by RFC 3261.
package sip

import (
	"fmt"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"
	"net"
	"time"
)

var (
	debugf = logp.MakeDebug("sip")
)

type Transport uint8

const (
	TransportTcp = iota
	TransportUdp
)

var TransportNames = []string{
	"tcp",
	"udp",
}

func (t Transport) String() string {
	if int(t) >= len(TransportNames) {
		return "impossible"
	}
	return TransportNames[t]
}

const MaxSipTupleRawSize = 1000

type HashableSipTuple [MaxSipTupleRawSize]byte

// SipMessage contains a single SIP message.
type SipMessage struct {
	Ts           time.Time          // Time when the message was received.
	Tuple        common.IpPortTuple // Source and destination addresses of packet.
	CmdlineTuple *common.CmdlineTuple
	Length       int // Length of the SIP message in bytes (without DecodeOffset).
	//Data         *message /// Parsed SIP packet data
}

// ReqSipMessage contains a single SIP message.
type ReqSipMessage struct {
	SipMessage
	Req *request
}

// ReqSipMessage contains a single SIP message.
type RespSipMessage struct {
	SipMessage
	Resp *response
}

// SipTuple contains source IP/port, destination IP/port, transport protocol,
// and Sip ID.
// eg:common/tuples IpPortTuple struct.
type SipTuple struct {
	Ip_length          int
	Src_ip, Dst_ip     net.IP
	Src_port, Dst_port uint16
	Transport          Transport
	Id                 uint16

	raw    HashableSipTuple // Src_ip:Src_port:Dst_ip:Dst_port:Transport:Id
	revRaw HashableSipTuple // Dst_ip:Dst_port:Src_ip:Src_port:Transport:Id
}

func SipTupleFromIpPort(t *common.IpPortTuple, trans Transport, id uint16) SipTuple {
	tuple := SipTuple{
		Ip_length: t.Ip_length,
		Src_ip:    t.Src_ip,
		Dst_ip:    t.Dst_ip,
		Src_port:  t.Src_port,
		Dst_port:  t.Dst_port,
		Transport: trans,
		Id:        id,
	}
	tuple.ComputeHashebles()

	return tuple
}
func (t SipTuple) Reverse() SipTuple {
	return SipTuple{
		Ip_length: t.Ip_length,
		Src_ip:    t.Dst_ip,
		Dst_ip:    t.Src_ip,
		Src_port:  t.Dst_port,
		Dst_port:  t.Src_port,
		Transport: t.Transport,
		Id:        t.Id,
		raw:       t.revRaw,
		revRaw:    t.raw,
	}
}

//eg:common/tuples.go ComputeHashebles&String&Hashable func
func (t *SipTuple) ComputeHashebles() {
	copy(t.raw[0:16], t.Src_ip)
	copy(t.raw[16:18], []byte{byte(t.Src_port >> 8), byte(t.Src_port)})
	copy(t.raw[18:34], t.Dst_ip)
	copy(t.raw[34:36], []byte{byte(t.Dst_port >> 8), byte(t.Dst_port)})
	copy(t.raw[36:38], []byte{byte(t.Id >> 8), byte(t.Id)})
	t.raw[39] = byte(t.Transport)

	copy(t.revRaw[0:16], t.Dst_ip)
	copy(t.revRaw[16:18], []byte{byte(t.Dst_port >> 8), byte(t.Dst_port)})
	copy(t.revRaw[18:34], t.Src_ip)
	copy(t.revRaw[34:36], []byte{byte(t.Src_port >> 8), byte(t.Src_port)})
	copy(t.revRaw[36:38], []byte{byte(t.Id >> 8), byte(t.Id)})
	t.revRaw[39] = byte(t.Transport)
}
func (t *SipTuple) String() string {
	return fmt.Sprintf("SipTuple src[%s:%d] dst[%s:%d] transport[%s] id[%d]",
		t.Src_ip.String(),
		t.Src_port,
		t.Dst_ip.String(),
		t.Dst_port,
		t.Transport,
		t.Id)
}

// Hashable returns a hashable value that uniquely identifies
// the Sip tuple.
func (t *SipTuple) Hashable() HashableSipTuple {
	return t.raw
}

// Hashable returns a hashable value that uniquely identifies
// the Sip tuple after swapping the source and destination.
func (t *SipTuple) RevHashable() HashableSipTuple {
	return t.revRaw
}

// Configuration data.
type Sip struct {
	Ports         []int
	Send_request  bool
	Send_response bool
	// Cache of active SIP transactions. The map key is the HashableDnsTuple
	// associated with the request.
	transactions       *common.Cache
	transactionTimeout time.Duration
	results            publish.Transactions // Channel where results are pushed.
}

// getTransaction returns the transaction associated with the given
// HashableDnsTuple. The lookup key should be the HashableDnsTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (sip *Sip) getTransaction(k HashableSipTuple) *SipTransaction {
	v := sip.transactions.Get(k)
	if v != nil {
		return v.(*SipTransaction)
	}
	return nil
}

type SipTransaction struct {
	ts           time.Time // Time when the request was received.
	tuple        SipTuple  // Key used to track this transaction in the transactionsMap.
	ResponseTime int32     // Elapsed time in milliseconds between the request and response.
	Src          common.Endpoint
	Dst          common.Endpoint
	Transport    Transport
	Notes        []string

	//Request  *SipMessage
	//Response *SipMessage
	Request  *ReqSipMessage
	Response *RespSipMessage
}

func init() {
	protos.Register("sip", New)
}
func New(
	testMode bool,
	results publish.Transactions,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &Sip{}
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
func (sip *Sip) init(results publish.Transactions, config *sipConfig) error {
	sip.setFromConfig(config)
	sip.transactions = common.NewCacheWithRemovalListener(
		sip.transactionTimeout,
		protos.DefaultTransactionHashSize,
		func(k common.Key, v common.Value) {
			trans, ok := v.(*SipTransaction)
			if !ok {
				logp.Err("Expired value is not a *SipTransaction.")
				return
			}
			sip.expireTransaction(trans)
		})
	sip.transactions.StartJanitor(sip.transactionTimeout)

	sip.results = results

	return nil
}
func (sip *Sip) setFromConfig(config *sipConfig) error {
	sip.Ports = config.Ports
	sip.Send_request = config.SendRequest
	sip.Send_response = config.SendResponse
	sip.transactionTimeout = config.TransactionTimeout
	return nil
}

func newTransaction(ts time.Time, tuple SipTuple, cmd common.CmdlineTuple) *SipTransaction {
	trans := &SipTransaction{
		Transport: tuple.Transport,
		ts:        ts,
		tuple:     tuple,
	}
	trans.Src = common.Endpoint{
		Ip:   tuple.Src_ip.String(),
		Port: tuple.Src_port,
		Proc: string(cmd.Src),
	}
	trans.Dst = common.Endpoint{
		Ip:   tuple.Dst_ip.String(),
		Port: tuple.Dst_port,
		Proc: string(cmd.Dst),
	}
	return trans
}

// deleteTransaction deletes an entry from the transaction map and returns
// the deleted element. If the key does not exist then nil is returned.
func (sip *Sip) deleteTransaction(k HashableSipTuple) *SipTransaction {
	v := sip.transactions.Delete(k)
	if v != nil {
		return v.(*SipTransaction)
	}
	return nil
}

// Implement  Plugin interface
func (sip *Sip) GetPorts() []int {
	return sip.Ports
}
func (sip *Sip) ConnectionTimeout() time.Duration {
	return sip.transactionTimeout
}
func (sip *Sip) receivedSipRequest(tuple *SipTuple, msg *ReqSipMessage) {
	debugf("Processing request. %s", tuple.String())
	trans := sip.deleteTransaction(tuple.Hashable())
	if trans != nil {
		sip.publishTransaction(trans)
		sip.deleteTransaction(trans.tuple.Hashable())
	}
	trans = newTransaction(msg.Ts, *tuple, *msg.CmdlineTuple)
	sip.transactions.Put(tuple.Hashable(), trans)

	trans.Request = msg
}

func (sip *Sip) receivedSipResponse(tuple *SipTuple, msg *RespSipMessage) {
	debugf("Processing response. %s", tuple.String())
	trans := sip.getTransaction(tuple.RevHashable())
	if trans == nil {
		trans = newTransaction(msg.Ts, tuple.Reverse(), common.CmdlineTuple{
			Src: msg.CmdlineTuple.Dst, Dst: msg.CmdlineTuple.Src})
	}
	trans.Response = msg
	sip.publishTransaction(trans)
	sip.deleteTransaction(trans.tuple.Hashable())
}

func (sip *Sip) publishTransaction(t *SipTransaction) {
	if sip.results == nil {
		return
	}
	debugf("Publishing transaction. %s", t.tuple.String())
	event := common.MapStr{
		"@timestamp":   common.Time(t.ts),
		"type":         "sip",
		"transport":    t.Transport.String(),
		"src":          &t.Src,
		"dst":          &t.Dst,
		"responsetime": t.ResponseTime,
		"version":      "SIP/2.0",
	}

	event["bytes_in"] = t.Request.Length
	event["method"] = t.Request.Req.GetMethod()
	event["requestURI"] = t.Request.Req.GetRequestURI()
	event["reasonphrase"] = t.Response.Resp.GetReasonPhrase()
	event["statuscode"] = t.Response.Resp.GetStatusCode()
	if sip.Send_request {
		event["request"] = t.Request.Req.GetHeader()

	}
	if sip.Send_response {
		event["response"] = t.Response.Resp.GetHeader()
	}
	debugf("statuscode: %d", t.Response.Resp.GetStatusCode())
	debugf("reasonphrase: %s", t.Response.Resp.GetReasonPhrase())
	debugf("method: %s", t.Request.Req.GetMethod())
	debugf("requestUIR: %s", t.Request.Req.GetRequestURI())
	debugf("request: %v", t.Request.Req.GetHeader())
	debugf("response: %v", t.Response.Resp.GetHeader())

	sip.results.PublishTransaction(event)

}

func (sip *Sip) expireTransaction(t *SipTransaction) {
	debugf("%s", t.tuple.String())
	sip.publishTransaction(t)
}

// decodeSipData decodes a byte array into a SIP struct. If an error occurs
// then the returnd sip pointer will be nil. This method recovers from panics
// and is concurrency-safe.
func decodeSipData(transport Transport, rawData []byte) (sip *message, err error) {

	// Recover from any panics that occur while parsing a packet.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	msg := &message{}
	return msg, nil

}
