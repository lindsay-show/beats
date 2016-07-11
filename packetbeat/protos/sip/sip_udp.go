package sip

import (
	"bufio"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"strings"
)

func (sip *Sip) ParseUdp(pkt *protos.Packet) {
	defer logp.Recover("Sip ParseUdp")
	packetSize := len(pkt.Payload)

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)
	sipPkt, err := decodeSipData(TransportUdp, pkt.Payload)
	if err != nil {
		// This means that malformed requests or responses are being sent or
		// that someone is attempting to the SIP port for non-SIP traffic. Both
		// are issues that a monitoring system should report.
		debugf("%s", err.Error())
		return
	}
	sipTuple := SipTupleFromIpPort(&pkt.Tuple, TransportUdp, sipPkt.Id)
	sipload := strings.NewReader(string(pkt.Payload))
	buf := bufio.NewReader(sipload)
	if sipPkt.Response {
		msg, _ := ReadResponseMessage(buf)
		debugf("response: %v", msg.GetHeader())
		respsipPkt := NewResponse(msg.GetStatusCode(), msg.GetReasonPhrase(), nil)

		respsipMsg := &RespSipMessage{
			SipMessage: SipMessage{
				Ts:           pkt.Ts,
				Tuple:        pkt.Tuple,
				CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
				Length:       packetSize,
			},
			Resp: respsipPkt,
		}
		sip.receivedSipResponse(&sipTuple, respsipMsg)

	} else {
		msg, _ := ReadRequestMessage(buf)
		debugf("request: %v", msg.GetHeader())
		reqsipPkt := NewRequest(msg.GetMethod(), msg.GetRequestURI(), nil)
		reqsipMsg := &ReqSipMessage{
			SipMessage: SipMessage{
				Ts:           pkt.Ts,
				Tuple:        pkt.Tuple,
				CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
				Length:       packetSize,
			},
			Req: reqsipPkt,
		}

		sip.receivedSipRequest(&sipTuple, reqsipMsg)
	}

}
