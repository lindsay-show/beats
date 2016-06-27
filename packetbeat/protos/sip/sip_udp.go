package sip

import (
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
)

const MaxSipPacketSize = 65535 //(bytes)

func (sip *Sip) ParseUdp(pkt *protos.Packet) {
	defer logp.Recover("Sip ParseUdp")
	packetSize := len(pkt.Payload)

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)
	sipPkt, err := decodeReqSipData(TransportUdp, pkt.Payload)
	reqsipPkt, err := decodeReqSipData(TransportUdp, pkt.Payload)
	respsipPkt, err := decodeRespSipData(TransportUdp, pkt.Payload)
	if err != nil {
		// This means that malformed requests or responses are being sent or
		// that someone is attempting to the SIP port for non-SIP traffic. Both
		// are issues that a monitoring system should report.
		debugf("%s", err.Error())
		return
	}

	sipTuple := SipTupleFromIpPort(&pkt.Tuple, TransportUdp, sipPkt.Id)
	reqsipMsg := &ReqSipMessage{
		SipMessage: SipMessage{
			Ts:           pkt.Ts,
			Tuple:        pkt.Tuple,
			CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
			Length:       packetSize,
		},
		Req: reqsipPkt,
	}
	respsipMsg := &RespSipMessage{
		SipMessage: SipMessage{
			Ts:           pkt.Ts,
			Tuple:        pkt.Tuple,
			CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
			Length:       packetSize,
		},
		Resp: respsipPkt,
	}
	if reqsipMsg.Req.Response {
		sip.receivedSipResponse(&sipTuple, respsipMsg)
	} else /* Request*/ {
		sip.receivedSipRequest(&sipTuple, reqsipMsg)
	}
}
