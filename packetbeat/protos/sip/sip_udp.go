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

	sipPkt, err := decodeSipData(TransportUdp, pkt.Payload)
	if err != nil {
		// This means that malformed requests or responses are being sent or
		// that someone is attempting to the SIP port for non-SIP traffic. Both
		// are issues that a monitoring system should report.
		debugf("%s", err.Error())
		return
	}
	sipTuple := SipTupleFromIpPort(&pkt.Tuple, TransportUdp, sipPkt.Id)
	sipMsg := &SipMessage{
		Ts:           pkt.Ts,
		Tuple:        pkt.Tuple,
		CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
		Data:         sipPkt,
		Length:       packetSize,
	}

	if sipMsg.Data.Response {
		sip.receivedSipResponse(&sipTuple, sipMsg)
	} else /* Request */ {
		sip.receivedSipRequest(&sipTuple, sipMsg)
	}
}
