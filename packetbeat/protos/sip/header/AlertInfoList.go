package header

import (
	"github.com/elastic/beats/packetbeat/protos/sip/core"
)

/**
* AlertInfo Header - there can be several AlertInfo headers.
 */
type AlertInfoList struct {
	SIPHeaderList
}

/** default constructor
 */
func NewAlertInfoList() *AlertInfoList {
	this := &AlertInfoList{}
	this.SIPHeaderList.super(core.SIPHeaderNames_ALERT_INFO)
	return this
}
