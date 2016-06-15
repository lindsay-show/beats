package sip

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type sipConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = sipConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
