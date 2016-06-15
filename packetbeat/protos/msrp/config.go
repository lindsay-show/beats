package msrp

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type msrpConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = msrpConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
