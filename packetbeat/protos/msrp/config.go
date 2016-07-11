package msrp

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type PortRange [2]int

type msrpPortsConfig struct {
	Range PortRange `config:"range"`
}

type msrpConfig struct {
	config.ProtocolCommon `config:",inline"`
	Ports                 msrpPortsConfig `config:"ports"`
}

var (
	defaultConfig = msrpConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
