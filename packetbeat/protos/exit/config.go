package exit

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type exitConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = exitConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

func (c *exitConfig) Validate() error {
	return nil
}
