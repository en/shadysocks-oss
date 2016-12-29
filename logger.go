package shadysocks

import (
	"github.com/uber-go/zap"
)

var (
	logger = zap.New(
		zap.NewTextEncoder(),
		zap.DebugLevel,
	)
)
