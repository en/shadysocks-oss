package shadysocks

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	Rnode       string `toml:"rnode"`
	Pnode       string `toml:"pnode"`
	Password    string `toml:"password"`
	Timeout     int    `toml:"timeout"`
	Method      string `toml:"method"`
	FastOpen    bool   `toml:"fast_open"`
	Workers     int    `toml:"workers"`
	PreferIpv6  bool   `toml:"prefer_ipv6"`
	OneTimeAuth bool   `toml:"one_time_auth"`
}

func ParseConfig(path string, conf *Config) error {
	_, err := toml.DecodeFile(path, conf)
	return err
}
